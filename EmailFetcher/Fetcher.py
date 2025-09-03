import os, json, email, imaplib, quopri, base64, re,  requests, spacy
from datetime import datetime, date
from typing import List, Dict, Optional, Union
from email.utils import parsedate_to_datetime, parseaddr, getaddresses
from email.header import decode_header, make_header
from imapclient import IMAPClient
from msal import ConfidentialClientApplication, PublicClientApplication, SerializableTokenCache
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from transformers import pipeline, AutoTokenizer
from concurrent.futures import ThreadPoolExecutor, as_completed
from Storage.storage import DatabaseManager
from Storage.models import EmailMessage
load_dotenv()

sentiment_analyzer = pipeline("sentiment-analysis")
text_classifier = pipeline("text-classification", model="DavinciTech/BERT_Categorizer")

class BaseEmailFetcher:

    def __init__(self, server: str, provider_name: str):
        self.client: Optional[IMAPClient] = None
        self.server = server
        self.provider_name = provider_name
        self.BATCH_SIZE  = 50
        self.MAX_THREADS = 4
        self.model = text_classifier
        self.sentiment_analyzer = sentiment_analyzer
        self.nlp = spacy.load("en_core_web_sm")
        self.db = DatabaseManager()
        self.FILTER_KEYWORDS = []
        self.ALLOWED_DOMAINS = []
        self.support_domain = os.getenv("SUPPORT_DOMAIN", "").strip().lower()
        self.PRODUCT_KEYWORDS = ["vpn", "erp", "crm", "server", "account", "login", "invoice"]
        self.LABEL_DICTIONARY = {
            "I1": "Low Impact",
            "I2": "Medium Impact",
            "I3": "High Impact",
            "I4": "Critical Impact",
            "U1": "Low Urgency",
            "U2": "Medium Urgency",
            "U3": "High Urgency",
            "U4": "Critical Urgency",
            "T1": "Information",
            "T2": "Incident",
            "T3": "Problem",
            "T4": "Request",
            "T5": "Question",
        }

    def classify_support_ticket(self, subject: str, body: str) -> Dict:
        try:
            text = f"Title: {subject}\nDescription: {body}"

            tokenizer = self.model.tokenizer
            inputs = tokenizer(
                text, truncation=True, max_length=512, return_tensors="pt"
            )

            preds = self.model(
                tokenizer.decode(inputs["input_ids"][0]), top_k=None, truncation=True, max_length=512
            )

            grouped = {"impact": {}, "urgency": {}, "type": {}}
            for pred in preds:
                label, score = pred["label"], pred["score"]
                if label.startswith("I"):
                    grouped["impact"][label] = score
                elif label.startswith("U"):
                    grouped["urgency"][label] = score
                elif label.startswith("T"):
                    grouped["type"][label] = score

            decoded = {}
            for key, scores in grouped.items():
                if scores:
                    best = max(scores, key=scores.get)
                    decoded[key] = self.LABEL_DICTIONARY.get(best, best)

            return decoded

        except Exception as e:
            print(f"❌ classify_support_ticket error: {e}")
            return {}

    def _is_relevant(self, subject: str, keywords: Optional[List[str]] = None) -> bool:
        """
        Header-level relevance check. If keywords is empty/None -> return True (no subject filtering).
        """
        if not keywords:
            return True
        if not subject:
            return False
        subject_lower = subject.lower()
        return any(kw.lower() in subject_lower for kw in keywords)

    def extract_entities(self, body: str) -> Dict:
        entities = {}

        phone_match = re.search(r"\+?\d[\d\-\s]{7,}\d", body)
        if phone_match:
            entities["phone"] = phone_match.group()

        email_match = re.search(r"[\w\.-]+@[\w\.-]+", body)
        if email_match:
            entities["alt_email"] = email_match.group()

        error_match = re.search(r"(error\s?\d{3,}|ERR\d+|code\s?\d{3,})", body.lower())
        if error_match:
            entities["error_code"] = error_match.group()

        invoice_match = re.search(r"(INV[- ]?\d+|Invoice\s?#?\d+)", body, re.IGNORECASE)
        if invoice_match:
            entities["invoice_id"] = invoice_match.group()

        ticket_match = re.search(r"(TKT[- ]?\d+|Ticket\s?#?\d+)", body, re.IGNORECASE)
        if ticket_match:
            entities["ticket_id"] = ticket_match.group()

        found_products = [k for k in self.PRODUCT_KEYWORDS if k in (body or "").lower()]
        if found_products:
            entities["products"] = list(set(found_products))

        try:
            doc = self.nlp(body or "")
            named_entities = {}
            for ent in doc.ents:
                named_entities.setdefault(ent.label_, []).append(ent.text)
            if named_entities:
                entities["named_entities"] = named_entities
        except Exception as e:
            print(f"⚠️ spaCy NER failed: {e}")

        return entities

    def _is_company_related(self, sender: str, body: str, domains: Optional[List[str]] = None) -> bool:
        """
        Full check involving allowed domains and product keywords inside body.
        If domains is empty -> accept all (True).
        """
        allowed = domains if domains is not None else self.ALLOWED_DOMAINS
        if not allowed:
            return True
        if any(domain.lower() in (sender or "").lower() for domain in allowed):
            if any(kw.lower() in (body or "").lower() for kw in self.PRODUCT_KEYWORDS):
                return True
            return False
        return False

    def get_priority_and_sentiment(self, body: str) -> Dict:
        priority_keywords = ["urgent", "critical", "immediately", "cannot access", "system down"]
        priority = "Normal"
        if any(pk in (body or "").lower() for pk in priority_keywords):
            priority = "Urgent"

        sentiment = self.sentiment_analyzer((body or "")[:512])[0]
        return {"priority": priority, "sentiment": sentiment["label"]}

    def _decode_mime_words(self, s: str) -> str:
        try:
            return str(make_header(decode_header(s)))
        except Exception:
            return s

    def _decode_payload(self, payload, charset="utf-8") -> str:
        """Handle different encodings (base64, quoted-printable, etc.)."""
        try:
            if isinstance(payload, bytes):
                return payload.decode(charset, errors="ignore")
            if payload is None:
                return ""
            return str(payload)
        except Exception:
            return str(payload)

    def _extract_body(self, email_message) -> Dict:
        """
        Extract email body with:
        - plain text only in 'body'
        - URLs in 'urls'
        - attachments metadata in 'attachments'
        - normalized attachments_list for DB persistence
        """
        body_text = ""
        attachments = []
        attachments_list = []

        def extract_urls(text):
            url_pattern = r"https?://[^\s\[\]]+"
            return re.findall(url_pattern, text)

        if email_message.is_multipart():
            for part in email_message.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition") or "")

                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                content = self._decode_payload(payload, charset)

                if ctype == "text/plain" and "attachment" not in disp:
                    body_text += content + "\n"
                elif ctype == "text/html" and not body_text:
                    text_only = self.clean_body(content)
                    body_text += text_only + "\n"

                if "attachment" in disp:
                    filename = part.get_filename()
                    att_dict = {
                        "filename": self._decode_mime_words(filename) if filename else "unknown",
                        "content_type": ctype,
                        "size_bytes": len(payload) if payload else 0,
                    }
                    attachments.append(att_dict)
                    attachments_list.append(att_dict)

        else:
            ctype = email_message.get_content_type()
            payload = email_message.get_payload(decode=True)
            content = self._decode_payload(payload, email_message.get_content_charset() or "utf-8")
            if ctype == "text/plain":
                body_text = content
            elif ctype == "text/html":
                body_text = self.clean_body(content)

        urls = extract_urls(body_text)
        for url in urls:
            body_text = body_text.replace(url, "")

        return {
            "body": body_text.strip(),
            "attachments": attachments,         # for raw use
            "attachments_list": attachments_list,  # for DB persistence
            "urls": urls,
        }

    def clean_body(self, body_html: str) -> str:
        if not body_html:
            return ""
        soup = BeautifulSoup(body_html, "html.parser")
        return soup.get_text(separator="\n", strip=True)

    def _process_messages(self, message_ids: List, filter_keywords: Optional[List[str]] = None,
                          allowed_domains: Optional[List[str]] = None) -> List[Dict]:
        emails = []
        if not message_ids:
            return emails

        filter_keywords = filter_keywords or []
        allowed_domains = allowed_domains or []

        batches = [message_ids[i:i+self.BATCH_SIZE] for i in range(0, len(message_ids), self.BATCH_SIZE)]

        for batch in batches:
            raw_headers = self.client.fetch(batch, ["BODY.PEEK[HEADER]"])
            relevant_ids = []
            headers_map = {}

            for msg_id in batch:
                msg_bytes = raw_headers[msg_id][b"BODY[HEADER]"]
                hdr = email.message_from_bytes(msg_bytes)
                subject = self._decode_mime_words(hdr.get("Subject", "No Subject"))
                sender = self._decode_mime_words(hdr.get("From", "Unknown Sender"))

                if self._is_relevant(subject, filter_keywords):
                    relevant_ids.append(msg_id)
                    headers_map[msg_id] = {
                        "subject": subject,
                        "sender": sender,
                        "recipient": self._decode_mime_words(hdr.get("To", "Unknown Recipient")),
                        "date": hdr.get("Date", None),
                        "message_id": hdr.get("Message-ID"),
                        "in_reply_to": hdr.get("In-Reply-To"),
                        "references": hdr.get("References"),
                        "cc": hdr.get("Cc"),
                        "bcc": hdr.get("Bcc"),
                    }

            if not relevant_ids:
                continue

            raw_messages = self.client.fetch(relevant_ids, ["RFC822"])

            def process_single(msg_id):
                try:
                    headers = headers_map[msg_id]
                    message_id_hdr = headers.get("message_id")

                    with self.db.Session() as check_session:
                        exists = (
                            check_session.query(EmailMessage.id)
                            .filter_by(message_id_hdr=message_id_hdr)
                            .first()
                        )

                        if exists:
                            print(f"⏩ Skipping already processed message {message_id_hdr}")
                            return None

                    raw_message = raw_messages[msg_id][b"RFC822"]
                    email_message = email.message_from_bytes(raw_message)
                    body_dict = self._extract_body(email_message)

                    sender_name, sender_addr = parseaddr(headers.get("sender", "") or "")

                    if not self._is_company_related(sender_addr, body_dict.get("body", ""), allowed_domains):
                        return None

                    subject = headers["subject"]
                    recipient_list = [addr for _, addr in getaddresses([headers.get("recipient", "")])]
                    cc_list = [addr for _, addr in getaddresses([headers.get("cc", "") or ""])]
                    bcc_list = [addr for _, addr in getaddresses([headers.get("bcc", "") or ""])]

                    try:
                        mail_date = parsedate_to_datetime(headers["date"])
                    except Exception:
                        mail_date = None

                    labels = self.classify_support_ticket(subject, body_dict.get("body", ""))
                    if not labels or labels.get("type") not in ("Incident", "Request", "Question", "Problem"):
                        return None

                    entities = self.extract_entities(body_dict.get("body", ""))
                    signals = self.get_priority_and_sentiment(body_dict.get("body", ""))

                    priority_map = {"Urgent": 2, "Normal": 1}
                    priority_rank = priority_map.get(signals.get("priority", "Normal"), 1)

                    is_agent_reply = False
                    if self.support_domain and sender_addr and sender_addr.lower().endswith(self.support_domain):
                        is_agent_reply = True

                    msg_dict = {
                        "id": msg_id,
                        "provider": self.provider_name,
                        "provider_uid": str(msg_id),
                        "message_id_hdr": headers.get("message_id"),
                        "in_reply_to": headers.get("in_reply_to"),
                        "references": headers.get("references"),
                        "subject": subject,
                        "from": sender_addr,
                        "to": recipient_list,
                        "cc": cc_list,
                        "bcc": bcc_list,
                        "date": mail_date.isoformat() if mail_date else None,
                        "body": body_dict,
                        "classification": labels,
                        "entities": entities,
                        "signals": signals,
                        "direction": "inbound" if not is_agent_reply else "outbound",
                        "flags": [],
                        "is_agent_reply": is_agent_reply,
                        "priority_rank": priority_rank,
                    }

                    try:
                        db_id = self.db.save_processed_message(msg_dict)
                        msg_dict["db_id"] = db_id
                    except Exception as db_exc:
                        print(f"⚠️ DB save failed for msg {msg_id}: {db_exc}")

                    return msg_dict
                except Exception as e:
                    print(f"❌ Error processing message {msg_id}: {e}")
                    return None

            with ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
                results = list(executor.map(process_single, relevant_ids))

            emails.extend([res for res in results if res is not None])

        emails.sort(key=lambda x: (-x.get("priority_rank", 1), x.get("date", "")), reverse=False)

        print(f"✅ Extracted {len(emails)} relevant emails from {self.provider_name}")
        return emails

    def allMails(self, folder: str = "INBOX", filter_keywords: Optional[List[str]] = None, allowed_domains: Optional[List[str]] = None) -> List[Dict]:
        try:
            self.client.select_folder(folder)
            messages = self.client.search(["ALL"])
            print(f"📝 Found {len(messages)} emails in {folder}")
            return self._process_messages(messages, filter_keywords=filter_keywords, allowed_domains=allowed_domains)
        except Exception as e:
            print(f"❌ Error fetching all {self.provider_name} emails: {e}")
            return []

    def _fetch_emails_by_date(self, date_str: str, folder: str, filter_keywords: Optional[List[str]] = None,
                              allowed_domains: Optional[List[str]] = None) -> List[Dict]:
        try:
            self.client.select_folder(folder)
            messages = self.client.search(["ON", date_str])
            return self._process_messages(messages, filter_keywords=filter_keywords, allowed_domains=allowed_domains)
        except Exception as e:
            print(f"Error fetching {self.provider_name} emails by date: {e}")
            return []

    def mailsByDate(self, target_date: Union[str, date], folder: str = "INBOX", filter_keywords: Optional[List[str]] = None,
                    allowed_domains: Optional[List[str]] = None) -> List[Dict]:
        if isinstance(target_date, str):
            target_date = datetime.strptime(target_date, "%Y-%m-%d").date()
        date_str = target_date.strftime("%d-%b-%Y")
        return self._fetch_emails_by_date(date_str, folder, filter_keywords=filter_keywords, allowed_domains=allowed_domains)

    def todayMails(self, folder: str = "INBOX", filter_keywords: Optional[List[str]] = None, allowed_domains: Optional[List[str]] = None) -> List[Dict]:
        return self.mailsByDate(date.today(), folder, filter_keywords=filter_keywords, allowed_domains=allowed_domains)

    def _fetch_emails_by_criteria(self, criteria: List, folder: str) -> List[Dict]:
        try:
            self.client.select_folder(folder)
            messages = self.client.search(criteria)
            return self._process_messages(messages)
        except Exception as e:
            print(f"Error fetching {self.provider_name} emails by criteria: {e}")
            return []

    def mailsByFilter(self, criteria: Dict, folder: str = "INBOX") -> List[Dict]:
        search_criteria = []
        for key, value in criteria.items():
            search_criteria.extend([key, value])
        return self._fetch_emails_by_criteria(search_criteria, folder)

    def set_domain_filter(self, domains: Optional[List[str]] = None):
        """
        Dynamically update allowed domains.
        """
        if domains:
            self.ALLOWED_DOMAINS = [d.lower() for d in domains]
            print(f"✅ Domain filter enabled: {self.ALLOWED_DOMAINS}")
        else:
            self.ALLOWED_DOMAINS = []
            print("✅ Domain filter disabled: accepting all support queries")

    def logout(self):
        if self.client:
            try:
                self.client.logout()
                print(f"🔒 Logged out from {self.provider_name}")
            except Exception as e:
                print(f"Error logging out from {self.provider_name}: {e}")


class GmailFetcher(BaseEmailFetcher):
    def __init__(self):
        super().__init__("imap.gmail.com", "Gmail")

    def login(self, user: str, password: str) -> bool:
        try:
            self.client = IMAPClient(self.server, ssl=True)
            self.client.login(user, password)
            print(f"Successfully logged into Gmail: {user}")
            return True
        except Exception as e:
            print(f"Gmail login failed: {e}")
            return False

class OutlookFetcher(BaseEmailFetcher):
    def __init__(self):
        super().__init__("outlook.office365.com", "Outlook")
        self.client_id = os.getenv('AZURE_CLIENT_ID')
        self.client_secret = os.getenv('AZURE_CLIENT_SECRET')
        self.tenant_id = os.getenv('AZURE_TENANT_ID', 'common')
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"

        self.scopes = [
            "https://outlook.office365.com/IMAP.AccessAsUser.All",
        ]

        self.cache_file = "msal_cache.json"
        self.cache = SerializableTokenCache()
        if os.path.exists(self.cache_file):
            self.cache.deserialize(open(self.cache_file, "r").read())

        self.app = PublicClientApplication(
            client_id=self.client_id,
            authority=self.authority,
            token_cache=self.cache
        )

    def get_access_token(self) -> Optional[str]:
        try:
            accounts = self.app.get_accounts()
            if accounts:
                result = self.app.acquire_token_silent(self.scopes, account=accounts[0])
                if result and "access_token" in result:
                    return result["access_token"]

            flow = self.app.initiate_device_flow(scopes=self.scopes)
            if "user_code" not in flow:
                raise Exception("Failed to initiate device flow: " + str(flow))
            print(flow["message"])
            result = self.app.acquire_token_by_device_flow(flow)

            if result and "access_token" in result:
                with open(self.cache_file, "w") as f:
                    f.write(self.cache.serialize())
                return result["access_token"]

            raise Exception(f"Failed to acquire token: {result}")
        except Exception as e:
            print(f"Error in get_access_token: {e}")
            return None

    def get_access_token_with_secret(self) -> Optional[str]:
        try:
            if not (self.client_id and self.client_secret):
                return None

            app = ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=self.authority
            )

            result = app.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
            if result and 'access_token' in result:
                return result['access_token']
            print(f"Client-secret token response: {result}")
            return None
        except Exception as e:
            print(f"Error getting access token with client secret: {e}")
            return None

    def _imaplib_xoauth2_and_wrap(self, username: str, access_token: str) -> bool:
        try:
            raw = imaplib.IMAP4_SSL(self.server, 993)
            auth_string = f"user={username}\x01auth=Bearer {access_token}\x01\x01"
            raw.authenticate('XOAUTH2', lambda x: auth_string.encode('utf-8'))

            imapc = IMAPClient(self.server, ssl=True)
            imapc._imap = raw
            self.client = imapc
            return True
        except Exception as e:
            print(f"XOAUTH2 authentication/wrap failed: {e}")
            return False

    def login_with_oauth(self, access_token: str = None, username: str = None) -> bool:
        try:
            if not username:
                username = os.getenv('OUTLOOK_USER')
                if not username:
                    raise Exception("OUTLOOK_USER is not set")

            if access_token and self._imaplib_xoauth2_and_wrap(username, access_token):
                print(f"Successfully logged into Outlook with provided token: {username}")
                return True

            env_token = os.getenv("OUTLOOK_OAUTH_TOKEN")
            if env_token and self._imaplib_xoauth2_and_wrap(username, env_token):
                print(f"Successfully logged into Outlook with OUTLOOK_OAUTH_TOKEN env var: {username}")
                return True

            token = self.get_access_token()
            if token and self._imaplib_xoauth2_and_wrap(username, token):
                print(f"Successfully logged into Outlook with MSAL cached token: {username}")
                return True

            raise Exception("All authentication attempts failed")
        except Exception as e:
            print(f"Outlook OAuth login failed: {e}")
            return False

    def login_with_stored_token(self) -> bool:
        access_token = os.getenv("OUTLOOK_OAUTH_TOKEN")
        username = os.getenv("OUTLOOK_USER")

        if not access_token:
            print("No stored access token found in OUTLOOK_OAUTH_TOKEN environment variable")
            return False

        return self.login_with_oauth(access_token, username)


# if __name__ == "__main__":
#     gmail_user = os.getenv("GMAIL_USER")
#     gmail_pass = os.getenv("GMAIL_PASS")

#     gmail_fetcher = GmailFetcher()
#     if gmail_user and gmail_pass:
#         gmail_fetcher.login(gmail_user, gmail_pass)
#         print(gmail_fetcher.todayMails())
#     else:
#         print("Missing Gmail credentials in .env")
