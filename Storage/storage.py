import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert
from Storage.models import (
    Base,
    EmailThread, EmailMessage, EmailExtraction,
    EmailInsight, ThreadStatus, AIDraft,
    KBDocument, KBChunk, RAGCitation,
    AuditEvent, DailyEmailStats, EmailAttachment,
)
from datetime import datetime
from typing import Optional, Dict, Any

class DatabaseManager:
    def __init__(self, db_url=None):
        if db_url is None:
            db_url = os.getenv(
                "DATABASE_URL",
                "postgresql://postgres:postgres@localhost:5432/support_db",
            )
        if not db_url:
            raise ValueError("❌ DATABASE_URL not found in environment variables")
        
        self.engine = create_engine(db_url, pool_pre_ping=True, echo=False)
        self.Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)

    def save_ai_draft(self, draft_dict: dict) -> int:
        session = self.Session()
        try:
            draft = AIDraft(
                message_id=draft_dict.get("message_id"),
                thread_id=draft_dict.get("thread_id"),
                model=draft_dict.get("model"),
                prompt=draft_dict.get("prompt"),
                draft_text=draft_dict.get("draft_text"), 
                tone_tags=draft_dict.get("tone_tags"),
                priority_hint=draft_dict.get("priority_hint"),
                sentiment_hint=draft_dict.get("sentiment_hint"),
                status=draft_dict.get("status", "pending"),
                created_at=datetime.utcnow(),
            )
            session.add(draft)
            session.commit()
            return draft.id
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def update_ai_draft_status(
        self, draft_id: int, status: str, edited_text: Optional[str] = None, draft_text: Optional[Dict[str, Any]] = None
    ):
        session = self.Session()
        try:
            draft = session.query(AIDraft).filter_by(id=draft_id).one_or_none()
            if not draft:
                raise ValueError(f"Draft {draft_id} not found")

            draft.status = status
            if edited_text:
                draft.edited_text = edited_text
            if draft_text:
                draft.draft_text = draft_text

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_processed_message(self, msg_dict: dict) -> int:
        session = self.Session()
        try:
            thread_key = (
                msg_dict.get("in_reply_to")
                or msg_dict.get("references")
                or msg_dict.get("message_id_hdr")
                or msg_dict.get("subject")
            )
            thread = (
                session.query(EmailThread)
                .filter_by(thread_key=thread_key)
                .one_or_none()
            )
            if not thread:
                thread = EmailThread(
                    thread_key=thread_key,
                    subject_canonical=msg_dict.get("subject"),
                    created_at=datetime.utcnow(),
                    last_msg_at=datetime.utcnow(),
                )
                session.add(thread)
                session.flush()

            email_msg = (
                session.query(EmailMessage)
                .filter_by(message_id_hdr=msg_dict.get("message_id_hdr"))
                .one_or_none()
            )
            if not email_msg:
                email_msg = EmailMessage(
                    provider=msg_dict["provider"],
                    provider_uid=msg_dict.get("provider_uid"),
                    message_id_hdr=msg_dict.get("message_id_hdr"),
                    thread_id=thread.id,
                    direction=msg_dict.get("direction", "inbound"),
                    from_email=msg_dict.get("from"),
                    to_emails=msg_dict.get("to", []),
                    cc_emails=msg_dict.get("cc", []),
                    bcc_emails=msg_dict.get("bcc", []),
                    subject=msg_dict.get("subject"),
                    sent_at=msg_dict.get("date"),
                    received_at=msg_dict.get("date"),
                    flags=msg_dict.get("flags", []),
                    body_text=msg_dict.get("body", {}).get("body"),
                    body_html=None,  
                    urls=msg_dict.get("body", {}).get("urls"),
                    attachments_meta=msg_dict.get("body", {}).get("attachments"),
                    is_agent_reply=msg_dict.get("is_agent_reply", False),
                    created_at=datetime.utcnow(),
                )
                session.add(email_msg)
                session.flush()
            else:
                return email_msg.id

            attachments = msg_dict.get("body", {}).get("attachments_list", [])
            for att in attachments:
                attachment = EmailAttachment(
                    message_id=email_msg.id,
                    filename=att.get("filename"),
                    content_type=att.get("content_type"),
                    size_bytes=att.get("size_bytes"),
                )
                session.add(attachment)

            if msg_dict.get("entities"):
                extraction = EmailExtraction(
                    message_id=email_msg.id,
                    phone=msg_dict["entities"].get("phone"),
                    alt_email=msg_dict["entities"].get("alt_email"),
                    error_code=msg_dict["entities"].get("error_code"),
                    invoice_id=msg_dict["entities"].get("invoice_id"),
                    ticket_id=msg_dict["entities"].get("ticket_id"),
                    products=msg_dict["entities"].get("products"),
                    named_entities=msg_dict["entities"].get("named_entities"),
                    raw_entities=msg_dict["entities"],
                    created_at=datetime.utcnow(),
                )
                session.add(extraction)

            if msg_dict.get("classification") or msg_dict.get("signals"):
                insights = EmailInsight(
                    message_id=email_msg.id,
                    impact=msg_dict.get("classification", {}).get("impact"),
                    urgency=msg_dict.get("classification", {}).get("urgency"),
                    type=msg_dict.get("classification", {}).get("type"),
                    priority=msg_dict.get("signals", {}).get("priority"),
                    sentiment=msg_dict.get("signals", {}).get("sentiment"),
                    confidence=msg_dict.get("signals", {}).get("confidence"),
                    model="DavinciTech/BERT_Categorizer",
                    created_at=datetime.utcnow(),
                )
                session.add(insights)

            session.commit()
            return email_msg.id

        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
