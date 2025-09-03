import os
from datetime import date

import pandas as pd
import plotly.express as px
import streamlit as st
import requests
from sqlalchemy import or_, cast, Date

# --- Project imports
from API import emails_api
from Storage.storage import DatabaseManager
from Storage.models import (
    AIDraft,
    EmailMessage,
    EmailInsight,
    EmailExtraction,
    EmailAttachment,
)

# -------------------------------
# Page Setup
# -------------------------------
st.set_page_config(page_title="Support Email Dashboard", layout="wide")
st.title("📧 Support Email Dashboard")

# Instantiate DB manager
db = DatabaseManager()

# -------------------------------
# Draft API Setup
# -------------------------------
DRAFT_API_URL = "http://localhost:8001"  # adjust to your backend host/port

def call_generate_draft_for_message(message_id: int):
    try:
        r = requests.post(f"{DRAFT_API_URL}/generate-draft/{message_id}", timeout=60)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Draft generation failed for {message_id}: {e}")
        return None

# -------------------------------
# Helpers
# -------------------------------
def normalize_row(msg: EmailMessage, insight_map: dict, extraction_map: dict, attachments_map: dict):
    ins = insight_map.get(msg.id)
    exts = extraction_map.get(msg.id, [])
    atts = attachments_map.get(msg.id, [])
    return {
        "ID": msg.id,
        "Provider": msg.provider,
        "Subject": msg.subject or "",
        "From": msg.from_email or "",
        "Date": msg.received_at or msg.sent_at,
        "Priority": getattr(ins, "priority", None) or "Normal",
        "Sentiment": getattr(ins, "sentiment", None) or "Neutral",
        "Type": getattr(ins, "type", None) or "N/A",
        "Resolved": "Yes" if (msg.flags and len(msg.flags) > 0) else "No",
        "Attachments": ", ".join([a.filename for a in atts]) if atts else "",
        "Entities": [e.raw_entities for e in exts] if exts else [],
        "BodyText": msg.body_text or "",
    }

def db_fetch_emails(provider: str, on_date: date | None, sender: str | None, keyword: str | None, allowed_domains: list[str] | None):
    with db.Session() as session:
        q = session.query(EmailMessage).filter(EmailMessage.provider == provider)

        if on_date:
            q = q.filter(cast(EmailMessage.received_at, Date) == on_date)

        if sender:
            q = q.filter(EmailMessage.from_email.ilike(f"%{sender}%"))

        if keyword:
            kw = f"%{keyword}%"
            q = q.filter(or_(EmailMessage.subject.ilike(kw), EmailMessage.body_text.ilike(kw)))

        if allowed_domains:
            domain_filters = [EmailMessage.from_email.ilike(f"%{d}") for d in allowed_domains]
            q = q.filter(or_(*domain_filters))

        msgs = q.order_by(EmailMessage.received_at.desc().nullslast()).all()

        if not msgs:
            return []

        msg_ids = [m.id for m in msgs]
        ins_rows = session.query(EmailInsight).filter(EmailInsight.message_id.in_(msg_ids)).all()
        ext_rows = session.query(EmailExtraction).filter(EmailExtraction.message_id.in_(msg_ids)).all()
        att_rows = session.query(EmailAttachment).filter(EmailAttachment.message_id.in_(msg_ids)).all()

        insight_map = {i.message_id: i for i in ins_rows}
        extraction_map = {}
        for e in ext_rows:
            extraction_map.setdefault(e.message_id, []).append(e)
        attachments_map = {}
        for a in att_rows:
            attachments_map.setdefault(a.message_id, []).append(a)

        rows = [normalize_row(m, insight_map=insight_map, extraction_map=extraction_map, attachments_map=attachments_map) for m in msgs]
        return rows

def api_fetch_and_persist(provider: str, view_type: str, selected_date: date | None, filter_keywords, allowed_domains):
    if provider == "Gmail":
        data = (
            emails_api.get_gmail_today(filter_keywords=filter_keywords, allowed_domains=allowed_domains)
            if view_type == "Today"
            else emails_api.get_gmail_by_date(selected_date.isoformat(), filter_keywords=filter_keywords, allowed_domains=allowed_domains)
        )
    else:
        data = (
            emails_api.get_outlook_today(filter_keywords=filter_keywords, allowed_domains=allowed_domains)
            if view_type == "Today"
            else emails_api.get_outlook_by_date(selected_date.isoformat(), filter_keywords=filter_keywords, allowed_domains=allowed_domains)
        )

    if not isinstance(data, list):
        return []

    for item in data:
        try:
            db.save_processed_message(item)
        except Exception:
            continue
    return data

def compute_analytics_df(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"total": 0, "urgent": 0, "normal": 0, "resolved": 0}
    return {
        "total": len(df),
        "urgent": len(df[df["Priority"] == "Urgent"]),
        "normal": len(df[df["Priority"] == "Normal"]),
        "resolved": len(df[df["Resolved"] == "Yes"]),
    }

def draw_charts(df: pd.DataFrame):
    if df.empty:
        st.info("No data to visualize yet.")
        return
    with st.container():
        fig_priority = px.pie(df, names="Priority", title="Priority Distribution", color="Priority")
        fig_sentiment = px.pie(df, names="Sentiment", title="Sentiment Distribution", color="Sentiment")
        type_counts = df.groupby("Type").size().reset_index(name="Count")
        fig_type = px.bar(type_counts, x="Type", y="Count", title="Email Type Counts")
        fig_resolved = px.pie(df, names="Resolved", title="Resolved vs Pending", color="Resolved")

        st.plotly_chart(fig_priority, use_container_width=True)
        st.plotly_chart(fig_sentiment, use_container_width=True)
        st.plotly_chart(fig_type, use_container_width=True)
        st.plotly_chart(fig_resolved, use_container_width=True)

# -------------------------------
# Sidebar: Filters & Actions
# -------------------------------
st.sidebar.header("Filters & Actions")

provider = st.sidebar.selectbox("Email Provider", ["Gmail", "Outlook"])
view_type = st.sidebar.radio("View Type", ["Today", "By Date"])

selected_date = None
if view_type == "By Date":
    selected_date = st.sidebar.date_input("Select Date", date.today())

# Filter Type
st.sidebar.markdown("### Filter Type")
filter_type = st.sidebar.radio("Choose filter type:", ["Keywords", "Domains", "Extra Input"])

filter_keywords = None
allowed_domains = None

if filter_type == "Keywords":
    search_keywords = st.sidebar.text_area("Enter keywords (comma-separated):", "support,query,request,help")
    filter_keywords = [k.strip() for k in search_keywords.split(",") if k.strip()]
elif filter_type == "Domains":
    domain_input = st.sidebar.text_area("Enter domains (comma-separated, e.g., @company.com):")
    allowed_domains = [d.strip() for d in domain_input.split(",") if d.strip()]
else:
    extra_input = st.sidebar.text_area("Extra filter input:")
    filter_keywords = [extra_input.strip()] if extra_input.strip() else None

search_sender = st.sidebar.text_input("Filter by Sender")
search_keyword = st.sidebar.text_input("Filter by Subject/Body Keyword")

st.sidebar.divider()
force_api_if_empty = st.sidebar.checkbox("If DB empty, fetch from API and persist", value=True)
sync_now = st.sidebar.button("🔄 Sync from API now (force)")
fetch_btn = st.sidebar.button("Fetch Emails")

# -------------------------------
# Optional: Force Sync Now
# -------------------------------
if sync_now:
    try:
        st.info("Syncing from API…")
        api_fetch_and_persist(provider, view_type, selected_date or date.today(), filter_keywords, allowed_domains)
        st.success("API sync completed and data persisted to DB.")
    except Exception as e:
        st.error(f"API sync failed: {e}")

# -------------------------------
# Fetch Emails (DB-first hybrid)
# -------------------------------
if fetch_btn:
    try:
        target_date = selected_date if view_type == "By Date" else date.today()

        rows = db_fetch_emails(
            provider=provider,
            on_date=target_date,
            sender=search_sender or None,
            keyword=search_keyword or None,
            allowed_domains=allowed_domains,
        )

        if not rows and force_api_if_empty:
            st.info("No rows in DB for the filter. Fetching from API and persisting…")
            api_fetch_and_persist(provider, view_type, target_date, filter_keywords, allowed_domains)
            rows = db_fetch_emails(
                provider=provider,
                on_date=target_date,
                sender=search_sender or None,
                keyword=search_keyword or None,
                allowed_domains=allowed_domains,
            )

        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["ID", "Provider", "Subject", "From", "Date", "Priority", "Sentiment", "Type", "Resolved", "Attachments", "Entities", "BodyText"])

        st.success(f"Fetched {len(df)} emails")

        st.subheader("📄 Emails Table")
        if df.empty:
            st.info("No emails match the filters.")
        else:
            for _, row in df.iterrows():
                with st.expander(f"{row['Date']} | {row['From']} | {row['Subject']}"):
                    st.markdown(f"**ID:** {row['ID']}")
                    st.markdown(f"**Priority:** {row['Priority']}")
                    st.markdown(f"**Sentiment:** {row['Sentiment']}")
                    st.markdown(f"**Type:** {row['Type']}")
                    st.markdown(f"**Resolved:** {row['Resolved']}")
                    st.markdown(f"**Attachments:** {row['Attachments']}")
                    st.markdown("**Entities:**")
                    if row.get("Entities"):
                        for ent in row["Entities"]:
                            st.json(ent)
                    else:
                        st.write("{}")
                    with st.expander("Show body text"):
                        st.write(row.get("BodyText", ""))
                    st.markdown("---")

                    # Draft generation per email
                    if st.button(f"Generate Draft for {row['ID']}", key=f"gen_{row['ID']}"):
                        with st.spinner("Generating draft... please wait ⏳"):
                            draft = call_generate_draft_for_message(row['ID'])
                            if draft:
                                st.session_state.setdefault("drafts", {})
                                st.session_state["drafts"][row['ID']] = draft
                            else:
                                st.warning("No draft was generated.")

                    if "drafts" in st.session_state and row['ID'] in st.session_state["drafts"]:
                        draft = st.session_state["drafts"][row['ID']]
                        st.markdown("**AI Draft:**")
                        draft_text = st.text_area(
                            f"Draft content for {row['ID']}",
                            draft.get("draft_text", ""),
                            height=200,
                            key=f"draft_text_{row['ID']}"
                        )
                        col1, col2 = st.columns([1, 1])
                        with col1:
                            if st.button(f"Save Draft {row['ID']}", key=f"save_{row['ID']}"):
                                with db.Session() as session:
                                    draft_obj = session.query(AIDraft).filter_by(message_id=row['ID']).first()
                                    if draft_obj:
                                        draft_obj.draft_text = draft_text
                                        session.commit()
                                        st.success("Draft updated successfully")
                        with col2:
                            if st.button(f"Send Draft {row['ID']}", key=f"send_{row['ID']}"):
                                with db.Session() as session:
                                    draft_obj = session.query(AIDraft).filter_by(message_id=row['ID']).first()
                                    if draft_obj:
                                        draft_obj.status = "sent"
                                        session.commit()
                                        st.success("Draft sent to user ✅")

        st.subheader("📊 Email Analytics")
        metrics = compute_analytics_df(df)
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Emails", metrics["total"])
        col2.metric("Urgent Emails", metrics["urgent"])
        col3.metric("Normal Emails", metrics["normal"])
        col4.metric("Resolved", metrics["resolved"])

        draw_charts(df)

    except Exception as ex:
        st.error(f"Error fetching emails: {ex}")
