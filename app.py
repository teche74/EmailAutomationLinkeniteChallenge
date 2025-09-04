import os
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st
import requests
from sqlalchemy import or_, and_, cast, Date

from API import emails_api
from Storage.storage import DatabaseManager
from Storage.models import (
    AIDraft,
    EmailMessage,
    EmailInsight,
    EmailExtraction,
    EmailAttachment,
)

st.set_page_config(page_title="Support Email Dashboard", layout="wide")
st.title("📧 Support Email Dashboard")


db = DatabaseManager()

DRAFT_API_URL = os.getenv("DRAFT_API_URL", "http://localhost:8000")

def call_generate_draft_for_message(message_id: int):
    try:
        r = requests.post(f"{DRAFT_API_URL}/generate-draft/{message_id}", timeout=300)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Draft generation failed for {message_id}: {e}")
        return None


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
        "Priority": (getattr(ins, "priority", None) or "Normal"),
        "Sentiment": (getattr(ins, "sentiment", None) or "Neutral"),
        "Type": getattr(ins, "type", None) or "N/A",
        "Resolved": "Yes" if (msg.flags and len(msg.flags) > 0) else "No",
        "Attachments": ", ".join([a.filename for a in atts]) if atts else "",
        "Entities": [e.raw_entities for e in exts] if exts else [],
        "BodyText": msg.body_text or "",
    }


@st.cache_data(ttl=60, show_spinner=False)
def db_fetch_emails(
    provider: str,
    on_date: date | None,
    sender: str | None,
    keyword: str | None,
    allowed_domains: List[str] | None,
) -> List[Dict[str, Any]]:
    """Fast DB read with light caching to avoid visible reloads."""
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
        extraction_map: Dict[int, list] = {}
        for e in ext_rows:
            extraction_map.setdefault(e.message_id, []).append(e)
        attachments_map: Dict[int, list] = {}
        for a in att_rows:
            attachments_map.setdefault(a.message_id, []).append(a)

        rows = [
            normalize_row(m, insight_map=insight_map, extraction_map=extraction_map, attachments_map=attachments_map)
            for m in msgs
        ]
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
    db_fetch_emails.clear()
    return data


def compute_analytics_df(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"total": 0, "urgent": 0, "normal": 0, "resolved": 0}

    pr = df["Priority"].astype(str).str.lower()
    rs = df["Resolved"].astype(str)
    return {
        "total": len(df),
        "urgent": len(pr[pr.isin(["urgent"])]) + len(pr[pr.isin(["high"])]),
        "normal": len(pr[pr.isin(["normal"])]) + len(pr[pr.isin(["low"])]),
        "resolved": len(rs[rs == "Yes"]),
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


st.sidebar.header("Filters & Actions")

provider = st.sidebar.selectbox("Email Provider", ["Gmail", "Outlook"], key="provider")
view_type = st.sidebar.radio("View Type", ["Today", "By Date"], key="view_type")

selected_date = None
if view_type == "By Date":
    selected_date = st.sidebar.date_input("Select Date", date.today(), key="selected_date")

st.sidebar.markdown("### Source Filters (DB/API)")
filter_type = st.sidebar.radio("Choose filter type:", ["Keywords", "Domains", "Extra Input"], key="filter_type")

filter_keywords = None
allowed_domains = None

if filter_type == "Keywords":
    search_keywords = st.sidebar.text_area("Enter keywords (comma-separated):", "support,query,request,help", key="kw_text")
    filter_keywords = [k.strip() for k in search_keywords.split(",") if k.strip()]
elif filter_type == "Domains":
    domain_input = st.sidebar.text_area("Enter domains (comma-separated, e.g., @company.com):", key="dom_text")
    allowed_domains = [d.strip() for d in domain_input.split(",") if d.strip()]
else:
    extra_input = st.sidebar.text_area("Extra filter input:", key="extra_text")
    filter_keywords = [extra_input.strip()] if extra_input.strip() else None

search_sender = st.sidebar.text_input("Filter by Sender", key="sender")
search_keyword = st.sidebar.text_input("Filter by Subject/Body Keyword", key="kw")

st.sidebar.divider()
force_api_if_empty = st.sidebar.checkbox("If DB empty, fetch from API and persist", value=True, key="force_api")
sync_now = st.sidebar.button("🔄 Sync from API now (force)", key="sync")
auto_refresh = st.sidebar.toggle("Live mode (auto-refresh every 30s)", value=False, key="live")

if auto_refresh:
    try:
        from streamlit_extras.app_autorefresh import st_autorefresh  
        st_autorefresh(interval=60 * 1000, key="autorefresh_key")
    except Exception:
        st.markdown("<meta http-equiv='refresh' content='60'>", unsafe_allow_html=True)


st.sidebar.markdown("---")
st.sidebar.subheader("⚡ Real‑Time Query Builder (Client‑side)")

# Quick toggles
only_high = st.sidebar.checkbox("High/Urgent priority only", value=False)
only_negative = st.sidebar.checkbox("Negative sentiment only", value=False)

priority_multi = st.sidebar.multiselect(
    "Priority in…",
    options=["Urgent", "High", "Normal", "Low"],
    default=[],
)

sentiment_multi = st.sidebar.multiselect(
    "Sentiment in…",
    options=["Negative", "Neutral", "Positive"],
    default=[],
)

etype_multi = st.sidebar.multiselect(
    "Type in…",
    options=["Support", "Request", "Complaint", "Bug", "Feedback", "N/A"],
    default=[],
)

has_attachments = st.sidebar.selectbox("Attachments", ["Any", "Only with attachments", "Only without attachments"], index=0)
resolved_filter = st.sidebar.selectbox("Resolved", ["Any", "Yes", "No"], index=0)

query_first = st.sidebar.text_input("Query first (search Subject/Body/From)", key="query_first")

with st.sidebar.expander("Advanced conditions"):
    logic = st.radio("Combine conditions with", ["ALL (AND)", "ANY (OR)"], index=0, horizontal=True, key="adv_logic")
    num_rows = st.number_input("Rows", min_value=0, max_value=10, value=0, step=1, key="adv_rows")

    adv_rows: List[Tuple[str, str, str]] = []
    field_options = [
        "Priority", "Sentiment", "Type", "From", "Subject", "BodyText", "Resolved",
    ]
    op_map = {
        "=": lambda a, b: str(a).strip().lower() == str(b).strip().lower(),
        "contains": lambda a, b: str(b).strip().lower() in str(a).strip().lower(),
        "starts with": lambda a, b: str(a).strip().lower().startswith(str(b).strip().lower()),
        "ends with": lambda a, b: str(a).strip().lower().endswith(str(b).strip().lower()),
        "!=": lambda a, b: str(a).strip().lower() != str(b).strip().lower(),
    }

    for i in range(int(num_rows)):
        c1, c2, c3 = st.columns([1.1, 1, 1.5])
        with c1:
            f = st.selectbox(f"Field {i+1}", options=field_options, key=f"adv_field_{i}")
        with c2:
            o = st.selectbox(f"Op {i+1}", options=list(op_map.keys()), key=f"adv_op_{i}")
        with c3:
            v = st.text_input(f"Value {i+1}", key=f"adv_val_{i}")
        adv_rows.append((f, o, v))


if sync_now:
    with st.spinner("Syncing from API…"):
        api_fetch_and_persist(provider, view_type, selected_date or date.today(), filter_keywords, allowed_domains)
        st.success("API sync completed and data persisted to DB.")

_target_date = selected_date if view_type == "By Date" else date.today()
rows = db_fetch_emails(
    provider=provider,
    on_date=_target_date,
    sender=search_sender or None,
    keyword=search_keyword or None,
    allowed_domains=allowed_domains,
)

if not rows and st.session_state.get("force_api"):
    with st.spinner("No rows in DB for the filter. Fetching from API and persisting…"):
        api_fetch_and_persist(provider, view_type, _target_date, filter_keywords, allowed_domains)
        rows = db_fetch_emails(
            provider=provider,
            on_date=_target_date,
            sender=search_sender or None,
            keyword=search_keyword or None,
            allowed_domains=allowed_domains,
        )

df = pd.DataFrame(rows) if rows else pd.DataFrame(
    columns=[
        "ID", "Provider", "Subject", "From", "Date", "Priority", "Sentiment", "Type",
        "Resolved", "Attachments", "Entities", "BodyText",
    ]
)

if not df.empty and query_first:
    q = query_first.strip().lower()
    df = df[
        df[["Subject", "BodyText", "From"]]
        .astype(str)
        .apply(lambda c: c.str.lower().str.contains(q, na=False))
        .any(axis=1)
    ]

if not df.empty and only_high:
    df = df[df["Priority"].astype(str).str.lower().isin(["urgent", "high"])]
if not df.empty and only_negative:
    df = df[df["Sentiment"].astype(str).str.lower() == "negative"]

if not df.empty and priority_multi:
    df = df[df["Priority"].isin(priority_multi)]
if not df.empty and sentiment_multi:
    df = df[df["Sentiment"].isin(sentiment_multi)]
if not df.empty and etype_multi:
    df = df[df["Type"].isin(etype_multi)]

if not df.empty and has_attachments != "Any":
    if has_attachments == "Only with attachments":
        df = df[df["Attachments"].astype(str).str.len() > 0]
    else:
        df = df[df["Attachments"].astype(str).str.len() == 0]

if not df.empty and resolved_filter != "Any":
    df = df[df["Resolved"] == resolved_filter]

if not df.empty and 'adv_rows' in locals() and len(adv_rows) > 0:
    def apply_row(row) -> bool:
        results = []
        for f, o, v in adv_rows:
            left = row.get(f, "")
            fn = op_map[o]
            try:
                results.append(fn(left, v))
            except Exception:
                results.append(False)
        return all(results) if logic.startswith("ALL") else any(results)

    df = df[df.apply(apply_row, axis=1)]

st.success(f"Showing {len(df)} emails (after client filters)")

st.subheader("📄 Emails Table")

if df.empty:
    st.info("No emails match the filters.")
else:
    table_df = df[["ID", "Date", "From", "Subject", "Priority", "Sentiment", "Type", "Resolved", "Attachments"]].copy()
    table_df.insert(0, "Select", False)

    edited = st.data_editor(
        table_df.sort_values("Date", ascending=False),
        hide_index=True,
        use_container_width=True,
        column_config={
            "Select": st.column_config.CheckboxColumn(help="Click to view details below", default=False),
        },
        disabled=[c for c in table_df.columns if c != "Select"],
        key="emails_grid",
    )

    selected_rows = edited[edited["Select"]].drop(columns=["Select"]) if not edited.empty else pd.DataFrame()

    selected_id = None
    if not selected_rows.empty:
        selected_rows_sorted = selected_rows.sort_values("Date", ascending=False)
        selected_id = int(selected_rows_sorted.iloc[0]["ID"]) if "ID" in selected_rows_sorted.columns else None

    st.markdown("---")
    st.subheader("🔎 Details & AI Draft")

    if not selected_id:
        st.info("Select a row in the table above to view details and manage the AI draft.")
    else:
        selected = df[df["ID"] == selected_id].iloc[0]
        left, right = st.columns([2, 1])
        with left:
            st.markdown(f"**ID:** {selected['ID']}")
            st.markdown(f"**From:** {selected['From']}")
            st.markdown(f"**Subject:** {selected['Subject']}")
            st.markdown(f"**Date:** {selected['Date']}")
            st.markdown(f"**Priority:** {selected['Priority']}")
            st.markdown(f"**Sentiment:** {selected['Sentiment']}")
            st.markdown(f"**Type:** {selected['Type']}")
            st.markdown(f"**Resolved:** {selected['Resolved']}")
            st.markdown(f"**Attachments:** {selected['Attachments']}")
            st.markdown("**Entities:**")
            if selected.get("Entities"):
                for ent in selected["Entities"]:
                    st.json(ent)
            else:
                st.write("{}")
            with st.expander("Show body text"):
                st.write(selected.get("BodyText", ""))

        with right:
            if st.button(f"Generate Draft for {selected['ID']}", key=f"gen_{selected['ID']}"):
                with st.spinner("Generating draft... ⏳"):
                    draft = call_generate_draft_for_message(selected['ID'])
                    if draft:
                        st.session_state.setdefault("drafts", {})
                        st.session_state["drafts"][selected['ID']] = draft
                    else:
                        st.warning("No draft was generated.")

            if "drafts" in st.session_state and selected['ID'] in st.session_state["drafts"]:
                draft = st.session_state["drafts"][selected['ID']]
                st.markdown("**AI Draft Email**")
                
                subject_val = st.text_input(
                    "Subject", draft.get("subject", ""),
                    key=f"subject_{selected['ID']}"
                )

                body_val = st.text_area(
                    "Body", draft.get("body", ""),
                    height=200,
                    key=f"body_{selected['ID']}"
                )

                to_val = st.text_input("To (comma separated)", ", ".join(draft.get("to", [])), key=f"to_{selected['ID']}")
                cc_val = st.text_input("CC (comma separated)", ", ".join(draft.get("cc", [])), key=f"cc_{selected['ID']}")
                bcc_val = st.text_input("BCC (comma separated)", ", ".join(draft.get("bcc", [])), key=f"bcc_{selected['ID']}")


                col1, col2 = st.columns([1, 1])
                with col1:
                    if st.button(f"Save Draft {selected['ID']}", key=f"save_{selected['ID']}"):
                        with db.Session() as session:
                            draft_obj = session.query(AIDraft).filter_by(message_id=selected['ID']).first()
                            if draft_obj:
                                draft_obj.draft_text = json.dumps({
                                    "subject": subject_val,
                                    "body": body_val,
                                    "to": [x.strip() for x in to_val.split(",") if x.strip()],
                                    "cc": [x.strip() for x in cc_val.split(",") if x.strip()],
                                    "bcc": [x.strip() for x in bcc_val.split(",") if x.strip()],
                                })
                                session.commit()
                                st.success("Draft updated successfully")
                with col2:
                    if st.button(f"Send Draft {selected['ID']}", key=f"send_{selected['ID']}"):
                        payload = {
                            "subject": subject_val,
                            "body": body_val,
                            "to": [x.strip() for x in to_val.split(",") if x.strip()],
                            "cc": [x.strip() for x in cc_val.split(",") if x.strip()],
                            "bcc": [x.strip() for x in bcc_val.split(",") if x.strip()],
                        }
                        r = requests.post(f"{DRAFT_API_URL}/send-mail", json=payload)  # adjust endpoint
                        if r.status_code == 200:
                            with db.Session() as session:
                                draft_obj = session.query(AIDraft).filter_by(message_id=selected['ID']).first()
                                if draft_obj:
                                    draft_obj.status = "sent"
                                    session.commit()
                            st.success("Draft sent successfully 🚀")
                        else:
                            st.error(f"Failed to send: {r.text}")

st.subheader("📊 Email Analytics (Client‑side slice)")
metrics = compute_analytics_df(df)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Emails", metrics["total"])
col2.metric("Urgent Emails", metrics["urgent"])
col3.metric("Normal Emails", metrics["normal"])
col4.metric("Resolved", metrics["resolved"])

draw_charts(df)
