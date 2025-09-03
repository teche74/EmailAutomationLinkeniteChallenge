# 📧 AI-Augmented Email Automation Platform

An **end-to-end AI-powered business automation system** that ingests emails, extracts insights, and generates context-aware drafts to empower customer support agents.  
Built for the [Linkenite Hackathon](https://unstop.com/hackathons/linkenite-hackathon-challenge-ai-powered-business-automation-platform-linkenite-1548651).

---

## ✨ Features

- **Email ingestion** from Gmail & Outlook (via IMAP/MSAL)
- **Shared relational data model** in PostgreSQL for consistency across services
- **NLP pipelines**:
  - Named Entity Recognition (spaCy + regex for phones, invoices, tickets)
  - Sentiment analysis (HuggingFace)
  - Classification (impact/urgency/type)
- **Draft generation** with RAG:
  - Uses HuggingFace text-generation models
  - Fetches relevant knowledge base chunks
- **Streamlit UI**:
  - Displays threads, messages, attachments, and insights
  - Agents can generate, edit, and send drafts
  - Simple analytics dashboard (priority, sentiment, type)
- **Audit & Stats**:
  - Every action logged (`audit_events`)
  - Daily KPIs (`daily_email_stats`)

---

## 🧭 Design Principles

We strictly follow:
- **KISS**: Keep services simple & modular  
- **DRY**: One shared data model across fetchers, APIs, UI  
- **YAGNI**: Only build what is needed — avoid over-engineering  

The **shared data model** is the backbone — guaranteeing consistency, traceability, and scalability.

---

## ⚙️ Architecture

### High-Level Flow

```
[External Email Providers]
      │
      ▼ (IMAP/OAuth)
[Fetcher Service] ──> (NER, Sentiment, Classification) ──> Normalized msg_dict
      │
      ▼ (save_processed_message)
[Postgres DB]
  - email_threads, email_messages, email_extractions,
  - email_insights, email_attachments, ai_drafts, kb_chunks...
      ▲
      │ reads
[Streamlit UI] ── POST /generate-draft/{id} ──> [Draft API]
                                                  │
                                                  ▼ (Generator + KB lookup)
                                              [ai_drafts row persisted]
```

---

### Data Flow

1. **Fetch & Parse**  
   - Connect to Gmail/Outlook → fetch headers & body  
   - Extract entities, classify, sentiment  
   - Normalize into `msg_dict`  

2. **Persist**  
   - Save into Postgres:
     - `email_threads`
     - `email_messages`
     - `email_extractions`, `email_insights`, `email_attachments`

3. **UI Read**  
   - Streamlit reads from DB (SQLAlchemy)  
   - Displays enriched messages + analytics  

4. **Draft Generation**  
   - UI calls `Draft API` → loads message + KB chunks  
   - Runs HuggingFace generator → saves draft in `ai_drafts`  
   - Draft editable & sendable by agent  

---

## 🗄️ Data Model (ER Diagram)

```
+----------------------+       1         N       +----------------------+
|   email_threads      |<------------------------|    email_messages    |
| PK id                |    thread_id FK         | PK id                |
| thread_key (unique)  |                         | provider             |
| subject_canonical    |                         | provider_uid (uniq)  |
| created_at           |                         | message_id_hdr (uniq)|
| last_msg_at          |                         | thread_id (FK)       |
+----------------------+                         | body_text, urls JSON |
                                                 | attachments_meta JSON|
                                                 +----------------------+
                                                         |
                 +---------------------------------------+---------------------------------+
                 |                                       |                                 |
                 v                                       v                                 v
    +--------------------------+            +---------------------------+           +----------------------+
    | email_attachments        |            | email_extractions         |           | email_insights       |
    | PK id                   |            | PK id                    |           | PK id                |
    | message_id FK           |            | message_id FK            |           | message_id FK        |
    | filename, content_type  |            | phone, ticket_id         |           | impact, urgency, ... |
    +--------------------------+            +---------------------------+           +----------------------+

                                           ^
                                           |
                                           | 1 .. N
                                           |
                                   +--------------------+
                                   |     ai_drafts      |
                                   | PK id              |
                                   | message_id FK      |
                                   | thread_id FK       |
                                   | model, prompt      |
                                   | draft_text         |
                                   | status             |
                                   | sent_message_id FK |
                                   +--------------------+
                                           |
                                           v
                                   1 .. N   [rag_citations]
                                   +---------------------+
                                   | rag_citations       |
                                   | draft_id FK         |
                                   | chunk_id FK         |
                                   | score               |
                                   +---------------------+
                                           ^
                                           |
                                  N .. 1   |
                                   +----------------+
                                   |   kb_chunks    |
                                   | document_id FK |
                                   | chunk_index    |
                                   | text           |
                                   +----------------+
                                           |
                                           v
                                   N .. 1
                                   +----------------+
                                   |  kb_documents  |
                                   | source, title  |
                                   | metadata_json  |
                                   +----------------+
```

Other tables:
- `thread_status` → lifecycle of a thread  
- `audit_events` → logs user/system actions  
- `daily_email_stats` → aggregated KPIs  
- `latest_thread_messages` → materialized view for fast thread queries  

---

## 🚀 Getting Started

### 1. Clone & Install
```bash
git clone https://github.com/your-repo/email-automation.git
cd email-automation
pip install -r requirements.txt
```

### 2. Setup Postgres
- Run migrations:
```bash
psql $DATABASE_URL -f migration.sql
```

### 3. Environment Variables
```bash
export DATABASE_URL=postgresql://user:pass@localhost:5432/emaildb
export GMAIL_USER=...
export OUTLOOK_CLIENT_ID=...
export OUTLOOK_CLIENT_SECRET=...
```

### 4. Start APIs
```bash
uvicorn emails_api:app --reload --port 8000
uvicorn ai_draft_api:app --reload --port 8001
```

### 5. Run Streamlit UI
```bash
streamlit run app.py
```

---

## 📊 Example Workflow

1. **Fetch** emails → parsed & saved into DB  
2. **View** emails in Streamlit → insights & entities visible  
3. **Generate draft** → calls Draft API, AI draft created & editable  
4. **Send draft** → agent approves & sends, audit logged  
5. **Track KPIs** → dashboard with sentiment, urgency, daily stats  

---

## 🔮 Future Improvements

- Semantic KB search with **pgvector**  
- Async job queue for fetching/drafting at scale  
- Outbound email sending integration  
- Advanced analytics (agent performance, SLA compliance)  
- Role-based access control for multi-team usage  

---

## 🏗️ Tech Stack

- **Backend**: FastAPI  
- **Frontend**: Streamlit  
- **Database**: PostgreSQL + SQLAlchemy  
- **NLP/ML**: HuggingFace pipelines, spaCy  
- **Infra**: Docker, Uvicorn  
- **Design principles**: KISS, DRY, YAGNI  

---

## 📜 License
MIT License

---

## 🤝 Acknowledgements
- [Linkenite Hackathon](https://unstop.com/hackathons/linkenite-hackathon-challenge-ai-powered-business-automation-platform-linkenite-1548651)  
- HuggingFace & spaCy for amazing NLP tooling  
- PostgreSQL for robust relational backbone  
