-- Migration SQL: create extensions, tables, indexes

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS vector; -- pgvector extension


-- Threads table
CREATE TABLE IF NOT EXISTS email_threads (
    id BIGSERIAL PRIMARY KEY,
    thread_key TEXT UNIQUE NOT NULL,
    subject_canonical TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_msg_at TIMESTAMPTZ
);

-- Messages (inbound + outbound)
CREATE TABLE IF NOT EXISTS email_messages (
    id BIGSERIAL PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_uid TEXT NOT NULL,
    message_id_hdr TEXT,
    thread_id BIGINT REFERENCES email_threads(id) ON DELETE SET NULL,
    direction TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
    from_email TEXT NOT NULL,
    to_emails TEXT[] NOT NULL,
    cc_emails TEXT[] DEFAULT '{}',
    bcc_emails TEXT[] DEFAULT '{}',
    subject TEXT,
    sent_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ DEFAULT now(),
    flags TEXT[] DEFAULT '{}',
    body_text TEXT,
    body_html TEXT,
    urls JSONB DEFAULT '[]',
    attachments_meta JSONB DEFAULT '[]',
    is_latest_in_thread BOOLEAN DEFAULT false,
    is_agent_reply BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT uq_provider_uid UNIQUE (provider, provider_uid),
    CONSTRAINT uq_message_id_hdr UNIQUE (message_id_hdr)
);

CREATE INDEX IF NOT EXISTS idx_email_messages_thread_sent ON email_messages (thread_id, sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_messages_is_agent_reply ON email_messages (is_agent_reply);
CREATE INDEX IF NOT EXISTS idx_email_messages_subject_trgm ON email_messages USING gin (subject gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_email_messages_sent_at ON email_messages (sent_at);


-- Extractions
CREATE TABLE IF NOT EXISTS email_extractions (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT REFERENCES email_messages(id) ON DELETE CASCADE,
    phone TEXT,
    alt_email TEXT,
    error_code TEXT,
    invoice_id TEXT,
    ticket_id TEXT,
    products JSONB,
    named_entities JSONB,
    raw_entities JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_extractions_phone ON email_extractions (phone);
CREATE INDEX IF NOT EXISTS idx_extractions_ticket ON email_extractions (ticket_id);

CREATE TABLE IF NOT EXISTS email_insights (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT REFERENCES email_messages(id) ON DELETE CASCADE,
    impact TEXT,
    urgency TEXT,
    type TEXT,
    priority TEXT,
    sentiment TEXT,
    confidence REAL,
    model TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_insights_priority_sentiment ON email_insights (priority, sentiment);
CREATE INDEX IF NOT EXISTS idx_insights_type ON email_insights (type);

CREATE TABLE IF NOT EXISTS thread_status (
    thread_id BIGINT PRIMARY KEY REFERENCES email_threads(id) ON DELETE CASCADE,
    first_customer_at TIMESTAMPTZ,
    last_customer_at TIMESTAMPTZ,
    last_agent_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','waiting_on_customer','resolved','closed')),
    last_message_id BIGINT REFERENCES email_messages(id),
    is_replied BOOLEAN DEFAULT false,
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_thread_status_status ON thread_status (status);


CREATE TABLE IF NOT EXISTS ai_drafts (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT REFERENCES email_messages(id) ON DELETE CASCADE,
    thread_id BIGINT REFERENCES email_threads(id) ON DELETE CASCADE,
    model TEXT,
    prompt TEXT,
    draft_text TEXT,
    tone_tags TEXT[] DEFAULT '{}',
    priority_hint TEXT,
    sentiment_hint TEXT,
    status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','edited','approved','sent','rejected')),
    edited_text TEXT,
    sent_message_id BIGINT REFERENCES email_messages(id),
    tokens_prompt INT,
    tokens_completion INT,
    cost_usd NUMERIC(10,4),
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_drafts_thread_status ON ai_drafts (thread_id, status);


CREATE TABLE IF NOT EXISTS kb_documents (
    id BIGSERIAL PRIMARY KEY,
    source TEXT,
    external_id TEXT,
    title TEXT,
    metadata_json JSONB,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS kb_chunks (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT REFERENCES kb_documents(id) ON DELETE CASCADE,
    chunk_index INT,
    text TEXT,
    metadata_json JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rag_citations (
    id BIGSERIAL PRIMARY KEY,
    draft_id BIGINT REFERENCES ai_drafts(id) ON DELETE CASCADE,
    chunk_id BIGINT REFERENCES kb_chunks(id) ON DELETE CASCADE,
    score REAL
);


CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    actor_type TEXT CHECK (actor_type IN ('system','agent','customer')),
    actor_id TEXT,
    event_type TEXT,
    message_id BIGINT REFERENCES email_messages(id),
    thread_id BIGINT REFERENCES email_threads(id),
    metadata_json JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_created ON audit_events (event_type, created_at);


CREATE TABLE IF NOT EXISTS daily_email_stats (
    day DATE PRIMARY KEY,
    total_inbound INT DEFAULT 0,
    total_outbound INT DEFAULT 0,
    open_threads INT DEFAULT 0,
    resolved_threads INT DEFAULT 0,
    avg_first_response_seconds BIGINT,
    urgent_inbound INT DEFAULT 0,
    negative_sentiment INT DEFAULT 0
);


CREATE MATERIALIZED VIEW IF NOT EXISTS latest_thread_messages AS
SELECT DISTINCT ON (t.id) t.id AS thread_id, m.*
FROM email_threads t
JOIN email_messages m ON m.thread_id = t.id
ORDER BY t.id, m.sent_at DESC;


CREATE INDEX IF NOT EXISTS idx_email_extractions_products ON email_extractions USING gin ((products));
CREATE INDEX IF NOT EXISTS idx_email_extractions_named_entities ON email_extractions USING gin ((named_entities));
