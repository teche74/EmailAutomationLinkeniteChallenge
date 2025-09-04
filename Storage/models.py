from sqlalchemy import (
    Column, Integer, BigInteger, String, Text, Boolean, DateTime, JSON, Float, Numeric, ForeignKey
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import TIMESTAMP, ARRAY as PG_ARRAY, JSONB

Base = declarative_base()


class EmailThread(Base):
    __tablename__ = 'email_threads'
    id = Column(BigInteger, primary_key=True)
    thread_key = Column(String, unique=True, nullable=False)
    subject_canonical = Column(Text)
    created_at = Column(TIMESTAMP)
    last_msg_at = Column(TIMESTAMP)
    messages = relationship('EmailMessage', back_populates='thread')


class EmailMessage(Base):
    __tablename__ = 'email_messages'
    id = Column(BigInteger, primary_key=True)
    provider = Column(String, nullable=False)
    provider_uid = Column(String, nullable=False)
    message_id_hdr = Column(String)
    thread_id = Column(BigInteger, ForeignKey('email_threads.id'))
    direction = Column(String, nullable=False)
    from_email = Column(String, nullable=False)
    to_emails = Column(PG_ARRAY(String), nullable=False)
    cc_emails = Column(PG_ARRAY(String))
    bcc_emails = Column(PG_ARRAY(String))
    subject = Column(Text)
    sent_at = Column(TIMESTAMP)
    received_at = Column(TIMESTAMP)
    flags = Column(PG_ARRAY(String))
    body_text = Column(Text)
    body_html = Column(Text)
    urls = Column(JSONB)
    attachments_meta = Column(JSONB)
    is_latest_in_thread = Column(Boolean, default=False)
    is_agent_reply = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP)

    thread = relationship('EmailThread', back_populates='messages')
    attachments = relationship("EmailAttachment", back_populates="message", cascade="all, delete-orphan")
    insights = relationship("EmailInsight", back_populates="message", uselist=False)
    extractions = relationship("EmailExtraction", back_populates="message", uselist=False)


class EmailAttachment(Base):
    __tablename__ = 'email_attachments'
    id = Column(BigInteger, primary_key=True)
    message_id = Column(BigInteger, ForeignKey('email_messages.id', ondelete="CASCADE"))
    filename = Column(Text)
    content_type = Column(Text)
    size_bytes = Column(BigInteger)

    message = relationship("EmailMessage", back_populates="attachments")


class EmailExtraction(Base):
    __tablename__ = 'email_extractions'
    id = Column(BigInteger, primary_key=True)
    message_id = Column(BigInteger, ForeignKey('email_messages.id'))
    phone = Column(String)
    alt_email = Column(String)
    error_code = Column(String)
    invoice_id = Column(String)
    ticket_id = Column(String)
    products = Column(JSONB)
    named_entities = Column(JSONB)
    raw_entities = Column(JSONB)
    created_at = Column(TIMESTAMP)

    message = relationship("EmailMessage", back_populates="extractions")


class EmailInsight(Base):
    __tablename__ = 'email_insights'
    id = Column(BigInteger, primary_key=True)
    message_id = Column(BigInteger, ForeignKey('email_messages.id'))
    impact = Column(String)
    urgency = Column(String)
    type = Column(String)
    priority = Column(String)
    sentiment = Column(String)
    confidence = Column(Float)
    model = Column(String)
    created_at = Column(TIMESTAMP)

    message = relationship("EmailMessage", back_populates="insights")


class ThreadStatus(Base):
    __tablename__ = 'thread_status'
    thread_id = Column(BigInteger, ForeignKey('email_threads.id'), primary_key=True)
    first_customer_at = Column(TIMESTAMP)
    last_customer_at = Column(TIMESTAMP)
    last_agent_at = Column(TIMESTAMP)
    status = Column(String)
    last_message_id = Column(BigInteger)
    is_replied = Column(Boolean, default=False)
    updated_at = Column(TIMESTAMP)


class AIDraft(Base):
    __tablename__ = 'ai_drafts'
    id = Column(BigInteger, primary_key=True)
    message_id = Column(BigInteger, ForeignKey('email_messages.id'))
    thread_id = Column(BigInteger, ForeignKey('email_threads.id'))
    model = Column(String)
    prompt = Column(Text)
    draft_text = Column(JSONB, nullable=True)
    tone_tags = Column(PG_ARRAY(String))
    priority_hint = Column(String)
    sentiment_hint = Column(String)
    status = Column(String)
    edited_text = Column(Text)
    sent_message_id = Column(BigInteger)
    tokens_prompt = Column(Integer)
    tokens_completion = Column(Integer)
    cost_usd = Column(Numeric)
    created_at = Column(TIMESTAMP)


class KBDocument(Base):
    __tablename__ = 'kb_documents'
    id = Column(BigInteger, primary_key=True)
    source = Column(String)
    external_id = Column(String)
    title = Column(String)
    metadata_json = Column("metadata", JSONB)
    created_at = Column(TIMESTAMP)
    updated_at = Column(TIMESTAMP)


class KBChunk(Base):
    __tablename__ = 'kb_chunks'
    id = Column(BigInteger, primary_key=True)
    document_id = Column(BigInteger, ForeignKey('kb_documents.id'))
    chunk_index = Column(Integer)
    text = Column(Text)
    metadata_json = Column("metadata", JSONB)
    created_at = Column(TIMESTAMP)


class RAGCitation(Base):
    __tablename__ = 'rag_citations'
    id = Column(BigInteger, primary_key=True)
    draft_id = Column(BigInteger, ForeignKey('ai_drafts.id'))
    chunk_id = Column(BigInteger, ForeignKey('kb_chunks.id'))
    score = Column(Float)


class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id = Column(BigInteger, primary_key=True)
    actor_type = Column(String)
    actor_id = Column(String)
    event_type = Column(String)
    message_id = Column(BigInteger)
    thread_id = Column(BigInteger)
    metadata_json = Column("metadata", JSONB)
    created_at = Column(TIMESTAMP)


class DailyEmailStats(Base):
    __tablename__ = 'daily_email_stats'
    day = Column(DateTime, primary_key=True)
    total_inbound = Column(Integer)
    total_outbound = Column(Integer)
    open_threads = Column(Integer)
    resolved_threads = Column(Integer)
    avg_first_response_seconds = Column(BigInteger)
    urgent_inbound = Column(Integer)
    negative_sentiment = Column(Integer)
