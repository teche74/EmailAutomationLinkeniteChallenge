from fastapi import APIRouter, HTTPException
from datetime import datetime
from sqlalchemy import exists
from Storage.storage import DatabaseManager
from Storage.models import EmailMessage, AIDraft, KBChunk
from EmailFetcher.Fetcher import GmailFetcher, OutlookFetcher
from transformers import pipeline

# -------------------------------
# Setup
# -------------------------------
router = APIRouter()
db = DatabaseManager()

# Load the model once globally (cached by HuggingFace)
# You can swap to a smaller/faster model if needed
generator = pipeline("text-generation", model="google/gemma-2b-it")  

# -------------------------------
# Helper Functions
# -------------------------------
def generate_reply(prompt: str) -> str:
    """Generate a reply using local HuggingFace pipeline"""
    try:
        outputs = generator(
            prompt,
            max_new_tokens=300,
            temperature=0.7,
            do_sample=True
        )
        return outputs[0]["generated_text"]
    except Exception as e:
        print(f"❌ Local model error: {e}")
        return "We are reviewing your request and will get back to you shortly."


def fetch_kb_context(session, query: str, top_k: int = 3):
    return [
        chunk.text
        for chunk in session.query(KBChunk)
        .filter(KBChunk.text.ilike(f"%{query}%"))
        .limit(top_k)
        .all()
    ]


def generate_ai_draft(session, email: EmailMessage):
    kb_contexts = fetch_kb_context(session, email.subject or "", top_k=3)
    kb_context = "\n\n".join(kb_contexts) if kb_contexts else "No relevant KB context."

    prompt = f"""
    Customer email:
    Subject: {email.subject}
    Body: {email.body_text}

    Knowledge Base Context:
    {kb_context}

    Write a professional, empathetic, and context-aware reply.
    """

    draft_text = generate_reply(prompt)
    draft = AIDraft(
        message_id=email.id,
        thread_id=email.thread_id,
        model="google/gemma-2b-it",
        prompt=prompt,
        draft_text=draft_text,
        status="proposed",
        created_at=datetime.utcnow(),
    )
    session.add(draft)

# -------------------------------
# Routes
# -------------------------------
@router.post("/generate-drafts")
def generate_drafts():
    """Generate drafts for all messages that don't already have one"""
    try:
        with db.Session() as session:
            msgs = (
                session.query(EmailMessage)
                .filter(~exists().where(AIDraft.message_id == EmailMessage.id))
                .all()
            )
            for msg in msgs:
                try:
                    generate_ai_draft(session, msg)
                except Exception as e:
                    print(f"⚠️ Failed to generate draft for {msg.id}: {e}")
            session.commit()
        return {"status": f"Drafts generated for {len(msgs)} emails"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/all")
def get_all_drafts():
    """Fetch all drafts"""
    try:
        with db.Session() as session:
            drafts = session.query(AIDraft).all()
            return [
                {"message_id": d.message_id, "draft_text": d.draft_text, "status": d.status}
                for d in drafts
            ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-draft/{message_id}")
def generate_draft_for_message(message_id: int):
    """Generate a draft for a specific message"""
    try:
        with db.Session() as session:
            msg = session.query(EmailMessage).filter_by(id=message_id).first()
            if not msg:
                raise HTTPException(status_code=404, detail="Email not found")
            generate_ai_draft(session, msg)
            session.commit()
            draft = (
                session.query(AIDraft)
                .filter_by(message_id=msg.id)
                .order_by(AIDraft.created_at.desc())
                .first()
            )
            return {
                "message_id": draft.message_id,
                "draft_text": draft.draft_text,
                "status": draft.status,
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
