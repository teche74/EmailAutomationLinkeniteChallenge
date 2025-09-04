from fastapi import APIRouter, HTTPException, Body
from datetime import datetime
from sqlalchemy import exists
from Storage.storage import DatabaseManager
from Storage.models import EmailMessage, AIDraft, KBChunk
from transformers import pipeline
import json
from typing import Any, Dict, Optional, List

router = APIRouter()
db = DatabaseManager()


generator = pipeline(
    "text-generation",
    model="mistralai/Mistral-7B-Instruct-v0.2",
    device_map="auto"
)

DEFAULT_MODEL = "mistralai/Mistral-7B-Instruct-v0.2"


def _safe_extract_model_text(outputs: list) -> str:
    if not outputs:
        return ""
    out0 = outputs[0]
    
    for k in ("generated_text", "text", "output_text"):
        if isinstance(out0, dict) and k in out0 and out0[k]:
            return out0[k]
    
    try:
        return str(out0)
    except Exception:
        return ""


def _ensure_list_of_str(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    if isinstance(val, str):
        parts = [p.strip() for p in val.split(",") if p.strip()]
        return parts
    return [str(val)]


def generate_reply(prompt: str) -> dict:
    try:
        formatted_prompt = f"""
        [INST] You are an AI email assistant.
        Based on the following customer email and knowledge base context,
        generate a reply strictly in JSON format with this schema:

        {{
          "subject": "string - reply subject line",
          "body": "string - the reply email body in plain English",
          "to": ["recipient@example.com"],
          "cc": ["optional.cc@example.com"],
          "bcc": ["optional.bcc@example.com"]
        }}

        Only output valid JSON — no extra commentary.

        Customer Email + Context:
        {prompt}
        [/INST]
        """

        outputs = generator(
            formatted_prompt,
            max_new_tokens=600,
            temperature=0.7,
            do_sample=True
        )
        raw_text = _safe_extract_model_text(outputs)

        
        try:
            start = raw_text.find("{")
            end = raw_text.rfind("}") + 1
            candidate = raw_text[start:end]
            parsed = json.loads(candidate)
        except Exception:
            
            print(f"⚠️ Failed to parse JSON from model. Raw: {raw_text}")
            parsed = {"subject": "Re: (auto-draft)", "body": raw_text.strip(), "to": [], "cc": [], "bcc": []}

        
        parsed["to"] = _ensure_list_of_str(parsed.get("to"))
        parsed["cc"] = _ensure_list_of_str(parsed.get("cc"))
        parsed["bcc"] = _ensure_list_of_str(parsed.get("bcc"))

        
        for k in ("subject", "body", "to", "cc", "bcc"):
            parsed.setdefault(k, "" if k in ("subject", "body") else [])

        return parsed

    except Exception as e:
        print(f"❌ Local model error: {e}")
        return {
            "subject": "Re: (error)",
            "body": "We are reviewing your request and will get back to you shortly.",
            "to": [],
            "cc": [],
            "bcc": []
        }


def fetch_kb_context(session, query: str, top_k: int = 3):
    return [
        chunk.text
        for chunk in session.query(KBChunk)
        .filter(KBChunk.text.ilike(f"%{query}%"))
        .limit(top_k)
        .all()
    ]


def generate_ai_draft(session, email: EmailMessage) -> int:
    kb_contexts = fetch_kb_context(session, email.subject or "", top_k=3)
    kb_context = "\n\n".join(kb_contexts) if kb_contexts else "No relevant KB context."

    prompt = f"""
Subject: {email.subject or "(no subject)"}
Body: {email.body_text or "(no body)"}

Knowledge Base Context:
{kb_context}
"""

    draft_json = generate_reply(prompt)

    draft_payload = {
        "message_id": email.id,
        "thread_id": email.thread_id,
        "model": DEFAULT_MODEL,
        "prompt": prompt,
        "draft_json": draft_json,
        "status": "proposed",
    }

    draft_id = db.save_ai_draft(draft_payload)
    return draft_id



@router.post("/generate-drafts")
def generate_drafts():
    try:
        with db.Session() as session:
            msgs = (
                session.query(EmailMessage)
                .filter(~exists().where(AIDraft.message_id == EmailMessage.id))
                .all()
            )
            created = 0
            for msg in msgs:
                try:
                    generate_ai_draft(session, msg)
                    created += 1
                except Exception as e:
                    print(f"⚠️ Failed to generate draft for {msg.id}: {e}")
            
        return {"status": f"Drafts generated for {created} emails"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/all")
def get_all_drafts():
    try:
        with db.Session() as session:
            drafts = session.query(AIDraft).all()
            results = []
            for d in drafts:
                
                dj = None
                if getattr(d, "draft_json", None):
                    dj = d.draft_json
                elif d.draft_text:
                    try:
                        dj = json.loads(d.draft_text)
                    except Exception:
                        dj = {"subject": None, "body": d.draft_text, "to": [], "cc": [], "bcc": []}
                results.append({
                    "id": d.id,
                    "message_id": d.message_id,
                    "draft_json": dj,
                    "draft_text": d.draft_text,
                    "status": d.status,
                    "created_at": d.created_at.isoformat() if d.created_at else None
                })
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-draft/{message_id}")
def generate_draft_for_message(message_id: int):
    try:
        with db.Session() as session:
            msg = session.query(EmailMessage).filter_by(id=message_id).first()
            if not msg:
                raise HTTPException(status_code=404, detail="Email not found")
            draft_id = generate_ai_draft(session, msg)
            
            with db.Session() as s2:
                d = s2.query(AIDraft).filter_by(id=draft_id).first()
                dj = d.draft_json or (json.loads(d.draft_text) if d.draft_text else None)
                return {
                    "draft_id": d.id,
                    "message_id": d.message_id,
                    "draft_json": dj,
                    "status": d.status
                }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/save/{message_id}")
def save_draft(message_id: int, payload: Dict[str, Any] = Body(...)):
    try:
        draft_json = payload.get("draft_json")
        if not draft_json:
            raise HTTPException(status_code=400, detail="draft_json is required")

        
        draft_json["to"] = _ensure_list_of_str(draft_json.get("to"))
        draft_json["cc"] = _ensure_list_of_str(draft_json.get("cc"))
        draft_json["bcc"] = _ensure_list_of_str(draft_json.get("bcc"))

        with db.Session() as session:
            
            existing = session.query(AIDraft).filter_by(message_id=message_id).order_by(AIDraft.created_at.desc()).first()
            if existing:
                existing.draft_json = draft_json
                
                existing.draft_text = json.dumps(draft_json)
                existing.status = payload.get("status", existing.status or "proposed")
                session.commit()
                return {"updated": True, "draft_id": existing.id}
            else:
                
                draft_payload = {
                    "message_id": message_id,
                    "thread_id": payload.get("thread_id"),
                    "model": payload.get("model", "ui/manual"),
                    "prompt": payload.get("prompt"),
                    "draft_json": draft_json,
                    "draft_text": json.dumps(draft_json),
                    "status": payload.get("status", "proposed"),
                }
                new_id = db.save_ai_draft(draft_payload)
                return {"created": True, "draft_id": new_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send/{draft_id}")
def send_draft(draft_id: int):
    try:
        with db.Session() as session:
            draft = session.query(AIDraft).filter_by(id=draft_id).first()
            if not draft:
                raise HTTPException(status_code=404, detail="Draft not found")

            
            payload = draft.draft_json or (json.loads(draft.draft_text) if draft.draft_text else None)
            if not payload:
                raise HTTPException(status_code=400, detail="No draft JSON to send")

            
            to_emails = _ensure_list_of_str(payload.get("to"))
            cc_emails = _ensure_list_of_str(payload.get("cc"))
            bcc_emails = _ensure_list_of_str(payload.get("bcc"))

            
            outbound = EmailMessage(
                provider="outbound",
                provider_uid=f"send-{draft.id}-{int(datetime.utcnow().timestamp())}",
                message_id_hdr=None,
                thread_id=draft.thread_id,
                direction="outbound",
                from_email="support@example.com",
                to_emails=to_emails,
                cc_emails=cc_emails,
                bcc_emails=bcc_emails,
                subject=payload.get("subject"),
                sent_at=datetime.utcnow(),
                received_at=None,
                flags=[],
                body_text=payload.get("body"),
                body_html=None,
                urls=[],
                attachments_meta=[],
                is_agent_reply=True,
                created_at=datetime.utcnow(),
            )
            session.add(outbound)
            session.flush()

            draft.status = "sent"
            draft.sent_message_id = outbound.id
            session.commit()

            return {"status": "sent", "draft_id": draft.id, "sent_message_id": outbound.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
