from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
import os
from EmailFetcher.Fetcher import GmailFetcher, OutlookFetcher

router = APIRouter()

gmail_user = os.getenv("GMAIL_USER")
gmail_pass = os.getenv("GMAIL_PASS")
gmail_fetcher = GmailFetcher()
if gmail_user and gmail_pass:
    gmail_fetcher.login(gmail_user, gmail_pass)

outlook_fetcher = OutlookFetcher()
outlook_fetcher.login_with_stored_token()

@router.get("/gmail/today")
def get_gmail_today(
    filter_keywords: Optional[List[str]] = Query(None, description="Keywords to filter emails"),
    allowed_domains: Optional[List[str]] = Query(None, description="Domains to filter emails")
):
    try:
        if allowed_domains is not None:
            gmail_fetcher.set_domain_filter(allowed_domains)
        else:
            gmail_fetcher.set_domain_filter([])

        emails = gmail_fetcher.todayMails()

        if filter_keywords:
            emails = [
                e for e in emails
                if any(kw.lower() in (e.get("subject") or "").lower() or
                       kw.lower() in (e.get("body", {}).get("body") or "").lower()
                       for kw in filter_keywords)
            ]

        return {"emails": emails}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/gmail/by-date")
def get_gmail_by_date(
    date: str = Query(..., description="YYYY-MM-DD"),
    filter_keywords: Optional[List[str]] = Query(None, description="Keywords to filter emails"),
    allowed_domains: Optional[List[str]] = Query(None, description="Domains to filter emails")
):
    try:
        if allowed_domains is not None:
            gmail_fetcher.set_domain_filter(allowed_domains)
        else:
            gmail_fetcher.set_domain_filter([])

        emails = gmail_fetcher.mailsByDate(date)

        if filter_keywords:
            emails = [
                e for e in emails
                if any(kw.lower() in (e.get("subject") or "").lower() or
                       kw.lower() in (e.get("body", {}).get("body") or "").lower()
                       for kw in filter_keywords)
            ]

        return {"emails": emails}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/outlook/today")
def get_outlook_today(
    filter_keywords: Optional[List[str]] = Query(None, description="Keywords to filter emails"),
    allowed_domains: Optional[List[str]] = Query(None, description="Domains to filter emails")
):
    try:
        if allowed_domains is not None:
            outlook_fetcher.set_domain_filter(allowed_domains)
        else:
            outlook_fetcher.set_domain_filter([])

        emails = outlook_fetcher.todayMails()

        if filter_keywords:
            emails = [
                e for e in emails
                if any(kw.lower() in (e.get("subject") or "").lower() or
                       kw.lower() in (e.get("body", {}).get("body") or "").lower()
                       for kw in filter_keywords)
            ]

        return {"emails": emails}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/outlook/by-date")
def get_outlook_by_date(
    date: str = Query(..., description="YYYY-MM-DD"),
    filter_keywords: Optional[List[str]] = Query(None, description="Keywords to filter emails"),
    allowed_domains: Optional[List[str]] = Query(None, description="Domains to filter emails")
):
    try:
        if allowed_domains is not None:
            outlook_fetcher.set_domain_filter(allowed_domains)
        else:
            outlook_fetcher.set_domain_filter([])

        emails = outlook_fetcher.mailsByDate(date)

        if filter_keywords:
            emails = [
                e for e in emails
                if any(kw.lower() in (e.get("subject") or "").lower() or
                       kw.lower() in (e.get("body", {}).get("body") or "").lower()
                       for kw in filter_keywords)
            ]

        return {"emails": emails}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
