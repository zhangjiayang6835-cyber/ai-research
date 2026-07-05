"""XS-Search mitigation for issue #255.

Cross-Site Search attacks exploit observable differences in search endpoints:
status codes, result counts, response sizes, cache state, or timing can reveal
whether a victim has private data matching an attacker-chosen query. The safe
pattern is to require same-site authenticated requests for real results and to
return a constant opaque response for cross-site or unauthenticated probes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


TRUSTED_ORIGIN = "https://app.example.com"
SAFE_EMPTY_BODY = '{"results":[],"next":null}'
SAFE_HEADERS = {
    "Cache-Control": "no-store, private",
    "Content-Type": "application/json",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Vary": "Origin, Sec-Fetch-Site, Cookie, Authorization",
    "X-Content-Type-Options": "nosniff",
}


@dataclass(frozen=True)
class SearchDocument:
    owner_id: str
    title: str
    body: str


@dataclass(frozen=True)
class RequestContext:
    user_id: str | None
    origin: str | None
    sec_fetch_site: str | None
    has_session_cookie: bool
    csrf_token_valid: bool


@dataclass(frozen=True)
class SearchResponse:
    status: int
    body: str
    headers: Mapping[str, str]
    results: tuple[SearchDocument, ...] = ()


def safe_private_search(query: str, context: RequestContext, documents: Iterable[SearchDocument]) -> SearchResponse:
    """Search private documents without leaking existence to cross-site probes."""

    if not _is_same_site_authenticated(context):
        return _opaque_empty_response()

    clean_query = _normalize_query(query)
    if not clean_query:
        return _authorized_response(())

    matches = tuple(
        doc
        for doc in documents
        if doc.owner_id == context.user_id and (clean_query in doc.title.lower() or clean_query in doc.body.lower())
    )
    return _authorized_response(matches)


def vulnerable_private_search_count(query: str, context: RequestContext, documents: Iterable[SearchDocument]) -> int:
    """Model the unsafe search-count leak used by regression tests."""

    clean_query = _normalize_query(query)
    return sum(
        1
        for doc in documents
        if doc.owner_id == context.user_id and clean_query and (clean_query in doc.title.lower() or clean_query in doc.body.lower())
    )


def _is_same_site_authenticated(context: RequestContext) -> bool:
    if not context.user_id or not context.has_session_cookie or not context.csrf_token_valid:
        return False
    if context.origin != TRUSTED_ORIGIN:
        return False
    return context.sec_fetch_site in {"same-origin", "same-site", None}


def _opaque_empty_response() -> SearchResponse:
    return SearchResponse(status=200, body=SAFE_EMPTY_BODY, headers=SAFE_HEADERS, results=())


def _authorized_response(results: Iterable[SearchDocument]) -> SearchResponse:
    result_tuple = tuple(results)
    body = '{"results":[' + ",".join(_document_json(doc) for doc in result_tuple) + '],"next":null}'
    return SearchResponse(status=200, body=body, headers=SAFE_HEADERS, results=result_tuple)


def _normalize_query(query: str) -> str:
    if not isinstance(query, str):
        return ""
    return " ".join(query.lower().split())[:128]


def _document_json(doc: SearchDocument) -> str:
    return (
        '{"title":"'
        + _json_escape(doc.title)
        + '","body":"'
        + _json_escape(doc.body)
        + '"}'
    )


def _json_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


__all__ = [
    "RequestContext",
    "SearchDocument",
    "SearchResponse",
    "SAFE_EMPTY_BODY",
    "SAFE_HEADERS",
    "TRUSTED_ORIGIN",
    "safe_private_search",
    "vulnerable_private_search_count",
]
