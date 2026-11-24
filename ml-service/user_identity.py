"""
Resolves a stable user_id from a stored event dict (as produced by
storage.event_record_to_dict). Pure logic, no I/O.

Preference order: user_sid (stable even if a display name changes) ->
"domain\\username" -> "username" alone -> "unknown" (only when an event has
neither — this should be rare, since username/domain/sid come from
Windows' own SubjectUserSid/TargetUserSid fields, but some system-level
events legitimately omit them).
"""

from __future__ import annotations


def resolve_user_id(event: dict) -> str:
    user_sid = event.get("user_sid")
    if user_sid:
        return user_sid
    username = event.get("username")
    domain = event.get("domain")
    if username and domain:
        return f"{domain}\\{username}"
    if username:
        return username
    return "unknown"
