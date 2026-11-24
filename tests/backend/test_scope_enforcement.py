"""Stage 4G / Finding 1: monitoring scope is enforced on the category that the Windows EVENT ID
implies - never on the label an agent attaches.

Audit evidence this fixes: an endpoint approved only for `authentication` could submit a
process-creation event (ID 4688) by labelling it `authentication`."""

import pytest

from app.repositories.pipeline_bridge import event_parser, storage
from app.services import ingestion_service
from tests.backend.test_enrollment_tokens import (  # noqa: F401  (fixtures + helpers shared with the enrollment tests)
    _approved,
    _headers,
    _mint,
    _redeem,
    agent_http,
    alice,
    installer,
)

# one real Windows event id per category, plus the full set the collector supports
ID = {"authentication": 4624, "file_activity": 4663, "process_activity": 4688, "device_activity": 6416}
ALL_IDS = {4624: "authentication", 4625: "authentication", 4634: "authentication", 4647: "authentication",
           4656: "file_activity", 4660: "file_activity", 4663: "file_activity", 4688: "process_activity", 6416: "device_activity"}
NON_AUTH_IDS = [4656, 4660, 4663, 4688, 6416]
_record = iter(range(1, 10_000_000))


def ev(event_id, label="__omit__", **over):
    """A minimal valid event; `label` omitted by default (key absent), None allowed, anything allowed."""
    e = {"event_id": event_id, "event_type": "t", "timestamp": "2026-01-01T00:00:00.000000Z",
         "computer_name": "SCOPE-FIXTURE", "username": "fixture", "event_record_id": next(_record)}
    if label != "__omit__":
        e["event_category"] = label
    e.update(over)
    return e


def enroll(client, alice, agent_http, scope):
    rid = _approved(client, alice, scope=("authentication", "file_activity", "process_activity", "device_activity"), approve_scope=scope)
    data = _redeem(agent_http, _mint(alice, rid)[0]).json()
    return _headers(data)


def send(agent_http, headers, *events):
    r = agent_http.post("/api/ingest/events", json={"log_name": "Security", "events": list(events)}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def stored(test_session):
    return sorted((r.event_id, r.event_category) for r in test_session.query(storage.EventRecord))


def reasons(body):
    return sorted(r for e in body["errors"] for r in e["errors"])


# ---------------------------------------------------------------- the audited attack


@pytest.mark.parametrize("event_id", NON_AUTH_IDS)
def test_authentication_only_endpoint_cannot_submit_other_activity_by_relabelling(client, alice, installer, agent_http, test_session, event_id):
    h = enroll(client, alice, agent_http, ("authentication",))
    forged = send(agent_http, h, ev(event_id, "authentication"))
    assert forged["accepted"] == 0 and reasons(forged) == ["event_category_mismatch"]  # the lie is rejected outright
    honest = send(agent_http, h, ev(event_id, ALL_IDS[event_id]))
    assert honest["accepted"] == 0 and honest["out_of_scope"] == 1  # the truth is simply out of scope
    unlabelled = send(agent_http, h, ev(event_id))
    assert unlabelled["accepted"] == 0 and unlabelled["out_of_scope"] == 1  # no label: the id decides
    nulled = send(agent_http, h, ev(event_id, None))
    assert nulled["accepted"] == 0 and nulled["out_of_scope"] == 1
    assert stored(test_session) == []  # nothing from any of the four attempts reached the database


@pytest.mark.parametrize("scope,event_id,claims", [
    (("authentication", "device_activity"), 4688, "device_activity"),
    (("authentication", "device_activity"), 4663, "authentication"),
    (("process_activity",), 4624, "process_activity"),
    (("file_activity",), 6416, "file_activity"),
    (("device_activity",), 4688, "device_activity"),
])
def test_relabelling_never_works_for_any_scope_combination(client, alice, installer, agent_http, test_session, scope, event_id, claims):
    h = enroll(client, alice, agent_http, scope)
    body = send(agent_http, h, ev(event_id, claims))
    assert body["accepted"] == 0 and reasons(body) == ["event_category_mismatch"]
    assert stored(test_session) == []


def test_in_scope_events_are_accepted_with_or_without_a_label_and_stored_with_the_derived_category(client, alice, installer, agent_http, test_session):
    h = enroll(client, alice, agent_http, ("authentication",))
    body = send(agent_http, h, ev(4624, "authentication"), ev(4625), ev(4634, None), ev(4647, "authentication"))
    assert body["accepted"] == 4 and body["out_of_scope"] == 0 and body["validation_errors"] == 0
    assert stored(test_session) == [(4624, "authentication"), (4625, "authentication"), (4634, "authentication"), (4647, "authentication")]


def test_a_mixed_batch_is_split_correctly(client, alice, installer, agent_http, test_session):
    h = enroll(client, alice, agent_http, ("authentication", "device_activity"))
    body = send(agent_http, h,
                ev(4624, "authentication"),        # accepted
                ev(6416),                          # accepted (device in scope, unlabelled)
                ev(4688, "process_activity"),      # honest but out of scope
                ev(4688, "authentication"),        # forged label -> rejected
                ev(4663),                          # out of scope
                ev(4672))                          # unsupported id -> rejected
    assert (body["accepted"], body["out_of_scope"], body["validation_errors"]) == (2, 2, 2)
    assert reasons(body) == ["event_category_mismatch", "unsupported_event_id"]
    assert stored(test_session) == [(4624, "authentication"), (6416, "device_activity")]


# ---------------------------------------------------------------- unknown / unsupported ids


@pytest.mark.parametrize("bad_id", [4672, 4648, 0, -1, 999999, 5156, 4689])
def test_unknown_event_ids_are_rejected_for_scoped_and_legacy_endpoints_alike(client, alice, installer, agent_http, test_session, monkeypatch, bad_id):
    from app.security import agent_auth

    h = enroll(client, alice, agent_http, ("authentication",))
    assert reasons(send(agent_http, h, ev(bad_id), ev(bad_id, "authentication"), ev(bad_id, "uncategorized"))) == ["unsupported_event_id"] * 3

    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "legacy-key")
    legacy = agent_http.post("/api/endpoints/register", json={"display_name": "LEGACY"}, headers={"X-Agent-Api-Key": "legacy-key"}).json()
    body = send(agent_http, _headers(legacy), ev(bad_id))
    assert body["accepted"] == 0 and reasons(body) == ["unsupported_event_id"]  # no unrestricted back door
    assert stored(test_session) == []


@pytest.mark.parametrize("bad_id", [True, False, "4624", 4624.0, None, [4624], {"id": 4624}])
def test_malformed_event_ids_are_rejected_safely_without_a_server_error(client, alice, installer, agent_http, test_session, bad_id):
    h = enroll(client, alice, agent_http, ("authentication",))
    body = send(agent_http, h, ev(bad_id, "authentication"))
    assert body["accepted"] == 0 and body["validation_errors"] == 1  # 200 with a clear rejection, never a 500
    assert stored(test_session) == []


@pytest.mark.parametrize("label", [["authentication"], {"c": "authentication"}, 4624, True, "AUTHENTICATION", "authentication ", "uncategorized", "", "download_related"])
def test_malformed_or_unknown_labels_are_rejected_not_trusted_and_never_crash(client, alice, installer, agent_http, test_session, label):
    h = enroll(client, alice, agent_http, ("authentication",))
    body = send(agent_http, h, ev(4624, label))
    assert body["accepted"] == 0 and reasons(body) == ["event_category_mismatch"]
    assert stored(test_session) == []


# ---------------------------------------------------------------- the one legitimate refinement


def test_download_related_is_only_a_refinement_of_file_activity(client, alice, installer, agent_http, test_session):
    h = enroll(client, alice, agent_http, ("file_activity",))
    body = send(agent_http, h, ev(4663, "download_related"), ev(4663, "file_activity"), ev(4688, "download_related"), ev(4624, "download_related"))
    assert body["accepted"] == 2 and reasons(body) == ["event_category_mismatch"] * 2
    assert stored(test_session) == [(4663, "download_related"), (4663, "file_activity")]

    other = enroll(client, alice, agent_http, ("authentication",))
    outside = send(agent_http, other, ev(4663, "download_related"))
    assert outside["accepted"] == 0 and outside["out_of_scope"] == 1  # file activity is still file activity


# ---------------------------------------------------------------- legacy endpoint and invariants


def test_legacy_unrestricted_endpoints_still_accept_all_supported_ids_but_never_mislabelled_ones(client, agent_http, test_session, monkeypatch):
    from app.security import agent_auth

    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "legacy-key")
    legacy = agent_http.post("/api/endpoints/register", json={"display_name": "LEGACY"}, headers={"X-Agent-Api-Key": "legacy-key"}).json()
    h = _headers(legacy)
    ok = send(agent_http, h, *[ev(i, c) for i, c in ALL_IDS.items()])
    assert ok["accepted"] == len(ALL_IDS) and ok["out_of_scope"] == 0
    assert stored(test_session) == sorted(ALL_IDS.items())
    bad = send(agent_http, h, ev(4688, "authentication"))
    assert bad["accepted"] == 0 and reasons(bad) == ["event_category_mismatch"]


def test_stored_category_always_matches_the_event_id(client, alice, installer, agent_http, test_session):
    h = enroll(client, alice, agent_http, ("authentication", "file_activity", "process_activity", "device_activity"))
    send(agent_http, h, *[ev(i) for i in ALL_IDS], *[ev(i, "authentication") for i in NON_AUTH_IDS])
    for event_id, category in stored(test_session):
        assert category == ALL_IDS[event_id]


def test_classify_event_unit_behaviour():
    classify = ingestion_service.classify_event
    for event_id, category in ALL_IDS.items():
        assert classify({"event_id": event_id}) == (category, None)
        assert classify({"event_id": event_id, "event_category": category}) == (category, None)
        assert classify({"event_id": event_id, "event_category": "bogus"}) == (None, "event_category_mismatch")
    assert classify({"event_id": 4663, "event_category": "download_related"}) == ("file_activity", None)
    assert classify({"event_id": 4688, "event_category": "download_related"}) == (None, "event_category_mismatch")
    for bad in (None, True, "4624", 4672, 0, 1.5):
        assert classify({"event_id": bad}) == (None, "unsupported_event_id")


def test_the_server_map_covers_every_event_id_the_agent_collects():
    """Guards against drift: every id the collector can send must have a category on the server."""
    import collector

    collected = {i for ids in collector.CATEGORY_EVENT_IDS.values() for i in ids}
    assert collected <= set(event_parser.EVENT_CATEGORY_MAP)
    for category, ids in collector.CATEGORY_EVENT_IDS.items():
        assert all(event_parser.EVENT_CATEGORY_MAP[i] == category for i in ids)
