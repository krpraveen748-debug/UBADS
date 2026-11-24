from user_identity import resolve_user_id


def test_prefers_user_sid():
    event = {"user_sid": "S-1-5-21-1", "username": "alice", "domain": "CORP"}
    assert resolve_user_id(event) == "S-1-5-21-1"


def test_falls_back_to_domain_and_username():
    event = {"user_sid": None, "username": "alice", "domain": "CORP"}
    assert resolve_user_id(event) == "CORP\\alice"


def test_falls_back_to_username_only():
    event = {"user_sid": None, "username": "alice", "domain": None}
    assert resolve_user_id(event) == "alice"


def test_falls_back_to_unknown():
    event = {"user_sid": None, "username": None, "domain": None}
    assert resolve_user_id(event) == "unknown"
