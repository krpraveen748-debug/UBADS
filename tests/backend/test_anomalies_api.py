"""An empty anomaly response is valid only when there are no recorded detections."""


def test_anomalies_returns_real_empty_result_and_summary(client):
    response = client.get("/api/anomalies")
    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "total": 0,
        "severity_counts": {},
        "limit": 100,
        "offset": 0,
    }
