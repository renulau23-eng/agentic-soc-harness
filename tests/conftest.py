import os
import tempfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from ash.api import create_app
from ash.config import Settings
from ash.core.types import AlertIn, Principal, Severity
from ash.observability import metrics
from ash.runtime import Harness


@pytest.fixture()
def settings(tmp_path) -> Settings:
    db = tmp_path / "test.db"
    return Settings(
        database_url=f"sqlite:///{db}",
        log_json=False,
        log_level="WARNING",
        api_keys="siem-key:siem:service,admin-key:root:admin",
        bootstrap_admin_password="admin-pass",
        environment="development",
        jwt_secret="test-secret-that-is-at-least-32-bytes-long",
    )


@pytest.fixture()
def harness(settings) -> Iterator[Harness]:
    metrics.reset()
    hz = Harness.build(settings)
    hz.auth.add_user("asha", "asha-pass", ["analyst"])
    hz.auth.add_user("rahul", "rahul-pass", ["soc_lead"])
    hz.auth.add_user("meera", "meera-pass", ["auditor"])
    hz.auth.add_user("vik", "vik-pass", ["viewer"])
    hz.auth.add_user("sam", "sam-pass", ["senior_analyst"])
    yield hz
    hz.db.engine.dispose()


@pytest.fixture()
def analyst() -> Principal:
    return Principal(id="user:asha", name="asha", roles=["analyst"])


@pytest.fixture()
def lead() -> Principal:
    return Principal(id="user:rahul", name="rahul", roles=["soc_lead"])


@pytest.fixture()
def auditor() -> Principal:
    return Principal(id="user:meera", name="meera", roles=["auditor"])


@pytest.fixture()
def viewer() -> Principal:
    return Principal(id="user:vik", name="vik", roles=["viewer"])


@pytest.fixture()
def c2_alert() -> AlertIn:
    return AlertIn(
        source="siem",
        title="Beaconing to known C2 from FIN-WS-042",
        severity=Severity.HIGH,
        indicators=["185.220.101.45", "evil-updates.xyz"],
        asset_id="host-fin-042",
    )


@pytest.fixture()
def benign_alert() -> AlertIn:
    return AlertIn(
        source="edr",
        title="Unusual login time",
        severity=Severity.LOW,
        indicators=["10.0.0.5"],
        asset_id="host-dev-007",
    )


@pytest.fixture()
def client(harness, settings) -> Iterator[TestClient]:
    app = create_app(harness, settings)
    with TestClient(app) as c:
        yield c


def token_for(client: TestClient, username: str, password: str) -> dict[str, str]:
    r = client.post("/api/v1/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def tmp_db_url() -> str:
    d = tempfile.mkdtemp()
    return "sqlite:///" + os.path.join(d, "x.db")
