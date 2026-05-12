from pathlib import Path

import yaml


def test_docker_compose_has_dashboard_and_auditor_services():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    assert {"dashboard", "auditor"}.issubset(services)
    assert "streamlit run app/streamlit_dashboard.py" in services["dashboard"]["command"]
    assert services["auditor"]["command"] == "cloud-audit scan --source snapshots"
