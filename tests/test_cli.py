import os
import subprocess
import sys

from cloud_audit.cli import main


def test_cli_smoke(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cloud-audit", "generate-snapshots"])
    main()
    assert "Generated snapshots" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["cloud-audit", "scan", "--source", "snapshots"])
    main()
    assert "Findings" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["cloud-audit", "export-report"])
    main()
    assert "Regenerated" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["cloud-audit", "validate-rules"])
    main()
    assert "Validated rules" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["cloud-audit", "health-check"])
    main()
    assert "Health checks passed" in capsys.readouterr().out


def test_module_cli_subprocess_needs_no_cloud_credentials():
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    env.pop("AWS_ACCESS_KEY_ID", None)
    env.pop("AWS_SECRET_ACCESS_KEY", None)
    result = subprocess.run(
        [sys.executable, "-m", "cloud_audit.cli", "validate-rules"],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )
    assert "Validated rules" in result.stdout
