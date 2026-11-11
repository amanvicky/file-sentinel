"""Tests for sentinel.py — snapshots, diffs, the canary, JSONL, webhook."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import sentinel as sd


@pytest.fixture
def root(tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    (d / "a.txt").write_text("alpha", encoding="utf-8")
    (d / "b.txt").write_text("beta", encoding="utf-8")
    return d


def test_diff_categories(root):
    snap = sd.snapshot(root)
    (root / "c.txt").write_text("gamma", encoding="utf-8")
    (root / "a.txt").write_text("ALPHA", encoding="utf-8")
    (root / "b.txt").unlink()
    d = sd.diff(snap, sd.snapshot(root))
    assert d["created"] == ["c.txt"]
    assert d["modified"] == ["a.txt"]
    assert d["deleted"] == ["b.txt"]


def test_diff_ignores_untouched_files(root):
    snap = sd.snapshot(root)
    d = sd.diff(snap, sd.snapshot(root))
    assert d == {"created": [], "modified": [], "deleted": []}


def test_snapshot_hashes_contents_not_mtime(root):
    s1 = sd.snapshot(root)
    import os
    os.utime(root / "a.txt", (0, 0))          # mtime changes, bytes don't
    s2 = sd.snapshot(root)
    assert s1["a.txt"]["sha256"] == s2["a.txt"]["sha256"]


def test_canary_fires_on_burst():
    now = 1000.0
    events = [now - 5 - i * 0.1 for i in range(50)]   # 50 changes in the last 5s
    fired, recent = sd.canary(events, now, window=60, threshold=40)
    assert fired and recent == 50


def test_canary_stays_calm_on_trickle():
    now = 1000.0
    events = [now - 10 - i * 2 for i in range(50)]    # 1 change per 2s, spread out
    fired, recent = sd.canary(events, now, window=60, threshold=40)
    assert recent <= 30 and not fired


def test_baseline_excludes_sentinel_file(root):
    snap = sd.snapshot(root)
    assert sd.BASELINE_NAME not in snap


def test_once_logs_and_reports(root, capsys):
    (root / sd.BASELINE_NAME).write_text(json.dumps(sd.snapshot(root)), encoding="utf-8")
    s = sd.Sentinel(root, log=str(root.parent / "alerts.jsonl"), feed=True)
    s.load_baseline()
    (root / "c.txt").write_text("gamma", encoding="utf-8")
    (root / "a.txt").write_text("ALPHA!", encoding="utf-8")
    d = s.once()
    assert d["created"] == ["c.txt"] and d["modified"] == ["a.txt"]
    out = capsys.readouterr().out
    assert "CHANGES" in out and "+ c.txt" in out
    rec = json.loads((root.parent / "alerts.jsonl").read_text().splitlines()[0])
    assert rec["kind"] == "changes" and rec["total"] == 2


def test_webhook_posts_alert(root):
    received = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    s = sd.Sentinel(root, webhook=f"http://127.0.0.1:{srv.server_address[1]}/hook", feed=False)
    payload = {"ts": "2026-11-12T00:00:00+00:00", "kind": "canary",
               "changes_in_window": 42, "window_seconds": 60, "threshold": 40}
    s._post(payload)
    srv.shutdown()
    assert received and received[0]["kind"] == "canary" and received[0]["changes_in_window"] == 42


def test_main_init_and_check(tmp_path, capsys):
    d = tmp_path / "docs"
    d.mkdir()
    (d / "x.txt").write_text("hello", encoding="utf-8")
    assert sd.main(["init", str(d)]) == 0
    assert (d / sd.BASELINE_NAME).exists()
    (d / "y.txt").write_text("new", encoding="utf-8")
    assert sd.main(["check", str(d)]) == 0
    out = capsys.readouterr().out
    assert "+ y.txt" in out
