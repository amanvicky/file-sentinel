#!/usr/bin/env python3
"""file-sentinel — real-time file-integrity watching with a ransomware canary.

Point it at a folder you care about and it:
  init   — records a SHA-256 baseline of every file
  watch  — diffs the folder against the baseline every few seconds, printing
           created / modified / deleted files the moment they happen
  check  — one-shot diff against the baseline, for cron

The canary: if too many files change inside one window, that's the classic
mass-encryption pattern — a loud alert fires (console + JSONL, optional
webhook). A folder of documents becomes a tripwire.

DEFENSIVE TOOL, RUN AT YOUR OWN RESPONSIBILITY: watch only folders on
systems you own or are authorized to monitor. See the README's ethics
section before deploying.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASELINE_NAME = ".sentinel-baseline.json"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root):
    """Every regular file under root: {relpath: {"sha256", "size", "mtime"}}."""
    out = {}
    root = Path(root)
    for p in root.rglob("*"):
        if p.is_file() and p.name != BASELINE_NAME:
            st = p.stat()
            out[p.relative_to(root).as_posix()] = {
                "sha256": sha256(p), "size": st.st_size, "mtime": st.st_mtime}
    return out


def diff(before, after):
    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(p for p in set(before) & set(after)
                      if before[p]["sha256"] != after[p]["sha256"])
    return {"created": created, "modified": modified, "deleted": deleted}


def canary(events, now, window=60.0, threshold=40):
    """True when `threshold`+ changes landed inside the last `window` seconds
    of the event list — the shape mass file-encryption leaves behind."""
    recent = [t for t in events if now - t <= window]
    return len(recent) >= threshold, len(recent)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Sentinel:
    def __init__(self, root, every=3.0, threshold=40, window=60.0,
                 log=None, webhook=None, feed=True):
        self.root = Path(root)
        self.every = every
        self.threshold = threshold
        self.window = window
        self.log = log
        self.webhook = webhook
        self.feed = feed
        self.change_times = []
        self.baseline = {}
        self.last = {}

    def _log(self, rec):
        if self.log:
            with open(self.log, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _post(self, payload):
        if not self.webhook:
            return
        req = urllib.request.Request(
            self.webhook, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "file-sentinel"})
        urllib.request.urlopen(req, timeout=10)

    def say(self, line):
        if self.feed:
            print(line, flush=True)

    def load_baseline(self):
        path = self.root / BASELINE_NAME
        self.baseline = json.loads(path.read_text(encoding="utf-8"))
        self.last = dict(self.baseline)

    def once(self):
        current = snapshot(self.root)
        d = diff(self.last, current)
        self.last = current
        changed = len(d["created"]) + len(d["modified"]) + len(d["deleted"])
        rec = {"ts": now_iso(), "kind": "changes", **d, "total": changed}
        self._log(rec)
        if changed:
            stamp = rec["ts"][11:19]
            self.say(f"\x1b[90m{stamp}\x1b[0m \x1b[33mCHANGES\x1b[0m "
                     f"+{len(d['created'])} ~{len(d['modified'])} -{len(d['deleted'])}")
            for rel in d["created"]:
                self.say(f"           \x1b[32m+ {rel}\x1b[0m")
            for rel in d["modified"]:
                self.say(f"           \x1b[33m~ {rel}\x1b[0m")
            for rel in d["deleted"]:
                self.say(f"           \x1b[31m- {rel}\x1b[0m")
        self.change_times.extend([time.time()] * changed)
        fired, recent = canary(self.change_times, time.time(), self.window, self.threshold)
        if fired:
            alert = {"ts": now_iso(), "kind": "canary",
                     "changes_in_window": recent,
                     "window_seconds": self.window, "threshold": self.threshold}
            self._log(alert)
            self._post(alert)
            self.change_times = []   # one canary per burst
            self.say(f"\x1b[41m!! CANARY: {recent} files changed in {self.window:.0f}s — "
                     f"POSSIBLE MASS-ENCRYPTION (ransomware pattern) !!\x1b[0m")
        return d

    def run(self):
        self.load_baseline()
        self.say(f"watching {self.root} every {self.every:g}s "
                 f"({len(self.baseline)} files baselined) — Ctrl+C to stop")
        try:
            while True:
                self.once()
                time.sleep(self.every)
        except KeyboardInterrupt:
            self.say("stopped")


def cmd_init(args):
    snap = snapshot(args.root)
    Path(args.root, BASELINE_NAME).write_text(
        json.dumps(snap, indent=1), encoding="utf-8")
    print(f"baseline written: {len(snap)} files under {args.root}")
    return 0


def cmd_check(args):
    s = Sentinel(args.root, log=args.log, feed=True)
    s.load_baseline()
    s.once()
    return 0


def cmd_watch(args):
    Sentinel(args.root, every=args.every, threshold=args.threshold, window=args.window,
             log=args.log, webhook=args.webhook).run()
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="real-time file-integrity watching")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="record a SHA-256 baseline")
    i.add_argument("root")
    i.set_defaults(func=cmd_init)

    w = sub.add_parser("watch", help="diff live, alert on bursts")
    w.add_argument("root")
    w.add_argument("--every", type=float, default=3.0, help="seconds between passes (default 3)")
    w.add_argument("--threshold", type=int, default=40, help="canary: changes per window (default 40)")
    w.add_argument("--window", type=float, default=60.0, help="canary window seconds (default 60)")
    w.add_argument("--log", default="sentinel.jsonl", help="JSONL alerts file")
    w.add_argument("--webhook", help="POST canary alerts to this URL")
    w.set_defaults(func=cmd_watch)

    c = sub.add_parser("check", help="one-shot diff against the baseline")
    c.add_argument("root")
    c.add_argument("--log", default="sentinel.jsonl")
    c.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
