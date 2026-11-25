#!/usr/bin/env python3
"""Find SMB brute-force chains in an exported Windows Security log.

The Detection looks for this pattern coming from one source IP:

  1. a burst of failed network logons (event 4625), where each failure comes
     within --max-gap seconds of the previous one, and there are at least
     --min-failures of them
  2. a successful network logon (4624, logon type 3) from the same IP within
     --success-window seconds of the burst
  3. the same account opening a file share (5140) or a file on it (5145)
     within --access-window seconds of that logon

Lockouts (4740) for the targeted accounts are reported alongside.

Usage:
  python3 detect_bruteforce.py ../evidence/Security.evtx
  python3 detect_bruteforce.py ../evidence/Security.evtx --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

FAILED_LOGON = 4625
SUCCESSFUL_LOGON = 4624
ACCOUNT_LOCKED = 4740
SHARE_OPENED = 5140
SHARE_FILE_CHECKED = 5145
WANTED_IDS = {FAILED_LOGON, SUCCESSFUL_LOGON, ACCOUNT_LOCKED, SHARE_OPENED, SHARE_FILE_CHECKED}

NETWORK_LOGON = "3"
NO_USER = {"", "-", "ANONYMOUS LOGON"}
LOCAL_SOURCES = {"", "-", "127.0.0.1", "::1"}


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Event:
    event_id: int
    time: datetime
    data: dict[str, str]

    @property
    def source_ip(self) -> str:
        ip = self.data.get("IpAddress", "").strip()
        if ip.startswith("::ffff:"):  # IPv4 written as IPv6
            ip = ip[len("::ffff:"):]
        return ip

    @property
    def user(self) -> str:
        """The account the event is about."""
        if self.event_id in (SHARE_OPENED, SHARE_FILE_CHECKED):
            return self.data.get("SubjectUserName", "")
        return self.data.get("TargetUserName", "")


def _local_name(tag: str) -> str:
    """'{namespace}EventID' -> 'EventID'."""
    return tag.rsplit("}", 1)[-1]


def parse_time(value: str) -> datetime:
    """Parse event timestamps in either format we can meet.

    Windows writes   2026-11-24T18:03:12.4567890Z  (seven decimals)
    python-evtx gives 2026-11-24 18:03:12.456789+00:00
    Both are UTC.
    """
    value = value.strip().replace("T", " ")
    value = re.sub(r"(Z|[+-]\d{2}:\d{2})$", "", value)
    whole, _, fraction = value.partition(".")
    parsed = datetime.strptime(whole, "%Y-%m-%d %H:%M:%S")
    micros = int((fraction + "000000")[:6]) if fraction else 0
    return parsed.replace(microsecond=micros, tzinfo=timezone.utc)


def parse_event_xml(xml_text: str) -> Event | None:
    """Turn one event's XML into an Event, or None if we don't need it."""
    root = ET.fromstring(xml_text)
    event_id = None
    time = None
    data: dict[str, str] = {}

    for element in root.iter():
        name = _local_name(element.tag)
        if name == "EventID" and element.text:
            event_id = int(element.text.strip())
        elif name == "TimeCreated":
            time = parse_time(element.get("SystemTime", ""))
        elif name == "Data" and element.get("Name"):
            data[element.get("Name")] = (element.text or "").strip()

    if event_id not in WANTED_IDS or time is None:
        return None
    return Event(event_id, time, data)


def read_evtx(path: str) -> tuple[list[Event], int, int]:
    """Read an .evtx file. Returns (events we need, records read, records skipped)."""
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        sys.exit("python-evtx is missing. Install it with: pip install -r requirements.txt")

    events: list[Event] = []
    read = skipped = 0
    with evtx.Evtx(path) as log:
        for record in log.records():
            read += 1
            try:
                event = parse_event_xml(record.xml())
            except Exception:  # python-evtx can fail on damaged records
                skipped += 1
                continue
            if event:
                events.append(event)
    return events, read, skipped


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    source_ip: str
    failures: list[Event]
    logon: Event | None = None
    share_events: list[Event] = field(default_factory=list)
    lockouts: list[Event] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.logon and self.share_events:
            return "CRITICAL"
        if self.logon:
            return "HIGH"
        return "MEDIUM"

    @property
    def summary(self) -> str:
        if self.logon and self.share_events:
            return "brute force -> logon -> share access"
        if self.logon:
            return "brute force -> successful logon"
        return "brute force attempt, no successful logon"

    @property
    def users_tried(self) -> list[str]:
        return sorted({e.user for e in self.failures if e.user not in NO_USER})

    @property
    def shares(self) -> list[str]:
        return sorted({e.data.get("ShareName", "") for e in self.share_events} - {""})

    @property
    def files(self) -> list[str]:
        names = {e.data.get("RelativeTargetName", "") for e in self.share_events
                 if e.event_id == SHARE_FILE_CHECKED}
        return sorted(names - {"", "\\"})


def split_into_bursts(failures: list[Event], max_gap: timedelta) -> list[list[Event]]:
    """Group failures that follow each other within max_gap."""
    bursts: list[list[Event]] = []
    for event in failures:
        if bursts and event.time - bursts[-1][-1].time <= max_gap:
            bursts[-1].append(event)
        else:
            bursts.append([event])
    return bursts


def is_real_network_logon(event: Event) -> bool:
    return (event.event_id == SUCCESSFUL_LOGON
            and event.data.get("LogonType") == NETWORK_LOGON
            and event.user not in NO_USER
            and not event.user.endswith("$"))  # computer accounts


def find_chains(
    events: Iterable[Event],
    min_failures: int = 5,
    max_gap: timedelta = timedelta(seconds=30),
    success_window: timedelta = timedelta(minutes=5),
    access_window: timedelta = timedelta(minutes=30),
) -> list[Finding]:
    events = sorted(events, key=lambda e: e.time)
    lockouts = [e for e in events if e.event_id == ACCOUNT_LOCKED]

    by_source: dict[str, list[Event]] = {}
    for event in events:
        if event.source_ip not in LOCAL_SOURCES:
            by_source.setdefault(event.source_ip, []).append(event)

    findings: list[Finding] = []
    for source_ip, source_events in by_source.items():
        failures = [e for e in source_events if e.event_id == FAILED_LOGON]

        for burst in split_into_bursts(failures, max_gap):
            if len(burst) < min_failures:
                continue
            finding = Finding(source_ip, burst)
            start, end = burst[0].time, burst[-1].time

            finding.logon = next(
                (e for e in source_events
                 if is_real_network_logon(e) and start <= e.time <= end + success_window),
                None,
            )

            if finding.logon:
                logon = finding.logon
                finding.share_events = [
                    e for e in source_events
                    if e.event_id in (SHARE_OPENED, SHARE_FILE_CHECKED)
                    and e.user.lower() == logon.user.lower()
                    and logon.time <= e.time <= logon.time + access_window
                ]

            targeted = {u.lower() for u in finding.users_tried}
            finding.lockouts = [
                e for e in lockouts
                if e.user.lower() in targeted and start <= e.time <= end + success_window
            ]
            findings.append(finding)

    return sorted(findings, key=lambda f: f.failures[0].time)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _clock(t: datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S") + "Z"


def timeline(finding: Finding) -> list[tuple[datetime, str]]:
    first, last = finding.failures[0], finding.failures[-1]
    users = ", ".join(finding.users_tried) or "(no user name)"
    lines = [
        (first.time, "first failed network logon (4625)"),
        (last.time, f"{len(finding.failures)} failed logons in a row, accounts tried: {users}"),
    ]
    for e in finding.lockouts:
        lines.append((e.time, f"account locked out: {e.user} (4740)"))
    if finding.logon:
        lines.append((finding.logon.time,
                      f"successful network logon as {finding.logon.user} (4624, type 3)"))
    seen: set[tuple[int, str]] = set()
    for e in finding.share_events:
        if e.event_id == SHARE_OPENED:
            share = e.data.get("ShareName", "?")
            key = (SHARE_OPENED, share)
            text = f"share opened: {share} (5140)"
        else:
            target = e.data.get("RelativeTargetName", "")
            if target in ("", "\\"):
                continue
            key = (SHARE_FILE_CHECKED, target)
            text = f"file accessed: {target} (5145)"
        if key not in seen:
            seen.add(key)
            lines.append((e.time, text))
    return sorted(lines, key=lambda line: line[0])


def print_report(findings: list[Finding], source: str, read: int, skipped: int) -> None:
    print(f"Scenario 01 Detection: {len(findings)} finding(s) in {source}")
    print(f"({read} records read, {skipped} skipped, times in UTC)\n")
    for finding in findings:
        print(f"[{finding.severity}] {finding.source_ip}  {finding.summary}")
        for when, text in timeline(finding):
            print(f"  {_clock(when)}  {text}")
        print()


def as_json(findings: list[Finding]) -> str:
    return json.dumps([
        {
            "severity": f.severity,
            "summary": f.summary,
            "source_ip": f.source_ip,
            "failed_logons": len(f.failures),
            "first_failure": f.failures[0].time.isoformat(),
            "last_failure": f.failures[-1].time.isoformat(),
            "users_tried": f.users_tried,
            "compromised_user": f.logon.user if f.logon else None,
            "logon_time": f.logon.time.isoformat() if f.logon else None,
            "shares": f.shares,
            "files": f.files,
            "lockouts": [e.user for e in f.lockouts],
        }
        for f in findings
    ], indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Find SMB brute-force chains in a Security.evtx file.")
    parser.add_argument("evtx", help="exported Security log (.evtx)")
    parser.add_argument("--min-failures", type=int, default=5,
                        help="failed logons needed to count as a burst (default 5)")
    parser.add_argument("--max-gap", type=int, default=30,
                        help="max seconds between failures in the same burst (default 30)")
    parser.add_argument("--success-window", type=int, default=300,
                        help="seconds after the burst to look for a successful logon (default 300)")
    parser.add_argument("--access-window", type=int, default=1800,
                        help="seconds after the logon to look for share access (default 1800)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args(argv)

    events, read, skipped = read_evtx(args.evtx)
    findings = find_chains(
        events,
        min_failures=args.min_failures,
        max_gap=timedelta(seconds=args.max_gap),
        success_window=timedelta(seconds=args.success_window),
        access_window=timedelta(seconds=args.access_window),
    )

    if args.json:
        print(as_json(findings))
    else:
        print_report(findings, args.evtx, read, skipped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
