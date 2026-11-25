"""Tests for detect_bruteforce.py on made-up events.

Run from the detect/ folder:  python3 -m pytest tests
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import detect_bruteforce as d  # noqa: E402

KALI = "192.168.56.10"
T0 = datetime(2026, 11, 24, 18, 0, 0, tzinfo=timezone.utc)


def ev(event_id, seconds, **data):
    return d.Event(event_id, T0 + timedelta(seconds=seconds), data)


def failure(seconds, user="svc_backup", ip=KALI):
    return ev(d.FAILED_LOGON, seconds, TargetUserName=user, IpAddress=ip, LogonType="3")


def success(seconds, user="svc_backup", ip=KALI, logon_type="3"):
    return ev(d.SUCCESSFUL_LOGON, seconds, TargetUserName=user, IpAddress=ip, LogonType=logon_type)


def share_open(seconds, user="svc_backup", ip=KALI):
    return ev(d.SHARE_OPENED, seconds, SubjectUserName=user, IpAddress=ip,
              ShareName="\\\\*\\Backup")


def file_access(seconds, name, user="svc_backup", ip=KALI):
    return ev(d.SHARE_FILE_CHECKED, seconds, SubjectUserName=user, IpAddress=ip,
              ShareName="\\\\*\\Backup", RelativeTargetName=name)


def fast_attack():
    """Seven wrong passwords 2 s apart, then the right one, then the file."""
    events = [failure(2 * i) for i in range(7)]
    events += [success(14), share_open(20), file_access(20, "\\"),
               file_access(21, "network-passwords.txt")]
    return events


def test_full_chain_is_critical():
    [finding] = d.find_chains(fast_attack())
    assert finding.severity == "CRITICAL"
    assert finding.source_ip == KALI
    assert len(finding.failures) == 7
    assert finding.logon.user == "svc_backup"
    assert finding.files == ["network-passwords.txt"]


def test_burst_without_success_is_medium():
    [finding] = d.find_chains([failure(2 * i) for i in range(7)])
    assert finding.severity == "MEDIUM"
    assert finding.logon is None


def test_too_few_failures_is_ignored():
    assert d.find_chains([failure(0), failure(2), success(4)]) == []


def test_slow_attack_slips_through():
    """The weakness shown on Wednesday: 45 s between attempts breaks the burst."""
    events = [failure(45 * i) for i in range(7)] + [success(45 * 7)]
    assert d.find_chains(events) == []


def test_slow_attack_caught_with_wider_gap():
    events = [failure(45 * i) for i in range(7)] + [success(45 * 7)]
    [finding] = d.find_chains(events, max_gap=timedelta(seconds=60))
    assert finding.severity == "HIGH"


def test_anonymous_and_local_logons_do_not_count_as_success():
    events = [failure(2 * i) for i in range(7)]
    events += [success(15, user="ANONYMOUS LOGON"), success(16, logon_type="2")]
    [finding] = d.find_chains(events)
    assert finding.logon is None


def test_other_source_does_not_join_the_chain():
    events = [failure(2 * i) for i in range(7)] + [success(14, ip="192.168.56.30")]
    [finding] = d.find_chains(events)
    assert finding.logon is None


def test_share_access_by_another_user_is_not_linked():
    events = [failure(2 * i) for i in range(7)] + [success(14), share_open(20, user="labuser")]
    [finding] = d.find_chains(events)
    assert finding.severity == "HIGH"


def test_lockout_is_reported():
    events = [failure(2 * i) for i in range(10)]
    events.append(ev(d.ACCOUNT_LOCKED, 19, TargetUserName="svc_backup"))
    [finding] = d.find_chains(events)
    assert [e.user for e in finding.lockouts] == ["svc_backup"]


def test_ipv4_mapped_address_is_normalised():
    assert failure(0, ip="::ffff:192.168.56.10").source_ip == KALI


WINDOWS_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-11-24T18:03:12.4567890Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc_backup</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.168.56.10</Data>
  </EventData>
</Event>"""


def test_parse_windows_xml():
    event = d.parse_event_xml(WINDOWS_XML)
    assert event.event_id == 4625
    assert event.time == datetime(2026, 11, 24, 18, 3, 12, 456789, tzinfo=timezone.utc)
    assert event.user == "svc_backup"
    assert event.source_ip == KALI


def test_parse_python_evtx_time_format():
    assert d.parse_time("2026-11-24 18:03:12.456789+00:00") == \
        datetime(2026, 11, 24, 18, 3, 12, 456789, tzinfo=timezone.utc)
    assert d.parse_time("2026-11-24 18:03:12+00:00") == \
        datetime(2026, 11, 24, 18, 3, 12, tzinfo=timezone.utc)
    assert d.parse_time("2026-11-24 18:03:12") == \
        datetime(2026, 11, 24, 18, 3, 12, tzinfo=timezone.utc)


def test_unwanted_event_is_skipped():
    assert d.parse_event_xml(WINDOWS_XML.replace("4625", "4688")) is None
