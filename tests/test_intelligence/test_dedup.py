import pytest

from driln.intelligence.dedup import FindingDeduplicator

@pytest.fixture
def deduplicator():
    return FindingDeduplicator(similarity_threshold=0.70)

def test_are_duplicates(deduplicator):
    a = {"host": "1.1.1.1", "port": 80, "tool_name": "nmap", "title": "Open Port 80 HTTP"}
    b = {"host": "1.1.1.1", "port": 80, "tool_name": "nuclei", "title": "Open Port 80 HTTP Server"}
    assert deduplicator._are_duplicates(a, b) == True

def test_are_duplicates_different_hosts(deduplicator):
    a = {"host": "1.1.1.1", "port": 80, "tool_name": "nmap", "title": "Open Port 80"}
    b = {"host": "2.2.2.2", "port": 80, "tool_name": "nuclei", "title": "Open Port 80"}
    assert deduplicator._are_duplicates(a, b) == False

def test_are_duplicates_different_ports(deduplicator):
    a = {"host": "1.1.1.1", "port": 80, "tool_name": "nmap", "title": "Open Port 80"}
    b = {"host": "1.1.1.1", "port": 443, "tool_name": "nuclei", "title": "Open Port 443"}
    assert deduplicator._are_duplicates(a, b) == False

def test_are_duplicates_same_tool(deduplicator):
    # Same tool means they aren't merged (usually different specific findings)
    a = {"host": "1.1.1.1", "port": 80, "tool_name": "nmap", "title": "Open Port"}
    b = {"host": "1.1.1.1", "port": 80, "tool_name": "nmap", "title": "Open Port"}
    assert deduplicator._are_duplicates(a, b) == False

def test_pick_primary(deduplicator):
    findings = [
        {"severity": "low", "description": "short"},
        {"severity": "high", "description": "very long description"}
    ]
    # high severity wins
    primary, victim = deduplicator._pick_primary(0, 1, findings)
    assert primary == 1
    assert victim == 0

def test_pick_primary_same_severity_longer_desc(deduplicator):
    findings = [
        {"severity": "low", "description": "short"},
        {"severity": "low", "description": "very long description here"}
    ]
    primary, victim = deduplicator._pick_primary(0, 1, findings)
    assert primary == 1
    assert victim == 0

def test_merge(deduplicator):
    primary = {"tool_name": "nmap", "description": "A open port"}
    victim = {"tool_name": "nuclei", "description": "More detailed open port description"}
    
    deduplicator._merge(primary, victim)
    
    assert "nmap" in primary["source_tools"]
    assert "nuclei" in primary["source_tools"]
    assert primary["deduplicated"] == True
    # Merges description because victim had it, wait, primary already had description so it does NOT override
    assert primary["description"] == "A open port"

def test_merge_missing_desc(deduplicator):
    primary = {"tool_name": "nmap"}
    victim = {"tool_name": "nuclei", "description": "Victim desc"}
    
    deduplicator._merge(primary, victim)
    assert primary["description"] == "Victim desc"

def test_deduplicate_list(deduplicator):
    findings = [
        {"host": "1.1.1.1", "port": 80, "tool_name": "nmap", "severity": "info", "title": "Open port 80"},
        {"host": "1.1.1.1", "port": 80, "tool_name": "nuclei", "severity": "low", "title": "Open port 80 with info"},
        {"host": "1.1.1.1", "port": 443, "tool_name": "nmap", "severity": "info", "title": "Open port 443"}
    ]
    
    deduped, merges = deduplicator.deduplicate(findings)
    assert merges == 1
    assert len(deduped) == 2
    # The low severity one should be kept for port 80
    port_80 = [f for f in deduped if f["port"] == 80][0]
    assert port_80["severity"] == "low"
    assert port_80["tool_name"] == "nuclei"
    assert "nmap" in port_80["source_tools"]
    assert port_80["deduplicated"] == True
