import pytest

from driln.intelligence.correlator import FindingCorrelator
from driln.schemas.intelligence import TechProfile, TechFingerprint

@pytest.fixture
def correlator():
    return FindingCorrelator()

def test_by_host_port(correlator):
    findings = [
        {"id": "1", "host": "1.1.1.1", "port": 80, "tool_name": "nmap"},
        {"id": "2", "host": "1.1.1.1", "port": 80, "tool_name": "nuclei"},
        {"id": "3", "host": "1.1.1.1", "port": 443, "tool_name": "nmap"}
    ]
    groups = correlator._by_host_port(findings)
    assert len(groups) == 1
    assert groups[0].relationship == "same_service"
    assert "1" in groups[0].finding_ids
    assert "2" in groups[0].finding_ids
    assert "3" not in groups[0].finding_ids

def test_by_attack_chain(correlator):
    findings = [
        {"id": "1", "host": "2.2.2.2", "port": 80, "severity": "info", "title": "Service Info"},
        {"id": "2", "host": "2.2.2.2", "port": 80, "severity": "high", "title": "CVE-2024"},
        {"id": "3", "host": "2.2.2.2", "port": 443, "severity": "low", "title": "Service Info"}
    ]
    groups = correlator._by_attack_chain(findings)
    assert len(groups) == 1
    assert groups[0].relationship == "attack_chain"
    assert "1" in groups[0].finding_ids
    assert "2" in groups[0].finding_ids

def test_by_technology(correlator):
    findings = [
        {"id": "1", "host": "3.3.3.3", "title": "WordPress login found"},
        {"id": "2", "host": "3.3.3.3", "description": "Running wordpress 5.0"},
        {"id": "3", "host": "3.3.3.3", "title": "Random info"}
    ]
    tech = TechProfile(technologies=[
        TechFingerprint(name="WordPress", category="cms", confidence=1.0)
    ])
    
    groups = correlator._by_technology(findings, tech)
    assert len(groups) == 1
    assert groups[0].relationship == "tech_overlap"
    assert "1" in groups[0].finding_ids
    assert "2" in groups[0].finding_ids
    assert "3" not in groups[0].finding_ids

def test_correlate_all(correlator):
    findings = [
        {"id": "1", "host": "1.1.1.1", "port": 80, "tool_name": "nmap", "severity": "info", "title": "WordPress"},
        {"id": "2", "host": "1.1.1.1", "port": 80, "tool_name": "nuclei", "severity": "high", "title": "WordPress SQLi"}
    ]
    tech = TechProfile(technologies=[
        TechFingerprint(name="WordPress", category="cms", confidence=1.0)
    ])
    
    groups = correlator.correlate(findings, tech)
    # Expect 3 groups: same_service, attack_chain, and tech_overlap
    assert len(groups) == 3
