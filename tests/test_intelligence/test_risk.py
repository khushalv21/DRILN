import pytest

from driln.intelligence.context import ScanContext, HostContext, ServiceContext
from driln.intelligence.risk import RiskScorer

@pytest.fixture
def empty_context():
    return ScanContext(scan_id="test", target="example.com", scan_type="full")

@pytest.fixture
def risk_scorer():
    return RiskScorer()

def test_base_severity(risk_scorer, empty_context):
    f_crit = {"severity": "critical"}
    f_high = {"severity": "high"}
    f_med = {"severity": "medium"}
    f_low = {"severity": "low"}
    f_info = {"severity": "info"}

    assert risk_scorer._base_severity(f_crit) == 1.0
    assert risk_scorer._base_severity(f_high) == 0.8
    assert risk_scorer._base_severity(f_med) == 0.5
    assert risk_scorer._base_severity(f_low) == 0.2
    assert risk_scorer._base_severity(f_info) == 0.05

def test_exploitability(risk_scorer):
    # High exploitability keywords
    f_high = {"title": "SQL Injection found"}
    assert risk_scorer._exploitability(f_high) == 0.9

    f_high2 = {"description": "remote code execution in web server"}
    assert risk_scorer._exploitability(f_high2) == 0.9

    # Medium exploitability
    f_med = {"title": "XSS vulnerability"}
    assert risk_scorer._exploitability(f_med) == 0.5

    f_med2 = {"description": "exposed internal path"}
    assert risk_scorer._exploitability(f_med2) == 0.5

    # Low exploitability (fallback)
    f_low = {"title": "Unknown service open"}
    assert risk_scorer._exploitability(f_low) == 0.2

def test_exposure(risk_scorer, empty_context):
    # Exposed service
    f_exposed_svc = {"service": "http"}
    assert risk_scorer._exposure(f_exposed_svc, empty_context) == 0.8

    # Well-known internet port
    f_exposed_port = {"port": 443}
    assert risk_scorer._exposure(f_exposed_port, empty_context) == 0.7

    # Large attack surface host
    host_ctx = HostContext(address="10.0.0.1", ports=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
    ctx = empty_context
    ctx.hosts["10.0.0.1"] = host_ctx
    f_host = {"host": "10.0.0.1", "port": 9999, "service": "unknown"}
    assert risk_scorer._exposure(f_host, ctx) == 0.6

    # Low exposure fallback
    f_low = {"host": "10.0.0.2", "port": 9999, "service": "unknown"}
    assert risk_scorer._exposure(f_low, empty_context) == 0.3

def test_context_boost(risk_scorer, empty_context):
    # Setup context with findings on same service
    ctx = empty_context
    ctx.findings = [
        {"host": "1.2.3.4", "port": 80},
        {"host": "1.2.3.4", "port": 80},
        {"host": "1.2.3.4", "port": 80},
    ]
    f = {"host": "1.2.3.4", "port": 80}
    assert risk_scorer._context_boost(f, ctx) == 0.4  # >= 3 findings = 0.4 boost

    ctx.findings = [{"host": "1.2.3.4", "port": 80}]
    assert risk_scorer._context_boost(f, ctx) == 0.2  # >= 1 finding = 0.2 boost

def test_score_finding(risk_scorer, empty_context):
    # A critical finding with RCE on HTTP port 80
    f = {
        "severity": "critical",
        "title": "RCE found",
        "service": "http",
        "port": 80
    }
    score = risk_scorer.score_finding(f, empty_context)
    # base=1.0 (*40 = 40), exploit=0.9 (*25 = 22.5), exposure=0.8 (*20 = 16), boost=0.0 (*15 = 0) => 78.5
    # Wait, base severity = 1.0
    # exploitability = 0.9
    # exposure = 0.8
    # 40 + 22.5 + 16 = 78.5
    assert score.score == 78.5
    assert score.label == "high"

def test_score_scan_empty(risk_scorer, empty_context):
    score = risk_scorer.score_scan([], empty_context)
    assert score.score == 0.0
    assert score.label == "clean"

def test_score_scan(risk_scorer, empty_context):
    f1 = {"severity": "critical", "title": "RCE", "service": "http", "port": 80}  # ~78.5
    f2 = {"severity": "info", "title": "Version disclosure", "service": "unknown"} # low score
    
    score = risk_scorer.score_scan([f1, f2], empty_context)
    assert score.score > 0.0
    assert score.base_severity > 0.0
