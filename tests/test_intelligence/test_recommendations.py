import pytest

from driln.intelligence.context import ScanContext, ServiceContext, HostContext
from driln.intelligence.recommendations import RecommendationEngine, _has_tech, _has_service, _has_finding_keyword, _has_open_port
from driln.schemas.intelligence import TechProfile, TechFingerprint

@pytest.fixture
def engine():
    return RecommendationEngine()

@pytest.fixture
def empty_context():
    return ScanContext(scan_id="test", target="example.com", scan_type="full")

@pytest.fixture
def empty_tech():
    return TechProfile()

def test_has_tech():
    tp = TechProfile(technologies=[TechFingerprint(name="WordPress", category="cms", confidence=1.0)])
    assert _has_tech(tp, "wordpress") == True
    assert _has_tech(tp, "joomla") == False

def test_has_service(empty_context):
    ctx = empty_context
    ctx.services[("1.1.1.1", 80)] = ServiceContext(host="1.1.1.1", port=80, service="http")
    ctx.services[("1.1.1.1", 445)] = ServiceContext(host="1.1.1.1", port=445, service="smb")
    
    assert _has_service(ctx, "smb", "microsoft-ds") == True
    assert _has_service(ctx, "ftp") == False

def test_has_finding_keyword(empty_context):
    ctx = empty_context
    ctx.findings = [{"title": "Admin panel login detected"}, {"title": "Random finding"}]
    assert _has_finding_keyword(ctx, "admin", "login") == True
    assert _has_finding_keyword(ctx, "sql") == False

def test_has_open_port(empty_context):
    ctx = empty_context
    ctx.hosts["1.1.1.1"] = HostContext(address="1.1.1.1", ports=[3306, 80])
    
    assert _has_open_port(ctx, 3306) == True
    assert _has_open_port(ctx, 5432) == False

def test_generate_wordpress_rule(engine, empty_context):
    tp = TechProfile(technologies=[TechFingerprint(name="WordPress", category="cms", confidence=1.0)])
    recs = engine.generate(empty_context, tp)
    
    # Should trigger wordpress_detected
    assert len(recs) == 1
    assert recs[0].title == "Run WPScan against WordPress installation"

def test_generate_smb_rule(engine, empty_context, empty_tech):
    ctx = empty_context
    ctx.services[("1.1.1.1", 445)] = ServiceContext(host="1.1.1.1", port=445, service="smb")
    
    recs = engine.generate(ctx, empty_tech)
    assert len(recs) == 1
    assert recs[0].tool_name == "enum4linux"

def test_generate_multiple_rules(engine, empty_context):
    ctx = empty_context
    ctx.services[("1.1.1.1", 445)] = ServiceContext(host="1.1.1.1", port=445, service="smb")
    ctx.hosts["1.1.1.1"] = HostContext(address="1.1.1.1", ports=[445, 3306])
    tp = TechProfile(technologies=[TechFingerprint(name="WordPress", category="cms", confidence=1.0)])
    
    recs = engine.generate(ctx, tp)
    assert len(recs) >= 3  # wordpress, smb, mysql
    titles = [r.title for r in recs]
    assert any("WPScan" in t for t in titles)
    assert any("SMB" in t for t in titles)
    assert any("MySQL" in t for t in titles)
