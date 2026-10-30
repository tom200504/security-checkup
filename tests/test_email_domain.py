from modules.email_domain import evaluate_spf, evaluate_dmarc, evaluate_dkim


def test_spf_missing_is_risk():
    level, message = evaluate_spf([])
    assert level == "RISK"

def test_spf_lessall_is_ok():
    level, message = evaluate_spf(["-all"])
    assert level == "OK"

def test_spf_moreall_is_risk():
    level, message = evaluate_spf(["+all"])
    assert level == "RISK"

def test_spf_two_is_attention():
    level, message = evaluate_spf(["-all", "+all"])
    assert level == "ATTENTION"

def test_spf_softfail_is_ok():
    level, message = evaluate_spf(["v=spf1 include:_spf.google.com ~all"])
    assert level == "OK"

def test_spf_google_is_attention():
    level, message = evaluate_spf(["redirect=_spf.google.com"])
    assert level == "ATTENTION"

def test_dmarc_none_is_attention():
    level, message = evaluate_dmarc("none")
    assert level == "ATTENTION"

def test_dmarc_reject_is_ok():
    level, message = evaluate_dmarc("reject")
    assert level == "OK"

def test_dmarc_None_is_risk():
    level, message = evaluate_dmarc(None)
    assert level == "RISK"

def test_dmarc_quarantine_is_ok():
    level, message = evaluate_dmarc("quarantine")
    assert level == "OK"

def test_dkim_google_is_info():
    level, message = evaluate_dkim("google")
    assert level == "INFO"

def test_dkim_None_is_info():
    level, message = evaluate_dkim(None)
    assert level == "INFO"

