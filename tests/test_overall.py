import modules.email_domain as email_domain


def fake_dns(records):
    def fake_get_txt_records(name):
        return records.get(name, [])
    return fake_get_txt_records


def test_overall_is_the_worst_of_spf_and_dmarc(monkeypatch):
    records = {
        "example.com": ["v=spf1 -all"],
    }
    monkeypatch.setattr(email_domain, "get_txt_records", fake_dns(records))
    result = email_domain.check_email_domain("example.com")
    assert result["overall"] == "RISK"


def test_overall_is_ok_when_spf_and_dmarc_are_strong(monkeypatch):
    records = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
    }
    monkeypatch.setattr(email_domain, "get_txt_records", fake_dns(records))
    result = email_domain.check_email_domain("example.com")
    assert result["overall"] == "OK"


def test_overall_is_risk_when_spf_is_missing(monkeypatch):
    records = {
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
    }
    monkeypatch.setattr(email_domain, "get_txt_records", fake_dns(records))
    result = email_domain.check_email_domain("example.com")
    assert result["overall"] == "RISK"


def test_overall_is_attention_when_dmarc_only_monitors(monkeypatch):
    records = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=none"],
    }
    monkeypatch.setattr(email_domain, "get_txt_records", fake_dns(records))
    result = email_domain.check_email_domain("example.com")
    assert result["overall"] == "ATTENTION"


def test_invalid_domain_returns_false():
    # The domain is rejected before any DNS query, so no fake DNS is needed
    assert email_domain.check_email_domain("evil.com;ls") is False


def test_dns_down_returns_false(monkeypatch):
    # A function that returns None for every name = "the DNS can't be queried"
    monkeypatch.setattr(email_domain, "get_txt_records", lambda name: None)
    assert email_domain.check_email_domain("example.com") is False


def test_invalid_selector_returns_false(monkeypatch):
    monkeypatch.setattr(email_domain, "get_txt_records", fake_dns({}))
    assert email_domain.check_email_domain("example.com", "sel;ls") is False