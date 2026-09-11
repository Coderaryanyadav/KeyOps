import pytest
from app.safety.domain_trust import DomainTrustContext

def test_domain_trust_evaluation_valid_official():
    ctx = DomainTrustContext(expected_service="github", allowed_explicit_domains=["github.com"])
    res = ctx.evaluate_url("https://github.com/settings/security")
    assert res.is_trusted is True
    assert res.registrable_domain == "github.com"
    assert res.is_https is True

def test_domain_trust_blocks_insecure_http():
    ctx = DomainTrustContext(expected_service="github", allowed_explicit_domains=["github.com"])
    res = ctx.evaluate_url("http://github.com/settings/security")
    assert res.is_trusted is False
    assert "HTTPS is mandatory" in res.reason

def test_domain_trust_blocks_subdomain_spoofing():
    ctx = DomainTrustContext(expected_service="github", allowed_explicit_domains=["github.com"])
    res = ctx.evaluate_url("https://github.com.attacker.com/login")
    assert res.is_trusted is False
    assert res.registrable_domain == "attacker.com"

def test_domain_trust_blocks_punycode_homographs():
    ctx = DomainTrustContext(expected_service="apple", allowed_explicit_domains=["apple.com"])
    res = ctx.evaluate_url("https://xn--pple-43d.com/signin")
    assert res.is_trusted is False
    assert "Homograph" in res.reason

def test_domain_trust_callback_on_domain_change():
    changes = []
    ctx = DomainTrustContext(expected_service="google", allowed_explicit_domains=["google.com"])
    ctx.register_on_domain_changed_callback(lambda old_d, new_d: changes.append((old_d, new_d)))

    ctx.evaluate_url("https://google.com/account")
    ctx.evaluate_url("https://evil-spoof.com/account")

    assert len(changes) == 1
    assert changes[0][0] == "google.com"
    assert changes[0][1] == "evil-spoof.com"
