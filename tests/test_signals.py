from app.security.signals import inspect_url, inspect_page, classify

def test_brand_lookalike_flag():
    flags = inspect_url('https://sbi-kyc-update.example.com/verify')
    assert any(s['code'] == 'impersonation' for s in flags)
    level, score = classify(flags, [], 'not_configured', False)
    assert level in ('caution', 'high') and score >= 30

def test_legitimate_brand_not_flagged():
    flags = inspect_url('https://onlineSBI.sbi/')
    assert not any(f['code'] == 'impersonation' for f in flags)

def test_unverified_without_sandbox():
    assert classify([], [], 'not_configured', True)[0] == 'unverified'

def test_known_threat_overrides_everything():
    assert classify([], ['MALWARE'], 'error', True) == ('critical', 98)

def test_browser_evidence():
    flags=inspect_page({'password_inputs':1, 'downloads':1, 'redirects':4, 'cross_domain_forms':1})
    assert {'password_form','download_attempt','redirects','offsite_form'} <= {x['code'] for x in flags}
