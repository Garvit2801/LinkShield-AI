import pytest
from app.security import orchestrator

@pytest.mark.asyncio
async def test_investigation_evidence(monkeypatch):
    async def threat(_):
        return {'checked': True,'threats':['SOCIAL_ENGINEERING'],'error':None}
    async def worker(_):
        return {'status':'completed','evidence':{'title':'Login','final_url':'https://hdfcbank-alert.example.com/',
               'redirects':1,'password_inputs':1,'payment_inputs':0,'downloads':0,'cross_domain_forms':1,
               'blocked_requests':0,'screenshot_base64':''}}
    async def ai(*args): return None
    monkeypatch.setattr(orchestrator,'google_web_risk',threat)
    monkeypatch.setattr(orchestrator,'investigate',worker)
    monkeypatch.setattr(orchestrator,'gemini_explain',ai)
    out = await orchestrator.scan(orchestrator.ScanInput(url='https://hdfcbank-alert.example.com/', message='update your KYC'))
    assert out['level'] == 'critical'
    assert out['score'] == 98
    assert out['sandbox']['status'] == 'completed'
    assert out['narrative']['generated_by'] == 'rules'
    assert len(out['steps']) == 5
    assert not out['disclaimer'].startswith('This link is safe')

@pytest.mark.asyncio
async def test_without_providers_is_unverified(monkeypatch):
    async def no_threat(_): return {'checked':False,'threats':[], 'error':'Not configured'}
    async def no_browser(_): return {'status':'not_configured', 'evidence':{},'error':'Not configured'}
    async def no_ai(*args):return None
    monkeypatch.setattr(orchestrator,'google_web_risk',no_threat)
    monkeypatch.setattr(orchestrator,'investigate',no_browser)
    monkeypatch.setattr(orchestrator,'gemini_explain',no_ai)
    out=await orchestrator.scan(orchestrator.ScanInput(url='https://example.com'))
    assert out['level']=='unverified'
    assert not out['web_risk']['checked']
    assert out['sandbox']['status']=='not_configured'

CLEAN_FILE = {'name':'ticket.pdf','type':'PDF document','kind':'document','size':900,'sha256':'a'*64,'complete':True,
              'verdict':'clean','score':0,'findings':[],'checks':[{'label':'No scripts (JavaScript)','ok':True}],'notes':[],'internal':'dropped'}

def _providers(monkeypatch, worker):
    async def no_threat(_): return {'checked':False,'threats':[], 'error':'Not configured'}
    async def no_ai(*args): return None
    monkeypatch.setattr(orchestrator,'google_web_risk',no_threat)
    monkeypatch.setattr(orchestrator,'investigate',worker)
    monkeypatch.setattr(orchestrator,'gemini_explain',no_ai)

@pytest.mark.asyncio
async def test_link_to_clean_file_is_cleared(monkeypatch):
    async def worker(_): return {'status':'completed','target':'file','files':[CLEAN_FILE],'evidence':{'final_url':'https://example.com/ticket.pdf','redirects':0}}
    _providers(monkeypatch, worker)
    out = await orchestrator.scan(orchestrator.ScanInput(url='https://example.com/ticket.pdf'))
    assert out['target'] == 'file' and out['level'] == 'low'
    assert out['files'][0]['sha256'] == 'a'*64 and 'internal' not in out['files'][0]
    assert [s['id'] for s in out['steps']] == ['normalize','reputation','sandbox','file','evidence','explain']
    assert out['narrative']['headline'] == 'No danger signs found in this file'

@pytest.mark.asyncio
async def test_link_to_dangerous_or_partly_read_file_is_not_cleared(monkeypatch):
    bad = {**CLEAN_FILE,'name':'photo.jpg','verdict':'dangerous','findings':[{'code':'disguised_program','label':'A program disguised as a harmless file','weight':95,'detail':'x'}]}
    async def worker(_): return {'status':'completed','target':'file','files':[bad],'evidence':{}}
    _providers(monkeypatch, worker)
    out = await orchestrator.scan(orchestrator.ScanInput(url='https://example.com/photo.jpg'))
    assert out['level'] == 'high' and out['signals'][0]['source'] == 'file_scan'
    assert out['narrative']['recommendations'][0] == 'Do not download or open this file.'
    async def partial(_): return {'status':'completed','target':'file','files':[{**CLEAN_FILE,'complete':False,'verdict':'unknown'}],'evidence':{}}
    monkeypatch.setattr(orchestrator,'investigate',partial)
    assert (await orchestrator.scan(orchestrator.ScanInput(url='https://example.com/big.pdf')))['level'] == 'unverified'

@pytest.mark.asyncio
async def test_uploaded_file(monkeypatch):
    async def no_ai(*args): return None
    async def worker(data, name, content_type=''): return {'status':'completed','file':{**CLEAN_FILE,'name':name}}
    monkeypatch.setattr(orchestrator,'gemini_explain',no_ai)
    monkeypatch.setattr(orchestrator,'inspect_upload',worker)
    out = await orchestrator.scan_upload(b'%PDF-1.7', 'ticket.pdf')
    assert out['target'] == 'upload' and out['level'] == 'low' and out['url'] == '' and out['domain'] == 'ticket.pdf'
    async def down(data, name, content_type=''): return {'status':'not_configured','evidence':{},'error':'Sandbox worker is not configured'}
    monkeypatch.setattr(orchestrator,'inspect_upload',down)
    out = await orchestrator.scan_upload(b'%PDF-1.7', 'ticket.pdf')
    assert out['level'] == 'unverified' and out['files'] == [] and out['narrative']['headline'] == 'This file could not be checked'

@pytest.mark.asyncio
async def test_file_link_the_sandbox_could_not_fetch_is_never_low(monkeypatch):
    challenge = {'title':'Just a moment...','final_url':'https://example.com/ticket.pdf','redirects':0,'password_inputs':0,'payment_inputs':0,
                 'downloads':0,'cross_domain_forms':0,'blocked_requests':0,'http_status':403,'screenshot_base64':''}
    async def worker(_): return {'status':'completed','target':'page','files':[],'file_error':'Server answered 403','evidence':challenge}
    _providers(monkeypatch, worker)
    out = await orchestrator.scan(orchestrator.ScanInput(url='https://example.com/ticket.pdf'))
    assert out['level'] == 'unverified' and out['file_expected'] and '403' in out['file_error']
    assert out['narrative']['headline'] == 'This file could not be checked'
    async def refused(_): return {'status':'completed','target':'page','files':[],'evidence':{**challenge,'final_url':'https://example.com/'}}
    monkeypatch.setattr(orchestrator,'investigate',refused)
    out = await orchestrator.scan(orchestrator.ScanInput(url='https://example.com/'))
    assert out['level'] == 'unverified' and not out['file_expected']
    assert next(s for s in out['steps'] if s['id'] == 'sandbox')['status'] == 'partial'
