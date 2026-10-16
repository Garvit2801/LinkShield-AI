from fastapi.testclient import TestClient
from sandbox.worker import app

worker=TestClient(app)

def test_worker_does_not_expose_anonymous_browser(monkeypatch):
    monkeypatch.setenv('SANDBOX_TOKEN','very-long-demo-token')
    assert worker.post('/investigate',json={'url':'https://example.com/'}).status_code == 401
    assert worker.post('/investigate',headers={'Authorization':'Bearer wrong'},json={'url':'https://example.com/'}).status_code == 401

def test_worker_rejects_private_address_even_with_token(monkeypatch):
    monkeypatch.setenv('SANDBOX_TOKEN','very-long-demo-token')
    r=worker.post('/investigate',headers={'Authorization':'Bearer very-long-demo-token'},json={'url':'http://127.0.0.1/admin'})
    assert r.status_code == 422

import asyncio
import httpx
from sandbox import worker as worker_module

def _serve(handler):
    async def public(_host): return True
    worker_module.public_dns = public
    return asyncio.run(worker_module.fetch_file('https://files.example.com/start', transport=httpx.MockTransport(handler)))

def test_fetch_treats_html_as_page_and_inspects_files(monkeypatch):
    monkeypatch.setattr(worker_module,'public_dns',worker_module.public_dns)
    assert _serve(lambda r: httpx.Response(200,headers={'content-type':'text/html; charset=utf-8'},content=b'<html></html>'))['kind'] == 'page'
    def redirecting(request):
        if request.url.path == '/start':
            return httpx.Response(302,headers={'location':'/files/holiday.jpg'})
        return httpx.Response(200,headers={'content-type':'image/jpeg'},content=b'MZ'+b'\x00'*200)
    got = _serve(redirecting)
    assert got['kind'] == 'file' and got['redirects'] == 1 and got['file']['name'] == 'holiday.jpg'
    assert got['file']['verdict'] == 'dangerous' and got['file']['source_url'].endswith('/files/holiday.jpg')
    named = _serve(lambda r: httpx.Response(200,headers={'content-type':'text/html','content-disposition':'attachment; filename="invoice.html"'},content=b'<html><body>hi</body></html>'))
    assert named['kind'] == 'file' and named['file']['name'] == 'invoice.html'

def test_fetch_refuses_redirects_to_internal_addresses_and_caps_size(monkeypatch):
    monkeypatch.setattr(worker_module,'public_dns',worker_module.public_dns)
    assert _serve(lambda r: httpx.Response(302,headers={'location':'http://169.254.169.254/latest/meta-data'}))['kind'] == 'error'
    monkeypatch.setattr(worker_module,'MAX_FILE_BYTES',1000)
    big = _serve(lambda r: httpx.Response(200,headers={'content-type':'application/octet-stream','content-length':'5000'},content=b'\x89PNG\r\n\x1a\n'+b'\x00'*4992))
    assert big['file']['bytes_checked'] == 1000 and big['file']['size'] == 5000 and not big['file']['complete']

def test_upload_endpoint_requires_token_and_reports(monkeypatch):
    monkeypatch.setenv('SANDBOX_TOKEN','very-long-demo-token')
    assert worker.post('/scan-file',content=b'x').status_code == 401
    r=worker.post('/scan-file',headers={'Authorization':'Bearer very-long-demo-token','X-File-Name':'photo.jpg.exe'},content=b'MZ'+b'\x00'*100)
    assert r.status_code == 200 and r.json()['file']['verdict'] == 'dangerous'
