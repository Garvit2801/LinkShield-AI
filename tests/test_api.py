import os
from fastapi.testclient import TestClient
from app.main import app
from app.security import api

SESSION = 'a38e8dad-d196-4fda-8c43-9be5eecb080f'
client=TestClient(app)

def test_home_and_health():
    assert client.get('/healthz').status_code == 200
    html=client.get('/app').text
    assert 'Check it before you' in html
    assert 'app.js' in html
    assert 'login.js' in client.get('/').text

def test_requires_local_session_header(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED','0')
    assert client.get('/api/v1/scans').status_code == 400

def test_api_scan_history_delete(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED','0')
    monkeypatch.setenv('DISABLE_GOOGLE','1')
    monkeypatch.delenv('SANDBOX_URL',raising=False)
    monkeypatch.delenv('SANDBOX_TOKEN',raising=False)
    h={'X-Linkshield-Session':SESSION}
    result=client.post('/api/v1/scans',headers=h,json={'url':'https://example.com','sandbox':True})
    assert result.status_code == 200,result.text
    obj=result.json()
    assert obj['level']=='unverified'
    sid=obj['id']
    assert any(x['id']==sid for x in client.get('/api/v1/scans',headers=h).json()['items'])
    assert client.get(f'/api/v1/scans/{sid}',headers=h).status_code==200
    assert client.get(f'/api/v1/scans/{sid}',headers={'X-Linkshield-Session':'b38e8dad-d196-4fda-8c43-9be5eecb080f'}).status_code==404
    assert client.delete(f'/api/v1/scans/{sid}',headers=h).status_code==204
    assert client.get(f'/api/v1/scans/{sid}',headers=h).status_code==404

def test_internal_address_rejected(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED','0')
    response=client.post('/api/v1/scans',headers={'X-Linkshield-Session':SESSION},json={'url':'http://127.0.0.1/private'})
    assert response.status_code==422

def test_file_upload_without_sandbox_is_unverified_and_limits_apply(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED','0')
    monkeypatch.setenv('DISABLE_GOOGLE','1')
    monkeypatch.delenv('SANDBOX_URL',raising=False)
    monkeypatch.delenv('SANDBOX_TOKEN',raising=False)
    api._hits.clear()
    h={'X-Linkshield-Session':SESSION,'X-File-Name':'holiday%20photo.jpg','Content-Type':'image/jpeg'}
    result=client.post('/api/v1/files',headers=h,content=b'\xff\xd8\xff\xe0data')
    assert result.status_code == 200,result.text
    obj=result.json()
    assert obj['target']=='upload' and obj['level']=='unverified' and obj['domain']=='holiday photo.jpg'
    assert client.get(f"/api/v1/scans/{obj['id']}",headers=h).status_code==200
    assert client.post('/api/v1/files',headers=h,content=b'').status_code==422
    monkeypatch.setattr(api,'MAX_UPLOAD_BYTES',8)
    assert client.post('/api/v1/files',headers=h,content=b'123456789').status_code==413
    assert client.post('/api/v1/files?language=xx',headers=h,content=b'1').status_code==422
