from fastapi.testclient import TestClient

from app import chat
from app.security import storage
from app.main import app
from app.security import api, identity

client = TestClient(app)
H = {'X-Linkshield-Session': 'a38e8dad-d196-4fda-8c43-9be5eecb080f'}


def test_reply_tags_are_split_off():
    reply, remember, suggest = chat.parse("Never share an OTP.\n[[remember: Their bank is SBI]]\n[[suggest: What is vishing? | How to report?]]")
    assert reply == 'Never share an OTP.' and remember == 'Their bank is SBI'
    assert suggest == ['What is vishing?', 'How to report?']
    assert chat.parse('Hi [[remember: none]]')[1] is None


def test_notes_can_be_taught_listed_and_removed(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', '0'); monkeypatch.setenv('ENABLE_FIRESTORE', '0')
    api._hits.clear(); storage._profiles.clear()
    n = client.post('/api/v1/chat/notes', headers=H, json={'text': 'My mother uses Paytm', 'kind': 'fact'}).json()
    client.post('/api/v1/chat/notes', headers=H, json={'text': 'my mother uses paytm'})  # duplicates are not kept twice
    assert [x['text'] for x in client.get('/api/v1/chat/notes', headers=H).json()['items']] == ['My mother uses Paytm']
    client.delete(f"/api/v1/chat/notes/{n['id']}", headers=H)
    assert client.get('/api/v1/chat/notes', headers=H).json()['items'] == []


def test_chat_needs_gemini(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', '0'); monkeypatch.setenv('DISABLE_GOOGLE', '1')
    api._hits.clear()
    r = client.post('/api/v1/chat', headers=H, json={'messages': [{'role': 'user', 'text': 'hi'}]})
    assert r.status_code == 503


def test_chat_answers_and_learns(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', '0'); monkeypatch.setenv('GOOGLE_CLOUD_PROJECT', 'p'); monkeypatch.delenv('DISABLE_GOOGLE', raising=False)
    api._hits.clear(); storage._profiles.clear()

    async def fake(uid, body, search=True):
        return {'reply': 'ok', 'suggestions': [], 'sources': [], 'learned': chat.add_note(uid, 'Prefers Hindi')}
    monkeypatch.setattr(chat, 'ask_gemini', fake)
    r = client.post('/api/v1/chat', headers=H, json={'messages': [{'role': 'user', 'text': 'remember I prefer Hindi'}]})
    assert r.json()['reply'] == 'ok' and r.json()['learned']['text'] == 'Prefers Hindi'


def test_google_sign_in_is_verified(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', '0'); monkeypatch.setenv('GOOGLE_CLIENT_ID', 'cid.apps.googleusercontent.com')
    api._hits.clear()
    monkeypatch.setattr(identity, '_google', lambda t: {'uid': 'g-1', 'email': 'a@b.c', 'name': 'Asha', 'picture': None} if t == 'good' else (_ for _ in ()).throw(ValueError()))
    me = client.get('/api/v1/me', headers={'Authorization': 'Bearer good'}).json()
    assert me['name'] == 'Asha' and me['guest'] is False
    # A bad or expired token is refused even though guests are allowed, so the page can send them to sign in again.
    assert client.get('/api/v1/me', headers={'Authorization': 'Bearer bad'}).status_code == 401
    assert client.get('/api/v1/me', headers=H).json()['guest'] is True
    assert client.get('/api/config').json() == {'authRequired': False, 'googleClientId': 'cid.apps.googleusercontent.com'}


def test_sign_in_required_turns_guests_away(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', '1')
    assert client.get('/api/v1/me', headers=H).status_code == 401


def test_slow_search_answer_falls_back_to_a_quick_one(monkeypatch):
    import asyncio
    calls = []

    async def fake(uid, body, search=True):
        calls.append(search)
        await asyncio.sleep(5 if search else 0.01)
        return {'reply': 'searched' if search else 'quick'}
    monkeypatch.setattr(chat, 'ask_gemini', fake)
    body = chat.ChatIn(messages=[{'role': 'user', 'text': 'hi'}])
    assert asyncio.run(chat.answer('u', body, head_start=0.05, limit_s=2))['reply'] == 'quick'

    async def broken(uid, body, search=True):
        if search:
            raise RuntimeError('search failed')
        return {'reply': 'quick'}
    monkeypatch.setattr(chat, 'ask_gemini', broken)
    assert asyncio.run(chat.answer('u', body, head_start=1, limit_s=2))['reply'] == 'quick'
