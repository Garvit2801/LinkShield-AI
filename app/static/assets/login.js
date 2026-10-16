import { buddySvg, CRITTERS } from './characters.js';

const $ = (s, root = document) => root.querySelector(s);
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const params = new URLSearchParams(location.search);
const next = '/app' + (/^#[a-z]+$/.test(params.get('next') || '') ? params.get('next') : '');
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};
const T = {
  en: {
    title: null, lead: 'A second opinion on anything you were sent: links, files, screenshots, voice notes and forwards.',
    p1: 'Scam links and files', p1d: 'Opened in a safe sandbox, never on your phone.', p2: 'Fake news, traced', p2d: 'Claims checked against fact-checkers and official sources.',
    cardTitle: 'Sign in to keep your history', cardSub: 'Or try it first as a guest. No account needed.', help: null,
    p3: 'Your history and helper', p3d: 'Saved to your account, with Shieldy to answer questions.', or: 'or', guest: 'Continue as a guest',
    fine: 'Signing in only reads your name, email and photo. Files you check are never kept.', say: 'Catch the scams before they reach you!',
    caught: 'caught', hint: 'Tap the critters · drag the shield', welcome: n => `Welcome${n ? `, ${n}` : ''}!`, guestHi: "Let's go!",
    noCfg: "Google sign-in isn't switched on for this server yet. You can use LinkShield as a guest.", fail: 'Sign-in did not work. Please try again.',
    expired: 'Your sign-in ended after an hour. Signing you back in…', out: 'You are signed out.',
    catches: ['Caught a phish!', 'Virus zapped!', 'Fake login, busted!', 'Gotcha!'],
  },
  hi: {
    title: 'खोलने से पहले <span class="u">जाँच लें<svg viewBox="0 0 200 14" preserveAspectRatio="none" aria-hidden="true"><path d="M3 9c28-9 46 6 76 0s58-7 118 1"/></svg></span>',
    lead: 'आपको भेजी गई हर चीज़ पर दूसरी राय: लिंक, फ़ाइलें, स्क्रीनशॉट, वॉइस नोट और फ़ॉरवर्ड।',
    p1: 'स्कैम लिंक और फ़ाइलें', p1d: 'सुरक्षित सैंडबॉक्स में खोली जाती हैं, आपके फ़ोन पर कभी नहीं।', p2: 'फ़र्ज़ी ख़बरों की जाँच', p2d: 'दावे फ़ैक्ट-चेकर और सरकारी स्रोतों से परखे जाते हैं।',
    cardTitle: 'इतिहास सहेजने के लिए साइन इन करें', cardSub: 'या पहले मेहमान के रूप में आज़माएँ। खाते की ज़रूरत नहीं।', help: 'ऑनलाइन ठगी हुई? <b>1930</b> पर कॉल करें',
    p3: 'आपका इतिहास और मददगार', p3d: 'आपके खाते में सहेजा जाता है, सवालों के लिए Shieldy हाज़िर है।', or: 'या', guest: 'बिना साइन इन के जारी रखें',
    fine: 'साइन इन सिर्फ़ आपका नाम, ईमेल और फ़ोटो पढ़ता है। जाँची गई फ़ाइलें कभी सहेजी नहीं जातीं।', say: 'स्कैम को आप तक पहुँचने से पहले पकड़ें!',
    caught: 'पकड़े', hint: 'जीवों पर टैप करें · ढाल को खींचें', welcome: n => `स्वागत है${n ? `, ${n}` : ''}!`, guestHi: 'चलिए!',
    noCfg: 'इस सर्वर पर Google साइन इन अभी चालू नहीं है। आप मेहमान के रूप में इस्तेमाल कर सकते हैं।', fail: 'साइन इन नहीं हो सका। फिर कोशिश करें।',
    expired: 'एक घंटे बाद साइन इन ख़त्म हो गया। फिर से साइन इन कर रहे हैं…', out: 'आप साइन आउट हो गए हैं।',
    catches: ['फ़िश पकड़ी!', 'वायरस ख़त्म!', 'नकली लॉगिन पकड़ा!', 'पकड़ लिया!'],
  },
};
let lang = store.get('linkshield_ui') || ((navigator.language || '').startsWith('hi') ? 'hi' : 'en');
const t = k => T[lang][k] ?? T.en[k];

function applyLang() {
  document.documentElement.lang = lang;
  $('#lang').value = lang;
  document.querySelectorAll('[data-t]').forEach(el => {
    const k = el.dataset.t;
    if (k === 'help') { if (!el.dataset.en) el.dataset.en = el.innerHTML; el.innerHTML = lang === 'hi' ? T.hi.help : el.dataset.en; } else if (k === 'title') { if (!el.dataset.en) el.dataset.en = el.innerHTML; el.innerHTML = lang === 'hi' ? T.hi.title : el.dataset.en; } else el.textContent = t(k);
  });
}

let sayTimer;
function say(words, moodName = 'happy', hold = 2400) {
  const buddy = $('#buddyWrap .buddy');
  if (buddy) buddy.dataset.mood = moodName;
  const box = $('#buddySay');
  box.textContent = words; box.classList.remove('pop'); void box.offsetWidth; box.classList.add('pop');
  clearTimeout(sayTimer);
  if (hold) sayTimer = setTimeout(() => { if (buddy) buddy.dataset.mood = 'idle'; box.textContent = t('say'); }, hold);
}
function confetti(host) {
  if (reducedMotion) return;
  const burst = document.createElement('div');
  burst.className = 'burst';
  burst.innerHTML = Array.from({ length: 26 }, (_, i) => `<i style="--x:${Math.round(Math.random() * 520 - 260)}px;--y:${Math.round(-60 - Math.random() * 190)}px;--r:${Math.round(Math.random() * 540)}deg;--d:${i * 12}ms;--c:${['#2fa870', '#8fe3b8', '#f4d35e', '#bfe8d0', '#f7b267'][i % 5]}"></i>`).join('');
  host.append(burst);
  setTimeout(() => burst.remove(), 2200);
}

/* The playground: critters to catch, a shield to drag, icon bits drifting by. */
let caught = 0;
function spawnCritter() {
  const layer = $('#critters');
  if (reducedMotion || document.hidden || layer.children.length >= 3) return;
  const kinds = Object.keys(CRITTERS);
  const kind = kinds[Math.floor(Math.random() * kinds.length)];
  const el = document.createElement('button');
  el.type = 'button'; el.className = `critter cr-${kind}`; el.tabIndex = -1; el.dataset.critter = kind; el.innerHTML = CRITTERS[kind].svg;
  layer.append(el);
  const w = layer.clientWidth, h = layer.clientHeight, size = el.offsetWidth;
  const right = Math.random() < 0.5;
  const y0 = h * (0.15 + Math.random() * 0.6), y1 = y0 + (Math.random() - 0.5) * h * 0.3;
  el.classList.toggle('flip', !right);
  el._swim = el.animate([{ transform: `translate(${right ? -size : w}px,${y0}px)` }, { transform: `translate(${right ? w : -size}px,${y1}px)` }],
    { duration: 7000 + Math.random() * 4000, easing: 'linear' });
  el._swim.onfinish = () => el.remove();
  el.addEventListener('click', () => {
    if (el.classList.contains('caught')) return;
    el._swim.pause(); el.classList.add('caught');
    caught++;
    const pill = $('#caughtCount');
    $('b', pill).textContent = caught; pill.classList.remove('bump'); void pill.offsetWidth; pill.classList.add('bump');
    const lines = t('catches');
    say(lines[Math.floor(Math.random() * lines.length)]);
    if (caught % 5 === 0) confetti($('#heroArt'));
    setTimeout(() => el.remove(), 650);
  });
}
function drift() {
  if (reducedMotion) return;
  const icons = ['link', 'lock', 'file', 'image', 'mic', 'quote', 'shield-check', 'spark'];
  $('#drift').innerHTML = Array.from({ length: 16 }, (_, i) => `<span style="--x:${Math.round(Math.random() * 100)}%;--s:${(0.7 + Math.random() * 0.9).toFixed(2)};--dur:${14 + Math.round(Math.random() * 16)}s;--delay:-${Math.round(Math.random() * 24)}s;--z:${(0.3 + Math.random() * 0.7).toFixed(2)}"><svg class="ic"><use href="#i-${icons[i % icons.length]}"/></svg></span>`).join('');
  document.addEventListener('pointermove', e => {
    const x = e.clientX / innerWidth - 0.5, y = e.clientY / innerHeight - 0.5;
    document.documentElement.style.setProperty('--px', x.toFixed(3)); document.documentElement.style.setProperty('--py', y.toFixed(3));
    const box = $('#buddyWrap').getBoundingClientRect();
    const dx = e.clientX - (box.left + box.width / 2), dy = e.clientY - (box.top + box.height * 0.42);
    const far = Math.hypot(dx, dy) || 1, pull = Math.min(1, far / 160);
    document.documentElement.style.setProperty('--ex', (dx / far * pull).toFixed(3));
    document.documentElement.style.setProperty('--ey', (dy / far * pull).toFixed(3));
  }, { passive: true });
}
function draggable() {
  const wrap = $('#buddyWrap');
  let start = null;
  wrap.addEventListener('pointerdown', e => { if (reducedMotion) return; start = { x: e.clientX, y: e.clientY, moved: false }; wrap.setPointerCapture(e.pointerId); wrap.classList.add('held'); });
  wrap.addEventListener('pointermove', e => {
    if (!start) return;
    const dx = e.clientX - start.x, dy = e.clientY - start.y;
    if (Math.hypot(dx, dy) > 6) start.moved = true;
    const pull = d => d * 0.6 / (1 + Math.abs(d) / 300);
    wrap.style.setProperty('--dx', `${pull(dx)}px`); wrap.style.setProperty('--dy', `${pull(dy)}px`); wrap.style.setProperty('--tilt', `${Math.max(-18, Math.min(18, dx / 8))}deg`);
  });
  const drop = () => {
    if (!start) return;
    wrap.classList.remove('held');
    ['--dx', '--dy'].forEach(v => wrap.style.setProperty(v, '0px')); wrap.style.setProperty('--tilt', '0deg');
    say(start.moved ? 'Wheee!' : ['Hi!', 'Sign in and feed me links!', 'That tickles.'][Math.floor(Math.random() * 3)]);
    start = null;
  };
  wrap.addEventListener('pointerup', drop); wrap.addEventListener('pointercancel', drop);
}

/* Sign in */
function go(words) {
  say(words, 'happy', 0);
  confetti($('#heroArt'));
  document.body.classList.add('leaving');
  setTimeout(() => location.assign(next), reducedMotion ? 0 : 900);
}
function onCredential(r) {
  store.set('ls_tok', r.credential);
  try { localStorage.removeItem('ls_guest'); } catch { /* private mode */ }
  let name = '';
  try { name = JSON.parse(atob(r.credential.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).given_name || ''; } catch { /* keep blank */ }
  go(t('welcome')(name));
}
// The status note sits above the buttons as a small badge; tone is info, ok or warn.
function note(text, tone = 'info') {
  const box = $('#msg');
  box.hidden = !text; box.className = `signin-msg tone-${tone}`;
  $('span', box).textContent = text || '';
  $('use', box).setAttribute('href', tone === 'ok' ? '#i-check' : '#i-info');
}
let gisReady = false;
// Google's button is drawn at a fixed width, so it is sized to match the guest button below it.
const renderGoogleButton = () => google.accounts.id.renderButton($('#gbtn'), { theme: 'outline', size: 'large', text: 'continue_with', shape: 'pill', logo_alignment: 'center', width: Math.max(220, Math.min(400, $('#gbtn').clientWidth)), locale: lang });
async function startGoogle() {
    let cfg = {};
  try { cfg = await (await fetch('/api/config')).json(); } catch { /* treated as not set up */ }
  if (cfg.authRequired) $('#guestBtn').closest('.signin-card').classList.add('no-guest');
  if (!cfg.googleClientId) { $('#gbtn').hidden = true; $('.or').hidden = true; note(t('noCfg')); return; }
  const ready = () => window.google?.accounts?.id;
  for (let i = 0; i < 80 && !ready(); i++) await new Promise(r => setTimeout(r, 100));
  if (!ready()) { note(t('fail'), 'warn'); return; }
  const out = params.has('out');
  google.accounts.id.initialize({ client_id: cfg.googleClientId, callback: onCredential, auto_select: !out, cancel_on_tap_outside: true, use_fedcm_for_prompt: true });
  if (out) { google.accounts.id.disableAutoSelect(); note(t('out'), 'ok'); }
  renderGoogleButton(); gisReady = true;
  if (params.has('expired')) { note(t('expired')); google.accounts.id.prompt(); }
}

applyLang();
$('#lang').onchange = e => { lang = e.target.value; store.set('linkshield_ui', lang); applyLang(); if (gisReady) renderGoogleButton(); };
$('#buddyWrap').innerHTML = buddySvg('idle');
$('#guestBtn').onclick = () => { store.set('ls_guest', '1'); go(t('guestHi')); };
drift(); draggable();
if (!reducedMotion) { setTimeout(spawnCritter, 900); setInterval(spawnCritter, 2600); }
startGoogle();
