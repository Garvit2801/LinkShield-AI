// The vector characters shared by the login page and the app: the shield mascot, the scam critters,
// the history owl and the chat helper. Each returns SVG markup; CSS in app.css animates them.

let buddyCount = 0;
export function buddySvg(mood = 'idle') {
  const n = ++buddyCount; // gradients and clips need an id of their own in each copy
  const shield = 'M120 22l84 30v72c0 60-37 96-84 116-47-20-84-56-84-116V52z';
  return `<svg class="buddy" data-mood="${mood}" viewBox="0 0 240 270" aria-hidden="true">
    <defs><linearGradient id="bdBody${n}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8fe3b8"/><stop offset="1" stop-color="#2fa870"/></linearGradient><clipPath id="bdClip${n}"><path d="${shield}"/></clipPath></defs>
    <ellipse class="bd-shadow" cx="120" cy="258" rx="60" ry="8"/>
    <g class="bd-float">
      <path class="bd-leaf" d="M120 26c-3-16 6-25 22-25 1 16-8 25-22 25z"/><path class="bd-leaf l2" d="M120 26c2-12-4-19-15-19-1 12 5 19 15 19z"/>
      <path class="bd-body" d="${shield}" fill="url(#bdBody${n})" stroke="url(#bdBody${n})"/>
      <g clip-path="url(#bdClip${n})"><path class="bd-shine" d="M36 52l84-30v218c-47-20-84-56-84-116z"/><path class="bd-tint" d="${shield}"/><rect class="bd-scan" x="30" y="-30" width="180" height="30"/></g>
      <g class="bd-eye"><circle cx="92" cy="116" r="18" fill="#fff"/><circle class="bd-pupil" cx="92" cy="116" r="8.500"/><circle class="bd-glint" cx="95" cy="112" r="2.800"/></g>
      <g class="bd-eye"><circle cx="148" cy="116" r="18" fill="#fff"/><circle class="bd-pupil" cx="148" cy="116" r="8.500"/><circle class="bd-glint" cx="151" cy="112" r="2.800"/></g>
      <path class="bd-brow" d="M74 90l30 9"/><path class="bd-brow" d="M166 90l-30 9"/>
      <circle class="bd-cheek" cx="70" cy="148" r="9"/><circle class="bd-cheek" cx="170" cy="148" r="9"/>
      <path class="m m-idle" d="M104 152q16 14 32 0"/><path class="m m-happy" d="M100 148q20 28 40 0z"/><circle class="m m-think" cx="120" cy="158" r="7"/>
      <path class="m m-worried" d="M102 160q9-8 18 0t18 0"/><path class="m m-alarm" d="M104 168q16-22 32 0z"/>
    </g></svg>`;
}

// Scam critters swim across the mascot's stage now and then. Tap one to catch it.
export const CRITTERS = {
  phish: {
    says: ['Caught a phish!', 'No phishing today.', 'Gotcha, phishy!'],
    svg: `<svg viewBox="0 0 100 92"><path class="cr-line" d="M80 -60V50"/><g class="cr-wiggle"><path d="M18 58L2 42l4 16-4 16z" fill="#e8846f"/><path d="M44 36q10-13 22-4" fill="#e8846f"/><ellipse cx="50" cy="58" rx="36" ry="22" fill="#f4a993"/><path d="M36 40q-6 18 0 36" stroke="#e8846f" stroke-width="5" fill="none"/>
      <rect x="40" y="57" width="22" height="11" rx="3" fill="#fff" opacity=".85"/><text x="51" y="65.500" font-size="8" font-weight="800" text-anchor="middle" fill="#c8423c" font-family="system-ui">KYC</text>
      <circle cx="68" cy="52" r="7" fill="#fff"/><circle class="cr-pupil" cx="70" cy="52" r="3.500" fill="#12382b"/><path d="M61 43l13 4" stroke="#12382b" stroke-width="3" stroke-linecap="round"/><path d="M84 62q-4 3-8 1" stroke="#12382b" stroke-width="2.500" fill="none" stroke-linecap="round"/><path d="M80 50q6 0 5 7-1 5-6 4" stroke="#7d8f88" stroke-width="2.500" fill="none"/></g></svg>`,
  },
  virus: {
    says: ['Squashed a bug!', 'Virus zapped.', 'Bye bye, malware.'],
    svg: `<svg viewBox="0 0 80 80"><g class="cr-spin">${Array.from({ length: 8 }, (_, i) => `<g transform="rotate(${i * 45} 40 40)"><path d="M40 16V5" stroke="#8d6cc0" stroke-width="4" stroke-linecap="round"/><circle cx="40" cy="5" r="4.500" fill="#b48ad6"/></g>`).join('')}</g>
      <g class="cr-wiggle"><circle cx="40" cy="40" r="22" fill="#b48ad6"/><circle cx="31" cy="44" r="4" fill="#9a72c8"/><circle cx="52" cy="31" r="3" fill="#9a72c8"/>
      <circle cx="32" cy="36" r="6" fill="#fff"/><circle cx="48" cy="36" r="6" fill="#fff"/><circle class="cr-pupil" cx="33" cy="37" r="3" fill="#12382b"/><circle class="cr-pupil" cx="49" cy="37" r="3" fill="#12382b"/>
      <path d="M26 28l10 4M54 28l-10 4" stroke="#12382b" stroke-width="2.500" stroke-linecap="round"/><path d="M31 49q9 7 18 0z" fill="#12382b"/><path d="M34 49l2 4 2-4M42 49l2 4 2-4" fill="#fff"/></g></svg>`,
  },
  ghost: {
    says: ['Fake login page, busted!', 'Boo yourself.', 'No passwords for you!'],
    svg: `<svg viewBox="0 0 84 92"><g class="cr-wiggle"><path d="M10 44a32 32 0 0 1 64 0v40l-8-6-8 6-8-6-8 6-8-6-8 6-8-6-8 6z" fill="#fff" stroke="#c8dcd1" stroke-width="2.500"/>
      <circle cx="32" cy="40" r="5" fill="#12382b"/><circle cx="52" cy="40" r="5" fill="#12382b"/><circle cx="34" cy="38" r="1.600" fill="#fff"/><circle cx="54" cy="38" r="1.600" fill="#fff"/><ellipse cx="42" cy="54" rx="5" ry="6" fill="#12382b"/>
      <rect x="48" y="58" width="30" height="20" rx="4" fill="#e6f5ea" stroke="#1c8a5a" stroke-width="2"/><rect x="53" y="63" width="20" height="4" rx="2" fill="#7fcfa6"/><rect x="53" y="70" width="12" height="4" rx="2" fill="#1c8a5a"/></g></svg>`,
  },
};

// Hoot, the owl who keeps your history. Moods: idle, happy, alarm, sleep, think.
export function owlSvg(mood = 'idle') {
  const eye = x => `<g class="ow-eye"><circle cx="${x}" cy="62" r="20" fill="#fff"/><circle class="ow-pupil" cx="${x}" cy="62" r="9" fill="#12382b"/><circle class="ow-glint" cx="${x + 3}" cy="58" r="3" fill="#fff"/></g>`;
  return `<svg class="owl" data-mood="${mood}" viewBox="0 0 160 172" aria-hidden="true">
    <ellipse class="ow-shadow" cx="80" cy="166" rx="44" ry="6"/>
    <g class="ow-z"><text x="126" y="34">z</text><text x="138" y="18">Z</text></g>
    <g class="ow-float">
      <path class="ow-tuft l" d="M44 42L34 12l26 20z"/><path class="ow-tuft r" d="M116 42l10-30-26 20z"/>
      <path class="ow-wing l" d="M30 84c-16 18-14 46 6 58 4-22 6-40-6-58z"/><path class="ow-wing r" d="M130 84c16 18 14 46-6 58-4-22-6-40 6-58z"/>
      <path class="ow-body" d="M80 22c-38 0-56 30-56 68 0 40 22 66 56 66s56-26 56-66c0-38-18-68-56-68z"/>
      <path class="ow-belly" d="M80 72c-24 0-34 22-34 44 0 24 14 38 34 38s34-14 34-38c0-22-10-44-34-44z"/>
      <path class="ow-scallop" d="M64 106q4 5 8 0M76 106q4 5 8 0M88 106q4 5 8 0M70 120q4 5 8 0M82 120q4 5 8 0M76 134q4 5 8 0"/>
      ${eye(58)}${eye(102)}
      <path class="ow-lid" d="M42 64q16 10 32 0M86 64q16 10 32 0"/>
      <g class="ow-glasses"><circle cx="58" cy="62" r="23"/><circle cx="102" cy="62" r="23"/><path d="M80 58h1"/></g>
      <circle class="ow-cheek" cx="44" cy="88" r="6"/><circle class="ow-cheek" cx="116" cy="88" r="6"/>
      <path class="ow-beak" d="M73 80l7 11 7-11z"/>
      <path class="ow-feet" d="M66 156v7M73 156v7M87 156v7M94 156v7"/>
    </g></svg>`;
}

// Shieldy, the chat helper: a little speech-bubble robot. Moods: idle, think (typing dots), talk, happy.
let botCount = 0;
export function botSvg(mood = 'idle') {
  const n = ++botCount;
  return `<svg class="bot" data-mood="${mood}" viewBox="0 0 120 124" aria-hidden="true">
    <defs><linearGradient id="btGrad${n}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6fd6a2"/><stop offset="1" stop-color="#1f9460"/></linearGradient></defs>
    <g class="bt-float">
      <path class="bt-antenna" d="M60 24V12"/><circle class="bt-light" cx="60" cy="9" r="6"/>
      <rect class="bt-ear" x="5" y="50" width="11" height="24" rx="5.500"/><rect class="bt-ear" x="104" y="50" width="11" height="24" rx="5.500"/>
      <path d="M32 90l-10 24 28-16z" fill="#2fa870"/>
      <rect x="14" y="24" width="92" height="74" rx="30" fill="url(#btGrad${n})"/>
      <rect class="bt-screen" x="26" y="38" width="68" height="46" rx="20"/>
      <g class="bt-eyes"><ellipse class="bt-eye" cx="47" cy="58" rx="6" ry="8"/><ellipse class="bt-eye" cx="73" cy="58" rx="6" ry="8"/></g>
      <path class="bt-mouth" d="M51 70q9 8 18 0"/>
      <g class="bt-dots"><circle cx="46" cy="61" r="4.500"/><circle cx="60" cy="61" r="4.500"/><circle cx="74" cy="61" r="4.500"/></g>
      <circle class="bt-cheek" cx="35" cy="72" r="4.500"/><circle class="bt-cheek" cx="85" cy="72" r="4.500"/>
    </g></svg>`;
}
