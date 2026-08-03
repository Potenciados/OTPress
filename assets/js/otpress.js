/**
 * OTPress front-end module.
 *
 * Framework-agnostic ES module. Reads boot config from `window.OTPRESS`
 * (printed by OTPress_Frontend::print_config). The Firebase SDK is imported
 * lazily so password-only sign-ins never pay its download cost.
 */

const cfg = () => {
  if (!window.OTPRESS) throw new Error('OTPress config missing');
  return window.OTPRESS;
};

let firebasePromise = null;
let confirmation = null;
let recaptcha = null;

const FIREBASE_VERSION = '10.14.1';
const gstatic = (mod) =>
  `https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/${mod}`;

async function ensureFirebase() {
  if (!firebasePromise) {
    firebasePromise = (async () => {
      const [{ initializeApp }, authMod] = await Promise.all([
        import(gstatic('firebase-app.js')),
        import(gstatic('firebase-auth.js')),
      ]);
      const app = initializeApp(cfg().firebase);
      const auth = authMod.getAuth(app);
      auth.useDeviceLanguage();
      return { auth, authMod };
    })();
  }
  return firebasePromise;
}

async function post(path, body) {
  const res = await fetch(`${cfg().restUrl}${path}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-OTPress': '1' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.ok) {
    const err = new Error(data.message || cfg().i18n.genericError);
    err.otpressCode = data.code || '';
    err.ticket = data.ticket || '';
    err.providerEmail = data.email || '';
    throw err;
  }
  return data;
}

async function finishWithCredential(userCredential, { redirectTo = '', profile = {} } = {}) {
  const idToken = await userCredential.user.getIdToken();
  return post('/login/firebase', {
    id_token: idToken,
    redirect_to: redirectTo,
    profile,
  });
}

/** Classic username / email / phone + password login through WordPress. */
export async function loginPassword({ identifier, password, remember = true, redirectTo = '', challengeToken = '' }) {
  return post('/login/password', {
    identifier,
    password,
    remember,
    redirect_to: redirectTo,
    challenge_token: challengeToken,
  });
}

/** Email OTP, step 1: send a six-digit code to the address. No Firebase involved. */
export async function emailOtpStart({ email, challengeToken = '' }) {
  return post('/email-otp/start', { email, challenge_token: challengeToken });
}

/**
 * Email OTP, step 2: verify the code and complete WordPress login. Pass
 * `linkTicket` (from a sign-in attempt that answered `otpress_link_choice`)
 * to also attach that federated identity to the account being proven.
 */
export async function emailOtpVerify({ email, code, remember = true, redirectTo = '', displayName = '', linkTicket = '' }) {
  return post('/email-otp/verify', {
    email,
    code,
    link_ticket: linkTicket,
    remember,
    redirect_to: redirectTo,
    profile: displayName ? { display_name: displayName } : {},
  });
}

/**
 * Complete a sign-in that answered `otpress_link_choice` by creating a NEW
 * account from the already-verified claims held by the ticket.
 */
export async function providerCreate({ ticket, redirectTo = '', displayName = '' }) {
  return post('/login/firebase', {
    ticket,
    mode: 'create',
    redirect_to: redirectTo,
    profile: displayName ? { display_name: displayName } : {},
  });
}

/** WhatsApp OTP, step 1: send a six-digit code via WhatsApp. */
export async function whatsappOtpStart({ phone, challengeToken = '' }) {
  return post('/whatsapp-otp/start', { phone, challenge_token: challengeToken });
}

/** WhatsApp OTP, step 2: verify the code and complete WordPress login. */
export async function whatsappOtpVerify({ phone, code, remember = true, redirectTo = '', linkTicket = '' }) {
  return post('/whatsapp-otp/verify', {
    phone,
    code,
    link_ticket: linkTicket,
    remember,
    redirect_to: redirectTo,
  });
}

/**
 * Federated sign-in via Firebase popup. Supported providerIds:
 * 'google.com', 'facebook.com', 'microsoft.com'. On server-side rejection
 * the thrown Error carries `otpressCode` and `email` (when the provider
 * returned one), letting UIs run fallback flows such as an email-OTP
 * ownership challenge for providers with unverified emails (Facebook).
 */
const PROVIDER_FACTORIES = {
  'google.com': (m) => new m.GoogleAuthProvider(),
  'facebook.com': (m) => {
    const p = new m.FacebookAuthProvider();
    p.addScope('email');
    return p;
  },
  'microsoft.com': (m) => new m.OAuthProvider('microsoft.com'),
};

export async function providerLogin(providerId, { redirectTo = '' } = {}) {
  const factory = PROVIDER_FACTORIES[providerId];
  if (!factory) throw new Error(`Unknown provider: ${providerId}`);
  const { auth, authMod } = await ensureFirebase();
  const credential = await authMod.signInWithPopup(auth, factory(authMod));
  try {
    return await finishWithCredential(credential, { redirectTo });
  } catch (err) {
    err.email = (credential.user && credential.user.email) || '';
    throw err;
  }
}

/** Google Sign-In via Firebase popup. */
export async function googleLogin(opts = {}) {
  return providerLogin('google.com', opts);
}

/**
 * Start phone sign-in: sends the SMS code. `recaptchaContainer` is a DOM
 * element or id for Firebase's (invisible) reCAPTCHA app verification.
 */
export async function phoneStart(phoneE164, recaptchaContainer) {
  const { auth, authMod } = await ensureFirebase();
  if (!recaptcha) {
    recaptcha = new authMod.RecaptchaVerifier(auth, recaptchaContainer, { size: 'invisible' });
  }
  confirmation = await authMod.signInWithPhoneNumber(auth, phoneE164, recaptcha);
  return true;
}

/** Confirm the SMS code and complete WordPress login. */
export async function phoneConfirm(code, { redirectTo = '', displayName = '' } = {}) {
  if (!confirmation) throw new Error('phoneStart must run first');
  const credential = await confirmation.confirm(code.trim());
  return finishWithCredential(credential, {
    redirectTo,
    profile: displayName ? { display_name: displayName } : {},
  });
}

export async function logout() {
  return post('/logout', {});
}

/** List the logged-in user's linked social/phone identities. */
export async function listIdentities() {
  const res = await fetch(`${cfg().restUrl}/identities`, {
    credentials: 'same-origin', headers: { 'X-OTPress': '1' },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.ok) throw new Error(data.message || cfg().i18n.genericError);
  return data.identities || [];
}

/** Link a federated provider to the current account (opens its popup). */
export async function linkProvider(providerId) {
  const factory = PROVIDER_FACTORIES[providerId];
  if (!factory) throw new Error(`Unknown provider: ${providerId}`);
  const { auth, authMod } = await ensureFirebase();
  const credential = await authMod.signInWithPopup(auth, factory(authMod));
  const idToken = await credential.user.getIdToken();
  return post('/identities/link', { id_token: idToken });
}

/** Unlink a federated identity by its Firebase uid. */
export async function unlinkIdentity(sub) {
  return post('/identities/unlink', { sub });
}

/** Complete a login gated by 2FA: submit the TOTP (or recovery) code + ticket. */
export async function totpVerify({ ticket, code }) {
  return post('/totp/verify', { ticket, code });
}

/** Begin TOTP enrollment: returns { secret, uri } for the QR. */
export async function totpEnrollStart() {
  return post('/totp/enroll/start', {});
}

/** Confirm TOTP enrollment with a code; returns { recovery_codes }. */
export async function totpEnrollConfirm(code) {
  return post('/totp/enroll/confirm', { code });
}

/** Disable TOTP (requires a current code). */
export async function totpDisable(code) {
  return post('/totp/disable', { code });
}

/** Acknowledge a one-time proactive invitation ('2fa' | 'passkey') so it never reappears. */
export async function ackPrompt(name) {
  return post('/prompts/ack', { name });
}

// --- Change email (dual OTP) ---
/** Step 1: send a code to the current address. Returns { ticket, email }. */
export async function emailChangeStart() {
  return post('/email/change/start', {});
}
/** Step 2: prove the current address with its code. */
export async function emailChangeVerifyCurrent({ ticket, code }) {
  return post('/email/change/verify-current', { ticket, code });
}
/** Step 3: submit the new address; a code is sent to it. */
export async function emailChangeSendNew({ ticket, email }) {
  return post('/email/change/send-new', { ticket, email });
}
/** Step 4: prove the new address with its code; the swap happens server-side. */
export async function emailChangeConfirm({ ticket, code }) {
  return post('/email/change/confirm', { ticket, code });
}

// --- Passkeys (WebAuthn) -------------------------------------------------

/** ArrayBuffer / Uint8Array -> unpadded base64url string. */
export function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url string -> ArrayBuffer. */
export function b64urlToBuf(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

/** True when this browser exposes the WebAuthn platform API. */
export function passkeySupported() {
  return typeof window !== 'undefined'
    && !!window.PublicKeyCredential
    && typeof navigator !== 'undefined'
    && !!(navigator.credentials && navigator.credentials.create);
}

/**
 * Register a new passkey for the logged-in user. Fetches creation options,
 * calls navigator.credentials.create(), and posts the attestation back.
 * Returns { ok, passkeys }.
 */
export async function passkeyRegister(friendlyName = '') {
  const { options } = await post('/passkey/register/options', {});
  const publicKey = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    user: { ...options.user, id: b64urlToBuf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({
      ...c, id: b64urlToBuf(c.id),
    })),
  };
  const cred = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error(cfg().i18n.genericError);
  return post('/passkey/register/verify', {
    name: friendlyName,
    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    attestationObject: bufToB64url(cred.response.attestationObject),
  });
}

/**
 * Authenticate with a passkey. Pass an `email` to scope the credential list,
 * or omit it for a discoverable (usernameless) sign-in. `mediation` may be
 * 'conditional' for autofill-style UI. Returns the standard { ok, redirect,
 * prompts } login shape so an auth modal's `go()` handler works unchanged.
 */
export async function passkeyAuthenticate({ email = '', redirectTo = '', remember = true, mediation, signal } = {}) {
  const { options } = await post('/passkey/auth/options', { email });
  const publicKey = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({
      ...c, id: b64urlToBuf(c.id),
    })),
  };
  const getOpts = { publicKey };
  if (mediation) getOpts.mediation = mediation;
  if (signal) getOpts.signal = signal;
  const assertion = await navigator.credentials.get(getOpts);
  if (!assertion) throw new Error(cfg().i18n.genericError);
  const r = assertion.response;
  return post('/passkey/auth/verify', {
    handle: options.handle,
    credentialId: assertion.id,
    authenticatorData: bufToB64url(r.authenticatorData),
    clientDataJSON: bufToB64url(r.clientDataJSON),
    signature: bufToB64url(r.signature),
    userHandle: r.userHandle ? bufToB64url(r.userHandle) : '',
    remember,
    redirect_to: redirectTo,
  });
}

/** List the logged-in user's registered passkeys. */
export async function passkeyList() {
  const { passkeys } = await post('/passkey/list', {});
  return passkeys || [];
}

/** Remove one of the user's passkeys by its (base64url) credential id. */
export async function passkeyRemove(id) {
  return post('/passkey/remove', { id });
}

/** Wire up the [otpress_form] default markup. Themes with custom UIs ignore this. */
export function autobind(root = document) {
  root.querySelectorAll('[data-otpress-form]').forEach((form) => {
    const redirectTo = form.dataset.redirect || '';
    const message = form.querySelector('[data-otpress-message]');
    const say = (text) => { if (message) message.textContent = text; };
    const go = (data) => { window.location.assign(data.redirect); };
    const fail = (err) => say(err.message || cfg().i18n.genericError);

    form.querySelector('[data-otpress-password]')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      loginPassword({ identifier: fd.get('identifier'), password: fd.get('password'), redirectTo })
        .then(go, fail);
    });

    form.querySelector('[data-otpress-google]')?.addEventListener('click', () => {
      googleLogin({ redirectTo }).then(go, fail);
    });

    const codeForm = form.querySelector('[data-otpress-code]');
    form.querySelector('[data-otpress-phone]')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const phone = new FormData(e.target).get('phone');
      phoneStart(phone, form.querySelector('[data-otpress-recaptcha]'))
        .then(() => { codeForm.hidden = false; say(cfg().i18n.codeSent); }, fail);
    });

    codeForm?.addEventListener('submit', (e) => {
      e.preventDefault();
      const code = new FormData(e.target).get('code');
      phoneConfirm(code, { redirectTo }).then(go, fail);
    });
  });
}
