# OTPress Roadmap

Feature comparison against Digits (digits.unitedover.com, v9.x, 2026) and the
resulting priorities. OTPress deliberately stays small: the engine is ~600
lines of auditable PHP with zero runtime dependencies. Features that mostly
exist to sell subscriptions (drag-and-drop form builders, 200-gateway
matrices) are explicitly out of scope — themes own the UI, Firebase owns
delivery.

## Where OTPress already matches or beats Digits

| Capability | Digits | OTPress |
| --- | --- | --- |
| Phone OTP login/registration | ✔ (25+ gateways) | ✔ via Firebase (Google-run SMS delivery, fraud protection, reCAPTCHA baked in) |
| Google Sign-In | ✔ | ✔ (Firebase provider) |
| Classic password login | ✔ | ✔ (`wp_signon` passthrough — WP stays source of truth) |
| WooCommerce cart merge / login hooks | ✔ | ✔ (fires `wp_login` like wp-login.php) |
| Custom-styled forms | Form builder UI | Theme-owned markup + ES module API (no builder lock-in) |
| Extensibility | Hooks | Hooks (`otpress_resolve_user`, `otpress_login_redirect`, …) |
| Data ownership | WP database | WP database, plus plugin lives in *your* git |
| Edge-cache-safe login | ✖ (nonce-based) | ✔ (custom-header CSRF, no nonces in cached HTML) |
| Verified-email enforcement | unclear | ✔ (`email_verified` required for email mapping) |
| Digits migration | — | ✔ built-in usermeta compat |

## Parity gaps → prioritized

### P1 — next (each small, high value)
- **Email magic link** (Firebase `sendSignInLinkToEmail`): passwordless email
  login/registration. Closes the "email OTP" gap without building an OTP
  mailer. JS + one template hook; server side already handles the token.
- **More social providers via Firebase console**: Apple, Facebook, GitHub,
  Microsoft are config + one `authMod.<Provider>` line each. Ship a provider
  allowlist setting so sites toggle buttons without code.
- **WooCommerce checkout phone verification** (Digits' strongest Woo
  feature): optional "verify phone before placing order" gate, reusing the
  same phoneStart/phoneConfirm flow inline at checkout.
- **Login/OTP event log** (lightweight table or CPT, retention-capped):
  needed for support and abuse forensics. Digits ships SMS/email logs.

### P2 — worth doing, not urgent
- **Passkeys / WebAuthn**: Digits ships this; real differentiator for
  password-free trust. WP has mature libs (`web-auth/webauthn-lib`) but it
  adds a dependency — gate behind a build flag or sub-module.
- **TOTP 2FA (authenticator apps)** for admins/roles: small, self-contained
  (RFC 6238 is ~50 lines), pairs well with the existing token flow.
- **WhatsApp OTP**: Digits markets "zero-cost WhatsApp OTP". Firebase does
  not deliver WhatsApp; would need Meta Cloud API integration (template
  message + webhook). Do only if SMS costs actually hurt.
- **Admin UX**: search users by phone in admin, phone column on the Woo
  order screen (Digits parity, trivial).
- **wp-login.php takeover mode** for sites without a custom auth page
  (render `[otpress_form]` on wp-login.php, hide password fields).

### P3 — deliberately NOT building
- **Drag-and-drop form builder / Elementor widgets**: themes own markup;
  builders are the source of the fragility OTPress exists to remove.
- **25–200 SMS gateway matrix**: Firebase is the delivery layer. One
  well-tested path beats a gateway zoo. (A `otpress_deliver_otp` filter can
  host third-party gateways if someone truly needs one.)
- **Multi-step signup forms / conditional logic**: application-level UX,
  not auth-engine scope.
- **Remote QR login, Slack/Spotify/TikTok providers**: niche; Firebase
  custom OAuth covers them if ever needed.

## Non-feature roadmap
- Unit tests for token verifier (kid rotation, expired/foreign-audience
  tokens) + Playwright reference flow.
- `uninstall.php` (options + transients cleanup).
- i18n `.pot` generation; translations ship per-site (Polylang/WPML docs).
- Decide public licensing story (PolyForm-NC vs GPL) before any wp.org or
  marketplace distribution — see README note.
