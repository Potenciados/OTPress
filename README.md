# OTPress

Self-hosted, dependency-light authentication for WordPress & WooCommerce.
Phone OTP, Google Sign-In and email link via Firebase Authentication, plus
classic password login — with your theme owning 100% of the markup and CSS.

Built as an alternative to the Digits plugin, with transparent migration for
existing Digits user bases.

## Why

- **No update roulette.** The auth engine lives in your repo, versioned and
  reviewable. No third-party plugin auto-update can break your login page.
- **Theme-owned UI.** The plugin ships no styled markup on your custom pages.
  Your theme renders its own form and talks to a small ES-module API. A
  minimal `[otpress_form]` shortcode exists for sites without a custom theme.
- **Verified identity only.** Firebase ID tokens are verified server-side
  (RS256 against Google's published certificates — algorithm pinned, no JWT
  library dependency) with strict `iss`/`aud`/`exp`/`sub` checks. Email
  claims are only trusted when `email_verified` is true.
- **Digits migration built in.** Verified phone numbers are matched against
  `digits_phone` usermeta (configurable), so an existing Digits user base
  keeps signing in with the same phone numbers — same Firebase project, same
  UX, zero data migration.
- **WooCommerce aware.** Logins fire `wp_login`, so persistent carts merge
  and session-dependent plugins behave exactly as with wp-login.php.

## How it works

1. Front end signs the user in with Firebase (phone OTP / Google popup) and
   obtains an ID token, or collects classic credentials.
2. `POST /wp-json/otpress/v1/login/firebase` (or `/login/password`) verifies
   and maps to a WordPress user — by verified phone, then verified email —
   creating a customer account when allowed.
3. The plugin sets standard WordPress auth cookies and returns a validated
   redirect URL.

CSRF protection uses a mandatory custom header (`X-OTPress: 1`) plus an
Origin check instead of nonces, so login pages remain compatible with
full-page edge caching (nonces baked into cached HTML go stale; custom
headers don't).

## Configuration

Settings → OTPress, or constants (which lock the corresponding field):

| Constant | Meaning |
| --- | --- |
| `OTPRESS_FIREBASE_API_KEY` | Firebase web API key (public identifier) |
| `OTPRESS_FIREBASE_AUTH_DOMAIN` | e.g. `your-project.firebaseapp.com` |
| `OTPRESS_FIREBASE_PROJECT_ID` | Firebase project id |
| `OTPRESS_PHONE_META_KEYS` | Comma-separated usermeta keys for phone matching |
| `OTPRESS_DEFAULT_ROLE` | Role for auto-created users |

Firebase console prerequisites: enable the Phone and Google sign-in
providers, and add your domain to Authentication → Authorized domains.

## Theme integration

```php
// On your auth template:
\OTPress_Frontend::boot(); // enqueues the ES module + prints window.OTPRESS
```

```js
import * as OTPress from '/app/plugins/otpress/assets/js/otpress.js';

await OTPress.loginPassword({ identifier, password, redirectTo });
await OTPress.googleLogin({ redirectTo });
await OTPress.phoneStart('+34600000000', recaptchaContainerEl);
await OTPress.phoneConfirm(code, { redirectTo, displayName });
```

Hooks: `otpress_resolve_user`, `otpress_allow_registration`,
`otpress_user_created`, `otpress_login_redirect`, `otpress_phone_meta_keys`.

## License

[PolyForm Noncommercial 1.0.0](LICENSE.md) — free for any noncommercial use.

Note for WordPress distribution: WordPress plugin PHP that links WordPress
APIs is commonly considered GPL-derivative; PolyForm-NC is not
GPL-compatible, which precludes wordpress.org distribution in this form. If
this project later needs a FOSS release, relicensing to GPL-2.0-or-later by
the copyright holder is the intended path.
