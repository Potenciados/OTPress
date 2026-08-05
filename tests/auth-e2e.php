<?php
/**
 * OTPress auth end-to-end / decision-path harness.
 * Run: wp eval-file otpress_auth_e2e.php --path=web/wp
 *
 * Drives the security-critical server-side auth logic through every
 * identity-resolution and REST decision branch with assertions. Creates
 * temp users (tagged), cleans them up. No external OTP/email/SMS sent.
 */

if (!defined('ABSPATH')) { fwrite(STDERR, "must run via wp eval-file\n"); exit(1); }
require_once ABSPATH . 'wp-admin/includes/user.php';
rest_get_server(); // force REST route registration (rest_api_init)

// Group C submits a wrong password on purpose. Firing wp_login_failed would
// page the Discord error-alert plugin (2 Medium alerts per run), so detach
// login listeners for this one-off CLI process only — it does not touch the
// live site's hooks. If you need a REAL authenticated session in a test,
// use the E2E Login Bridge instead of password signon:
//   mu-plugin e2e-login.php -> POST /wp-json/fy-e2e/v1/login
//   header X-E2E-Token: <E2E_LOGIN_TOKEN from bedrock/.env>
//   requires ALLOW_E2E_LOGIN=1 (temp) + user meta _e2e_test_user=1
remove_all_actions('wp_login_failed');
remove_all_actions('wp_login');

$TAG = 'e2etest_' . substr(md5(uniqid('', true)), 0, 8);
$GLOBALS["MADE"] = [];           // user ids to delete
$GLOBALS["PASS"] = 0; $GLOBALS["FAIL"] = 0; $GLOBALS["FAILS"] = [];

function t_ok($cond, $label) {
    global $PASS, $FAIL, $FAILS;
    if ($cond) { $PASS++; echo "  PASS  $label\n"; }
    else { $FAIL++; $FAILS[] = $label; echo "  FAIL  $label\n"; }
}
function t_mkuser($tag, $suffix, $email = '', $verified_meta = false) {
    global $MADE;
    $login = $tag . '_' . $suffix;
    $uid = wp_insert_user(['user_login' => $login, 'user_pass' => wp_generate_password(20), 'user_email' => $email, 'role' => 'customer']);
    if (is_wp_error($uid)) { return $uid; }
    $GLOBALS["MADE"][] = $uid;
    if ($verified_meta && $email) { update_user_meta($uid, 'otpress_email_verified', $email); }
    return $uid;
}
function t_claims($a) { // fill firebase.sign_in_provider wrapper
    if (isset($a['provider'])) { $a['firebase'] = ['sign_in_provider' => $a['provider']]; unset($a['provider']); }
    return $a;
}
function t_dispatch($route, $body, $headers = ['x-otpress' => '1']) {
    $req = new WP_REST_Request('POST', '/otpress/v1' . $route);
    foreach ($headers as $k => $v) { $req->set_header($k, $v); }
    $req->set_header('content-type', 'application/json');
    $req->set_body(wp_json_encode($body));
    $res = rest_do_request($req);
    return [$res->get_status(), (array) $res->get_data()];
}
function t_make_ticket(array $claims) { // mirror issue_link_ticket()
    $id = wp_generate_password(40, false, false);
    set_transient('otpress_link_' . $id, $claims, 600);
    return $id;
}
function t_totp_now($secret) {
    $rc = new ReflectionClass('OTPress_TOTP');
    $b32 = $rc->getMethod('base32_decode'); $b32->setAccessible(true);
    $hotp = $rc->getMethod('hotp'); $hotp->setAccessible(true);
    $period = $rc->getConstant('PERIOD');
    $key = $b32->invoke(null, $secret);
    return $hotp->invoke(null, $key, (int) floor(time() / $period));
}
function t_is_user($u) { return $u instanceof WP_User; }
function t_errcode($u) { return is_wp_error($u) ? $u->get_error_code() : '(not-error:' . (t_is_user($u) ? 'user#' . $u->ID : gettype($u)) . ')'; }

echo "=== OTPress auth e2e  tag=$TAG ===\n";

/* ---------- GROUP A: Mapper::resolve identity precedence & create ---------- */
echo "\n[A] Mapper::resolve + create_user\n";

// A1 verified email matches existing
$e1 = "$TAG+a1@example.test";
$u1 = t_mkuser($TAG, 'a1', $e1);
$r = OTPress_User_Mapper::resolve(t_claims(['email' => $e1, 'email_verified' => true]), [], true);
t_ok(t_is_user($r) && $r->ID === $u1, "A1 verified-email matches existing user (got " . t_errcode($r) . ")");

// A2 verified email, no user, auto-create -> creates with that email
$e2 = "$TAG+a2@example.test";
$r = OTPress_User_Mapper::resolve(t_claims(['email' => $e2, 'email_verified' => true, 'sub' => "sub_{$TAG}_a2", 'provider' => 'google.com']), [], true);
if (t_is_user($r)) { $GLOBALS["MADE"][] = $r->ID; }
t_ok(t_is_user($r) && strtolower($r->user_email) === strtolower($e2), "A2 verified-email new -> creates with email set");

// A3 UNVERIFIED email colliding with existing account -> refuse (no takeover)
$e3 = "$TAG+a3@example.test";
$u3 = t_mkuser($TAG, 'a3', $e3);
$r = OTPress_User_Mapper::resolve(t_claims(['email' => $e3, 'email_verified' => false, 'sub' => "attacker_$TAG", 'provider' => 'facebook.com']), [], true);
t_ok(is_wp_error($r) && $r->get_error_code() === 'otpress_email_unverified', "A3 unverified-email collision -> otpress_email_unverified (got " . t_errcode($r) . ")");

// A4 UNVERIFIED email, NO existing account, create -> via sub; user_email EMPTY (no seeding)
$e4 = "$TAG+a4@example.test";
$sub4 = "sub_a4_$TAG";
$r = OTPress_User_Mapper::resolve(t_claims(['email' => $e4, 'email_verified' => false, 'sub' => $sub4, 'provider' => 'facebook.com']), [], true);
if (t_is_user($r)) { $GLOBALS["MADE"][] = $r->ID; }
$a4_uid_meta = t_is_user($r) ? get_user_meta($r->ID, 'otpress_firebase_uid', false) : [];
t_ok(t_is_user($r), "A4 unverified-email new -> account created via sub (got " . t_errcode($r) . ")");
t_ok(t_is_user($r) && $r->user_email === '', "A4 unverified email NOT written to user_email (no seed/takeover)");
t_ok(t_is_user($r) && in_array($sub4, (array) $a4_uid_meta, true), "A4 firebase_uid stored for future direct resolve");

// A5 sub match wins over differing email
$u5 = t_mkuser($TAG, 'a5', "$TAG+a5@example.test");
$sub5 = "sub_a5_$TAG";
add_user_meta($u5, 'otpress_firebase_uid', $sub5);
$r = OTPress_User_Mapper::resolve(t_claims(['sub' => $sub5, 'email' => "totally-different+$TAG@example.test", 'email_verified' => true, 'provider' => 'microsoft.com']), [], true);
t_ok(t_is_user($r) && $r->ID === $u5, "A5 linked sub resolves to its user regardless of email");

// A6 phone match
$u6 = t_mkuser($TAG, 'a6');
update_user_meta($u6, 'otpress_phone', '+15550000006');
$r = OTPress_User_Mapper::resolve(t_claims(['phone_number' => '+15550000006']), [], true);
t_ok(t_is_user($r) && $r->ID === $u6, "A6 verified phone matches existing user");

// A7 sub-only new identity (Microsoft/Facebook no email/phone) -> creates (THE FIX)
$sub7 = "sub_a7_$TAG";
$r = OTPress_User_Mapper::resolve(t_claims(['sub' => $sub7, 'provider' => 'microsoft.com', 'name' => 'Gex Deal']), ['display_name' => 'Gex Deal'], true);
if (t_is_user($r)) { $GLOBALS["MADE"][] = $r->ID; }
t_ok(t_is_user($r), "A7 sub-only identity -> account created (Microsoft/FB fix) (got " . t_errcode($r) . ")");
t_ok(t_is_user($r) && in_array($sub7, (array) get_user_meta($r->ID, 'otpress_firebase_uid', false), true), "A7 sub stored on created account");

// A8 nothing to key on (no sub/email/phone) + create -> still refuse
$r = OTPress_User_Mapper::resolve(t_claims(['provider' => 'microsoft.com']), [], true);
t_ok(is_wp_error($r) && $r->get_error_code() === 'otpress_no_identity', "A8 no sub/email/phone -> otpress_no_identity (got " . t_errcode($r) . ")");

// A9 auto_create=false, no match -> otpress_no_match (drives link_choice)
$r = OTPress_User_Mapper::resolve(t_claims(['sub' => "nomatch_$TAG", 'provider' => 'google.com']), [], false);
t_ok(is_wp_error($r) && $r->get_error_code() === 'otpress_no_match', "A9 no-match + no-create -> otpress_no_match (got " . t_errcode($r) . ")");

// A10 verified-email create is idempotent (no duplicate account)
$e10 = "$TAG+a10@example.test";
$r1 = OTPress_User_Mapper::resolve(t_claims(['email' => $e10, 'email_verified' => true, 'sub' => "s10a_$TAG", 'provider' => 'google.com']), [], true);
if (t_is_user($r1)) { $GLOBALS["MADE"][] = $r1->ID; }
$r2 = OTPress_User_Mapper::resolve(t_claims(['email' => $e10, 'email_verified' => true, 'sub' => "s10b_$TAG", 'provider' => 'microsoft.com']), [], true);
t_ok(t_is_user($r1) && t_is_user($r2) && $r1->ID === $r2->ID, "A10 same verified email -> same account (no dup)");

/* ---------- GROUP B: REST /login/firebase via ticket seam (real handler) ---------- */
echo "\n[B] REST /login/firebase decision branches\n";

// B1 sub-only new identity, mode=create -> ok=true (session granted)
$tkt = t_make_ticket(t_claims(['sub' => "b1_$TAG", 'provider' => 'microsoft.com', 'name' => 'B1 User']));
list($st, $d) = t_dispatch('/login/firebase', ['ticket' => $tkt, 'mode' => 'create', 'redirect_to' => '']);
if (!empty($d['user'])) { $ux = get_user_by('login', $TAG); }
// capture created user for cleanup
$b1u = get_users(['meta_key' => 'otpress_firebase_uid', 'meta_value' => "b1_$TAG", 'number' => 1]);
if ($b1u) { $GLOBALS["MADE"][] = $b1u[0]->ID; }
t_ok($st === 200 && !empty($d['ok']) && $d['ok'] === true, "B1 create-mode sub-only -> ok=true (status $st, code " . ($d['code'] ?? '-') . ")");

// B2 new identity, NO create mode -> link_choice
$tkt = t_make_ticket(t_claims(['sub' => "b2_$TAG", 'email' => "$TAG+b2@example.test", 'email_verified' => true, 'provider' => 'google.com']));
list($st, $d) = t_dispatch('/login/firebase', ['ticket' => $tkt, 'redirect_to' => '']);
t_ok(($d['code'] ?? '') === 'otpress_link_choice' && !empty($d['ticket']), "B2 no-match no-create -> otpress_link_choice + ticket");

// B3 unverified email colliding existing -> email_unverified branch
$e_b3 = "$TAG+b3@example.test";
$ub3 = t_mkuser($TAG, 'b3', $e_b3);
$tkt = t_make_ticket(t_claims(['sub' => "b3_$TAG", 'email' => $e_b3, 'email_verified' => false, 'provider' => 'facebook.com']));
list($st, $d) = t_dispatch('/login/firebase', ['ticket' => $tkt, 'mode' => 'create', 'redirect_to' => '']);
t_ok(($d['code'] ?? '') === 'otpress_email_unverified' && !empty($d['ticket']), "B3 unverified-collision -> otpress_email_unverified + ticket");

// B4 no id_token + no ticket -> 400 bad request
list($st, $d) = t_dispatch('/login/firebase', ['redirect_to' => '']);
t_ok($st === 400, "B4 missing credentials -> 400 (status $st)");

// B5 bogus ticket (no transient) + no token -> ticket expired 401
list($st, $d) = t_dispatch('/login/firebase', ['ticket' => wp_generate_password(40, false, false), 'mode' => 'create']);
t_ok($st === 401 && ($d['code'] ?? '') === 'otpress_ticket_expired', "B5 expired/unknown ticket -> 401 otpress_ticket_expired");

// B6 create resolves to a TOTP-enabled user -> 2FA gate, NO session
$ub6 = t_mkuser($TAG, 'b6', "$TAG+b6@example.test");
$sub_b6 = "b6_$TAG";
add_user_meta($ub6, 'otpress_firebase_uid', $sub_b6);
$sec_b6 = OTPress_TOTP::generate_secret();
OTPress_TOTP::enroll($ub6, $sec_b6);
$tkt = t_make_ticket(t_claims(['sub' => $sub_b6, 'provider' => 'google.com']));
list($st, $d) = t_dispatch('/login/firebase', ['ticket' => $tkt, 'mode' => 'create']);
t_ok(($d['code'] ?? '') === 'otpress_2fa_required' && !empty($d['ticket']) && empty($d['ok']), "B6 TOTP user -> otpress_2fa_required (session withheld)");
$b6_2fa_ticket = $d['ticket'] ?? '';

/* ---------- GROUP C: password login credential logic + Turnstile enforcement ---------- */
echo "\n[C] Password login\n";
$pw = 'Correct-Horse-9';
$uc = t_mkuser($TAG, 'c1', "$TAG+c1@example.test");
wp_set_password($pw, $uc);
update_user_meta($uc, 'otpress_password_login', '1');

// C1 correct password + flag enabled -> signon success
$signon = wp_signon(['user_login' => $TAG . '_c1', 'user_password' => $pw], false);
t_ok(t_is_user($signon) && $signon->ID === $uc, "C1 wp_signon correct password -> user");

// C2 wrong password -> error
$signon = wp_signon(['user_login' => $TAG . '_c1', 'user_password' => 'wrong'], false);
t_ok(is_wp_error($signon), "C2 wrong password -> WP_Error");

// C3 password_allowed false for non-admin without flag
$uc3 = t_mkuser($TAG, 'c3', "$TAG+c3@example.test");
$rc = new ReflectionMethod('OTPress_REST', 'password_allowed');
$rc->setAccessible(true);
t_ok($rc->invoke(null, get_user_by('id', $uc3)) === false, "C3 password_allowed=false without opt-in flag (no enumeration)");
t_ok($rc->invoke(null, get_user_by('id', $uc)) === true, "C3b password_allowed=true with flag");

// C4 Turnstile ENFORCED at REST when no logged-in cookie + no token
list($st, $d) = t_dispatch('/login/password', ['identifier' => $TAG . '_c1', 'password' => $pw]);
t_ok($st === 403 && ($d['code'] ?? '') === 'otpress_challenge', "C4 password REST w/o Turnstile token -> 403 otpress_challenge (bot gate enforced)");

/* ---------- GROUP D: token verifier rejects junk ---------- */
echo "\n[D] Token verifier reject paths\n";
$bad = [
    'D1 empty' => '',
    'D2 garbage' => 'not-a-jwt',
    'D3 two-part' => base64_encode('{"alg":"none"}') . '.' . base64_encode('{"sub":"x"}'),
    'D4 unsigned RS256 wrong-aud' => (function () {
        $h = rtrim(strtr(base64_encode('{"alg":"RS256","kid":"fake"}'), '+/', '-_'), '=');
        $p = rtrim(strtr(base64_encode(wp_json_encode(['aud' => 'wrong', 'iss' => 'https://evil', 'sub' => 'x', 'exp' => time() + 999, 'iat' => time()])), '+/', '-_'), '=');
        return "$h.$p.AAAA";
    })(),
];
foreach ($bad as $label => $tok) {
    $r = OTPress_Token_Verifier::verify($tok);
    t_ok(is_wp_error($r), "$label -> rejected");
}

/* ---------- GROUP E: email-OTP verify attaches identity (link path) ---------- */
echo "\n[E] Email-OTP link + identities\n";
// resolve verified email -> existing user, then link_identity attaches a federated sub
$e_e1 = "$TAG+e1@example.test";
$ue = t_mkuser($TAG, 'e1', $e_e1, true);
$before = OTPress_User_Mapper::get_identities($ue);
OTPress_User_Mapper::link_identity($ue, t_claims(['sub' => "linked_$TAG", 'email' => $e_e1, 'email_verified' => true, 'provider' => 'microsoft.com']));
$after = OTPress_User_Mapper::get_identities($ue);
$has = false; foreach ($after as $row) { if (($row['sub'] ?? '') === "linked_$TAG") { $has = true; } }
t_ok($has && count($after) === count($before) + 1, "E1 link_identity attaches federated sub to email-verified account");
$rlk = OTPress_User_Mapper::resolve(t_claims(['sub' => "linked_$TAG", 'provider' => 'microsoft.com']), [], false);
t_ok(t_is_user($rlk) && $rlk->ID === $ue, "E2 subsequent sign-in resolves directly via linked sub (auto_create=false)");

/* ---------- GROUP F: TOTP second factor ---------- */
echo "\n[F] TOTP verify\n";
// F1 valid live code on the B6 2FA ticket -> success + session
if ($b6_2fa_ticket) {
    list($st, $d) = t_dispatch('/totp/verify', ['ticket' => $b6_2fa_ticket, 'code' => t_totp_now($sec_b6), 'redirect_to' => '']);
    t_ok($st === 200 && !empty($d['ok']), "F1 valid TOTP code completes 2FA -> ok=true (status $st, code " . ($d['code'] ?? '-') . ")");
} else { t_ok(false, "F1 skipped: no 2FA ticket from B6"); }
// F2 wrong code -> 401
$sec_f = OTPress_TOTP::generate_secret();
$uf = t_mkuser($TAG, 'f2', "$TAG+f2@example.test");
OTPress_TOTP::enroll($uf, $sec_f);
$tk2 = wp_generate_password(40, false, false);
set_transient('otpress_2fa_' . $tk2, ['user_id' => $uf, 'remember' => false, 'redirect' => ''], 600);
list($st, $d) = t_dispatch('/totp/verify', ['ticket' => $tk2, 'code' => '000000']);
t_ok($st === 401 && ($d['code'] ?? '') === 'otpress_2fa_invalid', "F2 wrong TOTP code -> 401 otpress_2fa_invalid");
// F3 expired/unknown 2fa ticket -> 401 expired
list($st, $d) = t_dispatch('/totp/verify', ['ticket' => wp_generate_password(40, false, false), 'code' => '123456']);
t_ok($st === 401 && ($d['code'] ?? '') === 'otpress_2fa_expired', "F3 unknown 2FA ticket -> 401 otpress_2fa_expired");
// F4 TOTP self-verify sanity
t_ok(OTPress_TOTP::verify($sec_f, t_totp_now($sec_f)) === true, "F4 TOTP verify accepts live code");
t_ok(OTPress_TOTP::verify($sec_f, '000000') === false || t_totp_now($sec_f) === '000000', "F4b TOTP verify rejects wrong code");

/* ---------- GROUP G: unlink safety ---------- */
echo "\n[G] Identity unlink\n";
$ug = t_mkuser($TAG, 'g1', "$TAG+g1@example.test", true);
OTPress_User_Mapper::link_identity($ug, t_claims(['sub' => "g_sub_$TAG", 'provider' => 'google.com', 'email' => "$TAG+g1@example.test", 'email_verified' => true]));
$un = OTPress_User_Mapper::unlink_identity($ug, "g_sub_$TAG");
t_ok($un === true, "G1 unlink linked sub -> true");
$un2 = OTPress_User_Mapper::unlink_identity($ug, "does_not_exist_$TAG");
t_ok(is_wp_error($un2) && $un2->get_error_code() === 'otpress_no_identity', "G2 unlink unknown sub -> otpress_no_identity");
t_ok(!in_array("g_sub_$TAG", (array) get_user_meta($ug, 'otpress_firebase_uid', false), true), "G3 uid meta removed after unlink");

/* ---------- CLEANUP ---------- */
echo "\n[cleanup] deleting " . count(array_unique($GLOBALS["MADE"])) . " test users\n";
foreach (array_unique($GLOBALS["MADE"]) as $id) { wp_delete_user($id); }

echo "\n=== RESULT: {$GLOBALS['PASS']} passed, {$GLOBALS['FAIL']} failed ===\n";
if ($GLOBALS["FAIL"]) { echo "FAILED:\n - " . implode("\n - ", $GLOBALS["FAILS"]) . "\n"; }
exit($GLOBALS["FAIL"] ? 1 : 0);
