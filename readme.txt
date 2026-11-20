=== WM HinSchG Whistleblower Desk ===
Contributors: arnoldwender
Tags: hinschg, whistleblower, meldestelle, encryption, deadlines
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 1.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Internal whistleblowing channel for the German HinSchG: report form, server-side encryption, § 17 deadlines and a keyed audit log.

== Description ==

The plugin provides the written reporting channel of an internal Meldestelle. It does not assess whether an organisation must run one or meets its duties under the HinSchG.

* **Report form & Gutenberg block:** `[wm_whistleblower_portal]`, `[wm_hinschg_portal]` and the Gutenberg block `wm/hinschg-portal` render a form with category and description. No name or e-mail is asked. The IP address is never stored with the report; the rate limiter keeps an hourly-rotated HMAC in a transient for up to one hour.
* **Block Bindings & GenerateBlocks 2.x:** registers the WordPress 6.5+ Block Bindings source `wm-hinschg/status` and the GenerateBlocks 2.x dynamic tag `{{wm_hinschg_status}}`.
* **Case id and access token:** shown once after submitting; with both the person checks the status and exchanges messages with the Meldestelle. Only an HMAC-SHA256 of the token, keyed with the WordPress auth salt, is stored.
* **Encryption at rest:** report and messages are encrypted on the server with AES-256-GCM under a fresh key, sealed with an RSA-4096 public key generated on activation. The browser sends plain JSON over HTTPS.
* **Deadlines & hooks:** acknowledgment = receipt + 7 days, feedback = receipt + 3 months (never later than § 17 Abs. 2). An hourly WP-Cron check fires `wm_hinschg_sla_breach_detected` when a deadline passed; boot fires `wm_hinschg_ready`; portal limits and localized config are filterable via `wm_hinschg_rest_rate_limit` and `wm_hinschg_portal_config`. No e-mail is sent.
* **Desk:** cases with status and deadlines, a case view that decrypts the report and the whole thread (or uses local browser decryption in `offline-custody` mode), direct § 17 receipt confirmation and reply controls (`admin/ack`, `admin/reply`), counters, embed instructions, test report, deadline rules, glossary, dashboard widget, and 28 bundled `.po`/`.mo` + JED `.json` translation catalogs.
* **Private key & dual-envelope backup:** `WM_HINSCHG_PRIVATE_KEY` in `wp-config.php` keeps the key out of the database; `WM_HINSCHG_MASTER_KEY` seals it in `wp_options` with `sodium_crypto_secretbox` (XSalsa20-Poly1305 via HKDF-SHA256) and transparently migrates legacy plaintext keys; `WM_HINSCHG_KEY_PASSPHRASE` stores it OpenSSL-encrypted; and the *Schlüsselverwahrung* tab supports client-side browser key generation (`RSA-OAEP-4096` via `window.crypto.subtle`), downloading the `PKCS#8` private key `.pem` locally in the browser and uploading only the `SPKI` public key (`offline-custody`, with local browser case decryption), plus an optional secondary recovery public key (`wm_hinschg_recovery_public_key`) for a 2nd Meldestelle officer or Ombudsperson (§ 8 Abs. 1, § 15 HinSchG). Officer replies carry a symmetric `reporter_box` (`sodium_crypto_secretbox`) so the token holder can read them in `offline-custody` mode while whistleblower messages remain strictly RSA-OAEP Zero-Knowledge. Fresh activations never write a plaintext PEM to `wp_options` or transients. `wp hinschg key-status` reports the active mode.
* **Who may open a report:** the plugin declares the capability `wm_hinschg_read_cases` and brings the role "Meldestelle (HinSchG)". Who holds it is managed in WordPress or with a role plugin, not here. Administrators get it on install so nobody is locked out; `wp hinschg access` lists the holders and `wp hinschg revoke-access --role=administrator` takes it away once the officer has it. Revoking the last access is refused. Multisite installs initialize new sites automatically via `wp_initialize_site` when network-activated.
* **Audit log:** submission, messages, acknowledgment, feedback, test reports and every case opened by the Meldestelle append an entry under a MySQL advisory lock (`GET_LOCK('wm_hinschg_audit_chain', 0)` with short jitter backoff, returning `503 Retry-After: 2` on contention), keyed with `WM_HINSCHG_AUDIT_KEY` (via HKDF-SHA256, dual-verifying pre-rotation `AUTH_KEY` entries) or `AUTH_KEY`, with an HMAC-signed chain tip; `wp hinschg audit` reports the first entry that does not verify. Tamper-evident rather than write-once.
* **WP-CLI:** `wp hinschg list`, `wp hinschg sla-check`, `wp hinschg audit`, `wp hinschg key-status`, `wp hinschg protect-key`, `wp hinschg access`, `wp hinschg grant-access`, `wp hinschg revoke-access`.
* **REST API:** `wm-hinschg/v1/report/submit`, `report/status`, `report/chat` (anonymous portal permission callback, rate-limited without storing client IPs); `admin/cases`, `admin/case`, `admin/ack`, `admin/reply` (capability `wm_hinschg_read_cases`).

All scripts and styles ship with the plugin; it makes no outbound request.

**What it does not do.** Oral and in-person reporting (§ 16 Abs. 3 HinSchG) and deletion three years after the procedure ends (§ 11 Abs. 5 HinSchG) are not covered. **Administrators can open a case until the install takes the capability away from them:** `wm_hinschg_read_cases` is granted to the administrator role on install so that nobody loses their own desk, and § 8 HinSchG expects the content to stay with the people running the channel — so separating the two is work the install has to do, with `wp hinschg revoke-access` or a role plugin. There is no screen here for assigning it: managing who holds a capability belongs to WordPress and to a role manager, not to this plugin. Moving the site to a server with other salts invalidates every access token and makes the audit check fail.

== Frequently Asked Questions ==

= Is technical or private support provided? =

No. This plugin comes with zero support (`0` support). Private inquiries sent via email, `arnoldwender.com`, or social/chat channels are not answered. Reproducible bugs belong solely on GitHub Issues (`https://github.com/arnoldwender/wm-wp-hinschg-whistleblower/issues`) with no guarantee of reply or resolution. The software is provided **"AS IS"** at your sole risk with zero warranty or liability (see `SUPPORT.md` in the repository).

== Screenshots ==

1. Case desk with the audit-chain check, the access warning and counters for open cases, overdue acknowledgments and overdue feedback
2. Gutenberg editor with wm/hinschg-portal intake block and inspector settings
3. Public report form ([wm_hinschg_portal]): category and description, encrypted on the server

== Changelog ==


= 1.4.0 =
* The WM Suite Hub contract now lives in the `ArnoldWender\SuiteHub\Contracts` namespace. The spoke adapter registers only with WM Suite Hub 1.2.0 or later, so update the hub together with this plugin; used on its own, the plugin works as before.
* The `.wordpress-org/` banners show the current version.
* The screenshot descriptions name what the screens show: the report form encrypts on the server, not in the browser, and the three-month deadline is the plugin's feedback deadline, not a statutory acknowledgment deadline.
* Removed: The archived pre-2026-11-19 marketing visuals in `versionen/`: they claimed features and conformity the plugin does not have. They were never part of the installable package.

= 1.3.5 =
* Removed the agency name, links to unrelated projects and the personal mailbox from code, catalogs and documentation; the admin family badge and the hub menu read "WM Suite". The READMEs say the plugin was built with an agentic workflow (AI coding agents) and should be reviewed like any third-party code.
* Added root `SUPPORT.md`, GitHub Issue templates, explicit zero-support & "AS IS" liability notices in READMEs and `readme.txt`, and normalized canonical GPLv2+ `arnoldwender.com` / `arnoldwender/wm-wp-hinschg-whistleblower` links.
* Updated `.wordpress-org/` visual banners to personal `ARNOLD WENDER · OPEN SOURCE` branding.

= 1.3.4 =
* Add `.wordpress-org/` vector icons, banners (`772x250`, `1544x500`), live WordPress screenshots (`screenshot-1..3.png`) and `== Screenshots ==` descriptions.
* Add `README.de.md`, `README.es.md`, root `llms.txt`, live previews, and direct plugin catalog link (`https://arnoldwender.com/wordpress-plugins/wm-hinschg-whistleblower/`).

= 1.3.3 =
* Point Plugin URI to the official plugin page and enabled lexer-based security-audit CI step.

= 1.3.2 =
* Added optional dual-envelope recovery public key (`wm_hinschg_recovery_public_key`) for a 2nd Meldestelle officer / Ombudsperson (§ 8 Abs. 1, § 15 HinSchG) with browser key generation and `env.recovery_key` decryption fallback.
* Added direct § 17 receipt confirmation (`admin/ack`) and reply/final-feedback (`admin/reply`) UI controls inside the Admin Desk case view (in both server-key and `offline-custody` modes) and symmetric `reporter_box` sealing solely for compliance officer replies so reporters can read responses in `offline-custody` mode while whistleblower messages remain strictly RSA-OAEP Zero-Knowledge.
* Switched `Vault::log_audit_event()` `GET_LOCK` serialization to short jittered retry backoff returning HTTP `503 Retry-After: 2` (`wm_hinschg_audit_busy`) on contention.
* Hooked `wp_initialize_site` for automatic Multisite schema/key setup when network-activated.

= 1.3.1 =
* Security: removed the 5-minute `wm_hinschg_offline_key_once` activation transient so private keys never touch `wp_options` or transients even when no object cache or `AUTH_KEY` is present.
* Added client-side WebCrypto `RSA-OAEP-4096` keypair generation and local browser case decryption (`Schlüsselverwahrung` tab, `assets/js/wm-hinschg-zero-knowledge.js`, `Vault::install_zero_knowledge_public_key()`), storing only the `SPKI` public key on the server.
* Wired `WM_HINSCHG_AUDIT_KEY` (HKDF-SHA256) with dual-verification of pre-rotation `AUTH_KEY` entries, HMAC-signed `wm_whistle_audit_tip`, and MySQL `GET_LOCK('wm_hinschg_audit_chain', 5)` serialization on concurrent audit appends.
* Added activation prerequisite check for `ext-openssl` and `ext-sodium` (`Schema::enforce_prerequisites()`) and a MySQL 8.0 CI integration job.

= 1.3.0 =
* Added compiled Gutenberg block `wm/hinschg-portal` (`blocks/portal/block.json`, `build/index.js`, `InspectorControls` + `ServerSideRender`) visible in the Block Inserter, WP 6.5+ Block Bindings (`wm-hinschg/status`), and GenerateBlocks 2.x Dynamic Tag (`{{wm_hinschg_status}}`).
* Replaced `__return_true` on public whistleblower REST routes with `check_anonymous_portal_access` enforcing hourly-rotated HMAC transient rate-limiting (`wm_hinschg_rest_rate_limit` filter) with zero IP logging (§ 8 HinSchG), parameterized all `$wpdb` queries with `$wpdb->prepare()`, and used `checked()` on the uninstall opt-in checkbox.
* Tokenized all hex colours in `assets/css/portal-zero-cdn.css` into `:root` `--wm-hinschg-*` CSS custom properties, added `wm_hinschg_portal_config` filter and `wm_hinschg_ready` action, added WordPress Playground `blueprint.json` and CycloneDX 1.6 `bom.json`, and shipped full translations across all 28 `.po`/`.mo` and JED `.json` catalogs.

= 1.2.2 =
* Security: added `WM_HINSCHG_MASTER_KEY` at-rest sealing via `sodium_crypto_secretbox` (XSalsa20-Poly1305 + HKDF-SHA256) with automatic transparent migration of legacy plaintext PEM keys; `Schema::activate()` never writes a plaintext PEM private key to `wp_options`.
* Changed: `uninstall.php` now preserves statutory 3-year HinSchG § 11 records, keys, chain tip and Meldestelle role by default across reinstalls, with an explicit administrator opt-in checkbox on the *Deinstallation* tab to drop all tables and records.

= 1.2.1 =
* Regenerated `.pot` catalog from code via `wp i18n make-pot` and added `tests/test-pot-freshness.php` in CI.
* Reading a report uses the dedicated capability `wm_hinschg_read_cases` and the role "Meldestelle (HinSchG)" with `wp hinschg access`, `grant-access`, and `revoke-access`.
* Added case decryption view in the desk and `GET admin/case`, recording `CASE_OPENED_BY_COMPLIANCE_OFFICER` in the audit chain before returning plaintext.
* Added `WM_HINSCHG_PRIVATE_KEY` and `WM_HINSCHG_KEY_PASSPHRASE` key storage options, `wp hinschg protect-key`, and `wp hinschg key-status`.
* Portal cleaned of unverified certification, end-to-end encryption, and zero-knowledge promises; categories and statuses shown as labels.
* Follow-up chat messages sealed with `Vault::seal_message()` (RSA-4096 / AES-256-GCM) and opened server-side for the token holder.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.4.0 =
Hub users: update WM Suite Hub to 1.2.0 together with this plugin. The hub contract moved to a new PHP namespace; next to an older hub the plugin keeps working, but it is not listed in the cockpit and its admin page has no menu entry until the hub is updated.
