# Changelog — WM HinSchG Whistleblower Desk

All notable changes to **WM HinSchG Whistleblower Desk** are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Fixed
- Relaxed `WhistlePortal` GenerateBlocks `generateblocks_dynamic_tag_replacement` filter parameter to `mixed`.
- Renamed `RestController::NAMESPACE` to `REST_NAMESPACE` for PHP 8.5/8.6 compatibility.
- Added `Schema::maybe_upgrade()` in `Plugin::boot()` (`plugins_loaded`) guarded by extension availability without `wp_die()`, keeping tables and `wm_hinschg_hourly_sla_check` healthy (`wm_hinschg_db_version` stored with `autoload = false`, cleaned on opt-in uninstall).
- Added `Tested up to: 7.1` to the main plugin header and synchronized `bom.json`.

## [1.4.1] - 2026-11-21

### Fixed
- In the block editor, the preview of the `HinSchG Meldestelle Portal` block showed the form without its stylesheet (measured in the editor canvas: no `wm-hinschg-portal-css`, width unlimited, no rounded corners). `block.json` names that stylesheet, but it was registered only for the front end; it is now registered together with the block, so the editor loads it as well.
- 67 texts of the key custody tab, the case handling panel under § 17 and the related notices, added in 1.3.1 and 1.3.2, were untranslated in all 28 catalogs; non-German sites showed them in German. They now carry their translations, with the terms the catalogs already use (for example the portal's "Vorgang abrufen" button).
- The plural forms of "%d Frist überschritten" and "%d Person darf Meldungen öffnen." in Arabic, Czech, Irish, Croatian, Lithuanian, Latvian, Maltese, Polish, Romanian, Slovak and Slovenian repeated one form for every number above one (Czech read "Překročeno 2 lhůt" instead of "Překročeny 2 lhůty"); each form now matches its number. The Maltese deadline text also said "buried" (`maqbura`) instead of "exceeded" (`maqbuża`).

### Changed
- The bundled family stylesheet is identical to WM Suite Hub 1.2.5 again: it starts the admin header below WordPress's help toggle instead of shortening it. This plugin's own screens register no help tab, so they change only where another plugin adds one.
- The translation catalogs are regenerated from the code: the `.pot` header names the current version, the Author URI entry follows the plugin header, and the block editor's JavaScript catalogs carry the block's title, description and keywords under their block contexts and the full plural forms of each language.

## [1.4.0] - 2026-11-20

### Changed
- The WM Suite Hub contract now lives in the `ArnoldWender\SuiteHub\Contracts` namespace. The spoke adapter registers only with WM Suite Hub 1.2.0 or later, so update the hub together with this plugin; used on its own, the plugin works as before.
- The `.wordpress-org/` banners show the current version.
- The screenshot descriptions (`readme.txt` and the three READMEs) name what the screens show. The third called the report form "client-side WebCrypto"; the form sends plain JSON and the report is encrypted on the server (the screen says so). The first called the three-month deadline a statutory acknowledgment deadline; it is the plugin's feedback deadline.
- `README.de.md` and `README.es.md` stated version 1.3.4 since release 1.3.5.
- The standalone suite compares the SBOM reference with the version constant instead of a literal that had to be edited on every release.

### Removed
- The archived pre-2026-11-19 marketing visuals in `versionen/`: they claimed features and conformity the plugin does not have. They were never part of the installable package.

## [1.3.5] - 2026-11-19

- Removed the agency name, links to unrelated projects and the personal mailbox from code, catalogs and documentation; the admin family badge and the hub menu read "WM Suite". The READMEs say the plugin was built with an agentic workflow (AI coding agents) and should be reviewed like any third-party code.

- Added root `SUPPORT.md`, `.github/ISSUE_TEMPLATE/{config.yml,bug_report.yml}`, and explicit zero-support / "AS IS" liability notices across `README.md`, `README.de.md`, `README.es.md`, `readme.txt`, `SECURITY.md`, and `llms.txt`.
- Migrated plugin author/catalog/repository metadata to personal open-source distribution (`Arnold Wender`, `https://arnoldwender.com/wordpress-plugins/wm-hinschg-whistleblower/`, `https://github.com/arnoldwender/wm-wp-hinschg-whistleblower`), normalized FSF GPL-2.0 `LICENSE` metadata where applicable, and updated `.wordpress-org/` banner branding to `ARNOLD WENDER · OPEN SOURCE`.

## [1.3.4] - 2026-11-19

### Added
- Official `.wordpress-org/` directory visual kit (`icon.svg`, `icon-128x128.png`, `icon-256x256.png`, `banner-772x250.png`, `banner-1544x500.png`) and live Playwright screenshots (`screenshot-1.png` through `screenshot-3.png`) with `== Screenshots ==` in `readme.txt`.
- Added German (`README.de.md`) and Spanish (`README.es.md`) documentation with language switcher badges, root `llms.txt`, visual previews, and direct links to `https://arnoldwender.com/wordpress-plugins/wm-hinschg-whistleblower/`.

### Changed
- Archived superseded pre-2026-11-19 banners and mockups non-destructively in `versionen/visuals-pre-2026-11-19/` and excluded `versionen/` from distribution packages via `.distignore`.
- Updated release metadata, adapter fallback, test bootstrap/suite constants, and SBOM (`bom.json`) to `1.3.4`.

## [1.3.3] - 2026-11-19

### Changed
- Point `Plugin URI` to `https://arnoldwender.com/wordpress-plugins/wm-hinschg-whistleblower/` and align release metadata at `v1.3.3`. Added `.github/scripts/security-audit.py` CI gate.

## [1.3.2] - 2026-11-18

- **Dual-envelope Zero-Knowledge backup key for a 2nd Meldestelle officer / Ombudsperson (`R2-B3`).** Added `Vault::RECOVERY_PUBLIC_KEY_OPTION` (`wm_hinschg_recovery_public_key`) and `Vault::install_recovery_public_key()` (rejects private keys, validates SPKI RSA >= 2048 bits, allows `''` to clear). `Vault::encrypt_envelope()` dual-seals the AES-256 session key under `recovery_key` (preserved across REST intake, demo seeding, test reports, and `offline-custody` bundles), while `assets/js/wm-hinschg-zero-knowledge.js` falls back to `env.recovery_key` during local browser decryption. Added the *Notfall- & Vertretungsschlüssel* generator & form card on the *Schlüsselverwahrung* tab (§ 8 Abs. 1, § 15 HinSchG) and opt-in cleanup in `uninstall.php`.
- **Direct Desk § 17 Ack/Reply UI & `reporter_box` for `offline-custody` (`R2-B2`).** Added the *Fallbearbeitung nach § 17 HinSchG* panel (`#wm-hinschg-ack-btn`, `#wm-hinschg-reply-text`, `#wm-hinschg-reply-final`, `#wm-hinschg-reply-btn`, `#wm-hinschg-case-action-status`) directly inside the open case view in both server-key and `offline-custody` modes, localized `restUrl` + `restNonce` via `wp_localize_script`, removed the obsolete REST-only banner, and updated the encryption glossary and architecture docs. Added `Vault::seal_for_reporter()` / `open_message_for_reporter()` (`sodium_crypto_secretbox` via `reporter_box_secret()` + `token_auth_hash`) strictly for `compliance_officer` replies so reporters can read officer responses in `offline-custody` mode, while keeping `whistleblower`-authored messages 100% asymmetric RSA-OAEP Zero-Knowledge without `reporter_box`.
- **Audit lock jitter-backoff & `503 Retry-After: 2` (`R2-B6`).** `Vault::log_audit_event()` now retries `GET_LOCK(..., 0)` up to 6 times with `15–45 ms` jittered backoff; `RestController` catches lock-acquisition failures and returns HTTP `503` (`wm_hinschg_audit_busy`, `Retry-After: 2`) before partial database writes, and `AdminDashboard` handles `WP_REST_Response` errors (`>= 400`) cleanly.
- **Multisite `wp_initialize_site` (`R2-B8`).** Hooked `wp_initialize_site` in `wm-hinschg-whistleblower.php` to run `Schema::activate()` inside `switch_to_blog()` / `restore_current_blog()` when network-activated (`is_plugin_active_for_network`).

## [1.3.1] - 2026-11-18

- **Zero-Knowledge browser key custody & elimination of `wm_hinschg_offline_key_once` transient (`WP-E2`).** Removed `set_transient('wm_hinschg_offline_key_once', ...)` from `Schema::activate()` so a private key never touches `wp_options` or transients even on installs without Redis/Memcached and without `AUTH_KEY`. Added the *Schlüsselverwahrung* tab and `assets/js/wm-hinschg-zero-knowledge.js`: generates an `RSA-OAEP-4096` (`SHA-1` OAEP hash, matching `OPENSSL_PKCS1_OAEP_PADDING`) keypair locally via `window.crypto.subtle`, downloads `hinschg-meldestelle-private-key.pem` directly from browser memory, uploads only the `SPKI` public key (`Vault::install_zero_knowledge_public_key()`), and decrypts cases locally in the browser on the desk case view after `CASE_OPENED_BY_COMPLIANCE_OFFICER` is audited.
- **Dedicated `WM_HINSCHG_AUDIT_KEY`, MySQL `GET_LOCK` concurrency guard & signed chain tip.** `Vault::audit_hash()` derives a 32-byte key from `WM_HINSCHG_AUDIT_KEY` via `hash_hkdf('sha256', ...)`, while `Vault::verify_audit_chain()` dual-verifies pre-rotation `AUTH_KEY` rows and refuses post-rotation downgrades. `Vault::log_audit_event()` serializes concurrent appends via `SELECT GET_LOCK('wm_hinschg_audit_chain', 5)` and HMAC-signs `wm_whistle_audit_tip`.
- **Activation prerequisite gate & MySQL 8.0 CI job.** Added `Schema::enforce_prerequisites()` checking `ext-openssl` and `ext-sodium` on activation, plus a `mysql:8.0` integration job in `.github/workflows/ci.yml`.

## [1.3.0] - 2026-11-16

- **Gutenberg block & ecosystem bridges.** Added `blocks/portal/block.json`, `blocks-src/index.js`, `build/index.js`, and `build/index.asset.php` (`wm-hinschg-blocks-editor` with `InspectorControls` and `ServerSideRender`), making `wm/hinschg-portal` visible in the Block Inserter (`1 / 0`). Registered WordPress 6.5+ Block Bindings source `wm-hinschg/status` and GenerateBlocks 2.x dynamic tag `{{wm_hinschg_status}}`, plus the `wm_hinschg_ready` action and `wm_hinschg_rest_rate_limit` / `wm_hinschg_portal_config` filters.
- **REST permission callback & SQL parameterization.** Replaced `'__return_true'` on `report/submit`, `report/status`, and `report/chat` with `RestController::check_anonymous_portal_access()`, enforcing hourly-rotated HMAC transient rate-limiting (`wm_hinschg_rest_rate_limit`) without storing client IPs (§ 8 HinSchG). Parameterized all remaining `$wpdb` queries with `$wpdb->prepare()` and replaced manual ternary attribute output on the uninstall checkbox with `checked()`.
- **Design tokens, SBOM, Playground & 28 locales.** Moved all 16 hex colours in `assets/css/portal-zero-cdn.css` into `:root` `--wm-hinschg-*` custom properties. Added CycloneDX 1.6 `bom.json`, `.license-allowlist.yml`, and `.wordpress-org/blueprints/blueprint.json`. Translated all 202 catalog strings (including plural forms) across all 28 `.po`/`.mo` and block-editor JED `.json` files.

## [1.2.2] - 2026-11-16

- **Libsodium at-rest private-key encryption and zero-plaintext activation (`D-HINSCHG-KEY`).** Added `WM_HINSCHG_MASTER_KEY` (`wp-config.php`), sealing the RSA-4096 private key in `wp_options` with `sodium_crypto_secretbox` (XSalsa20-Poly1305) under a 32-byte key derived via `hash_hkdf('sha256', ...)`. Existing installs with a legacy plaintext PEM in `wp_options` migrate transparently on boot as soon as `WM_HINSCHG_MASTER_KEY` is defined (and via `wp hinschg protect-key`), keeping every report readable. Fresh activations (`Schema::activate()`) never write a plaintext PEM private key to `wp_options`, sealing via `WM_HINSCHG_MASTER_KEY`, `WM_HINSCHG_KEY_PASSPHRASE`, `AUTH_KEY`-derived Libsodium, or one-time offline custody when no `wp-config.php` secret exists.
- **Statutory 3-year retention by default on uninstall (`D-UNINSTALL`).** Under § 11 Abs. 5 HinSchG, case documentation is retained for three years after closure. `uninstall.php` now cleans ephemeral transients, scheduled cron and unused legacy settings while preserving `wm_whistle_reports`, `wm_whistle_messages`, `wm_whistle_audit_log`, the key pair, the audit chain tip and the Meldestelle role by default unless an administrator (`manage_options`) explicitly enables `wm_hinschg_delete_data_on_uninstall` on the *Deinstallation* tab.

## [1.2.1] - 2026-09-20

- **Regenerated `.pot` catalog from code.** Extracted all translatable strings with `wp i18n make-pot`, merged `.po` catalogs while preserving obsolete `#~` entries, and added `tests/test-pot-freshness.php` in CI so newly added strings cannot drift from `languages/wm-hinschg-whistleblower.pot`.

## [1.2.0] - 2026-09-19

- **Dedicated capability `wm_hinschg_read_cases`.** The desk, dashboard widget, and four `admin/*` routes now check `wm_hinschg_read_cases` instead of `manage_options`, and the plugin registers the role `Meldestelle (HinSchG)`.
- **Upgrade safety & CLI access management.** Administrators receive `wm_hinschg_read_cases` on install and upgrade (`Capabilities::maybe_upgrade()`) so existing installs are not locked out; `wp hinschg access`, `grant-access`, and `revoke-access` manage holders and refuse revoking the last holder.

## [1.1.0] - 2026-09-19

- **Compliance officer case decryption.** `GET /wm-hinschg/v1/admin/case` and the desk case view decrypt the report and message thread, appending `CASE_OPENED_BY_COMPLIANCE_OFFICER` to the audit chain before returning plaintext.
- **Externalized and passphrase-protected private key storage.** Added `WM_HINSCHG_PRIVATE_KEY` and `WM_HINSCHG_KEY_PASSPHRASE` support along with `wp hinschg protect-key` and `wp hinschg key-status`.

## [1.0.1] - 2026-09-16

- **Admin design family & honest copy.** Migrated the admin desk to the shared WM Suite family stylesheets (`assets/css/wm-admin-tokens.css`, `assets/css/wm-admin-ui.css`). Replaced static counters with live `HinSchGSlaManager::status_counts()`, sealed follow-up chat messages with `Vault::seal_message()`, escaped portal DOM templates, and removed unverified marketing claims from portal and documentation.
