# Architecture — WM HinSchG Whistleblower Desk

Measured from the code. Provides a written whistleblowing intake channel, server-side RSA-4096 + AES-256-GCM envelope encryption, Libsodium private-key sealing, § 17 HinSchG deadline calculations, and an HMAC-SHA256 audit chain.

## Flow

```text
Browser (form, assets/js/portal-crypto.js)
   │  JSON over the site's HTTPS: category, description   (nothing is encrypted in the browser)
   ▼
REST wm-hinschg/v1/report/submit        RateLimiter: 5 per hour per HMAC(REMOTE_ADDR)
   │
   ├─ ReportCategories::normalize(category)
   ├─ Vault::encrypt_envelope()          AES-256-GCM, fresh 32-byte key and 12-byte IV;
   │                                     the key sealed with the RSA public key (OAEP)
   ├─ Vault::hash_token()                HMAC-SHA256(token, wp_salt('auth'))
   ├─ HinSchGSlaManager::compute_deadlines()   receipt + 7 days, receipt + 3 months (UTC)
   ├─ insert wp_wm_whistle_reports
   └─ Vault::log_audit_event()           HMAC chain in wp_wm_whistle_audit_log
   │
   ▼
response: case id + access token (shown once)
```

The Meldestelle reads a case through `GET admin/case` (capability `wm_hinschg_read_cases`), which decrypts the report and the thread and appends `CASE_OPENED_BY_COMPLIANCE_OFFICER` to the audit chain BEFORE returning the plaintext — a read that happened is recorded even if the response never arrives. The desk's case view calls that same handler, so there is one path and one record.

## Who may read a report

Until 2026-09-19 the desk, the widget and the four `admin/*` routes checked `manage_options`. An install cannot take that capability away from an administrator — it is most of what an administrator is — so on a site where the managing director also administers WordPress, they could read every report, and no role plugin could have separated the two. § 8 HinSchG expects the content to stay with the people entrusted with the channel.

`Security\Capabilities` declares `wm_hinschg_read_cases` and the role `wm_hinschg_meldestelle` ("Meldestelle (HinSchG)"). It does NOT manage who holds the capability: that belongs to WordPress roles and to whatever role manager the install uses, and a second place to decide it is a second place for it to be wrong.

| decision | where it lives |
| --- | --- |
| what the capability is, and that the desk and the routes require it | this plugin |
| which roles and users hold it | WordPress, a role plugin, or `wp hinschg grant-access` / `revoke-access` |

The administrator role receives the capability in `Capabilities::install()`, called from activation AND from `Capabilities::maybe_upgrade()` in `Plugin::boot()` — activation does not fire on an update, so without the version check an existing install would update into a desk nobody could open. Removing it from administrators afterwards is the intended end state and the install's decision.

`revoke_from_role()` and `revoke_from_user()` apply the removal, then MEASURE `holders()` and undo it when the answer is zero. Predicting whether somebody keeps the capability through another role is a question only WordPress can answer, and a channel nobody can open still has the § 17 seven-day clock running against it.

Status and follow-up messages go through `report/status` and `report/chat` with case id and token (20 per hour each). Messages are sealed with the same RSA-OAEP + AES-256-GCM envelope (`Vault::seal_message()`, with optional dual-envelope `recovery_key`). In `offline-custody` mode, compliance officer messages (`compliance_officer`) also attach a `reporter_box` (`sodium_crypto_secretbox` keyed from `reporter_box_secret()` + `token_auth_hash`) so the token holder can read officer replies via `report/status`, while whistleblower-authored messages (`whistleblower`) remain strictly asymmetric RSA-OAEP Zero-Knowledge and never carry `reporter_box`.

## Classes

| File | Responsibility |
| --- | --- |
| `wm-hinschg-whistleblower.php` | Header, constants, autoloader, activation/deactivation (`Schema`), multisite `wp_initialize_site` hook when network-activated, hub registration via `wm_register_suite_module`, boot on `plugins_loaded` |
| `includes/Core/Plugin.php` | Singleton holding `Vault` and `HinSchGSlaManager`; applies the capabilities on a version bump; loads the text domain on `init`; wires REST, desk (admin only), portal, WP-CLI and the cron action |
| `includes/Database/Schema.php` | Creates the three tables, checks `openssl`/`sodium` prerequisites, schedules `wm_hinschg_hourly_sla_check` hourly, generates the RSA-4096 key pair without ever storing a plaintext PEM in `wp_options` |
| `includes/Crypto/Vault.php` | Dual-envelope RSA-OAEP + AES-256-GCM encryption/decryption (`recovery_key`), Libsodium (`WM_HINSCHG_MASTER_KEY` / `AUTH_KEY`) private-key sealing and transparent migration, `reporter_box` sealing/opening for officer replies, message sealing, access token and its hash, `GET_LOCK` retry + HMAC audit chain writer/verifier |
| `includes/Compliance/HinSchGSlaManager.php` | Deadlines; `status_counts()` (no side effects); `execute_hourly_check()` (fires `wm_hinschg_sla_breach_detected` when a deadline passed) |
| `includes/Compliance/ReportCategories.php` | The six category keys and labels, shared by form, desk and REST |
| `includes/Compliance/CaseStatus.php` | Status labels, shared by desk and form; unknown values are shown as stored |
| `includes/API/RestController.php` | The seven REST routes (with `503 Retry-After: 2` on audit chain lock contention) |
| `includes/Security/RateLimiter.php` | Fixed-window counters in transients keyed by an HMAC of `REMOTE_ADDR` |
| `includes/Security/Capabilities.php` | Declares `wm_hinschg_read_cases` and the Meldestelle role; grants, revokes and counts holders. Does not manage users |
| `includes/Admin/AdminDashboard.php` | Menu `wm-hinschg-desk`, tabs (including `Schlüsselverwahrung` primary + recovery backup key UI and `Fallbearbeitung nach § 17 HinSchG` case ack/reply controls), dashboard widget, demo cases, test report |
| `includes/Frontend/WhistlePortal.php` | Shortcodes, Gutenberg block `wm/hinschg-portal` (`blocks/portal/block.json`, `build/index.js`), WP 6.5+ Block Bindings (`wm-hinschg/status`), GenerateBlocks 2.x Dynamic Tag (`{{wm_hinschg_status}}`), form markup, script and style registration |
| `includes/CLI/HinSchGCommand.php` | `wp hinschg list`, `sla-check`, `audit`, `key-status`, `protect-key`, `access`, `grant-access`, `revoke-access` |
| `includes/Adapters/HinSchG_Spoke_Adapter.php` | WM Suite Hub module (defined only when the hub interface exists) |
| `uninstall.php` | Cleans transients, cron and unused legacy settings; preserves statutory 3-year HinSchG § 11 tables, keys (including `wm_hinschg_recovery_public_key`), audit tip and role unless `wm_hinschg_delete_data_on_uninstall` is enabled |

## Data

| Table | Columns that matter |
| --- | --- |
| `wm_whistle_reports` | `case_public_id` (unique), `category`, `encrypted_payload`, `encrypted_key` (JSON: `key`, `tag`, `iv`, optional `recovery_key`), `token_auth_hash`, `status`, `ack_sla_deadline`, `feedback_sla_deadline`, `ack_sent_at`, `feedback_sent_at`, `created_at`, `updated_at`. No name, e-mail or IP column. |
| `wm_whistle_messages` | `report_id`, `sender_role` (`whistleblower`, `compliance_officer`), `encrypted_message` (JSON envelope with optional `recovery_key`, plus `reporter_box` solely on `compliance_officer` messages; rows before 2026-09-14 hold plain text and are returned flagged `sealed: false`), `created_at` |
| `wm_whistle_audit_log` | `case_public_id`, `action`, `actor_role`, `actor_user_id`, `previous_hash`, `current_hash`, `created_at` |

Options: `wm_hinschg_public_key`, `wm_hinschg_recovery_public_key` (optional backup RSA public key for 2nd officer / Ombudsperson), `wm_hinschg_private_key` (Libsodium- or OpenSSL-sealed when stored server-side; absent in `offline-custody`), `wm_whistle_audit_tip` (HMAC-signed hash and count of the last entry), `wm_hinschg_capability_version` (which capability set has been applied), `wm_hinschg_delete_data_on_uninstall`. Transients: `wm_hinschg_rl_<bucket>_<hash>` (rate limit), `wm_hinschg_test_report_<user>` (the test report's token, five minutes).

Statuses written by the code: `submitted` (form, test report), `acknowledged` (`admin/ack`, only from `submitted` or `received`), `investigated` (`admin/reply` with `is_final_feedback`). The demo cases add `received`, `in_investigation` and `closed`. Deadline counters skip `closed` only.

## Where the private key lives

`Vault::private_key_source()` inspects constants in `wp-config.php` and `wp_options` and reports which mode is active (`v1.3.2`):

| configuration / state | `source` | stored form | is a database dump enough? |
| --- | --- | --- | --- |
| `WM_HINSCHG_PRIVATE_KEY` in `wp-config.php` | `wp-config` | private key lives in `wp-config.php`; option is ignored | no |
| `WM_HINSCHG_MASTER_KEY` in `wp-config.php` | `database-sodium` | `wp_options`, sealed with `sodium_crypto_secretbox` via HKDF-SHA256; migrates plaintext PEMs on boot | no |
| `WM_HINSCHG_KEY_PASSPHRASE` in `wp-config.php` | `database-encrypted` | `wp_options`, OpenSSL-encrypted with that passphrase | no |
| Fresh activation with `AUTH_KEY`/`SECURE_AUTH_KEY` (no `MASTER_KEY`/`PASSPHRASE`) | `database-authkey-sodium` | `wp_options`, sealed with `sodium_crypto_secretbox` derived from `AUTH_KEY`/`SECURE_AUTH_KEY` | no |
| Browser-generated key (`Schlüsselverwahrung` tab) | `offline-custody` | server stores only `wm_hinschg_public_key` (plus optional `wm_hinschg_recovery_public_key` for a 2nd Meldestelle officer / Ombudsperson); private keys stay `.pem` files in browser custody | no |
| Unconfigured install without `wp-config.php` secrets | `unconfigured-zero-knowledge` | no private key generated or stored anywhere until configured | no |
| Pre-1.2.2 legacy install with plaintext PEM and no `wp-config.php` secret | `database-plain` | `wp_options`, legacy unencrypted PEM | **yes — every report decrypts** |

`Schema::activate()` never writes a plaintext PEM private key to `wp_options` or transients. `Schema::protect_private_key()` (`wp hinschg protect-key`) migrates an install that already ran: the RSA pair is KEPT — the reports are sealed against its public half — and only the stored form changes. It verifies the re-encrypted key opens before overwriting the old copy, refuses a key already encrypted with a different passphrase, and is a no-op when run twice.

`Vault` prefers `wp-config.php` over the option on purpose: an operator who moved the key out expects the old copy to stop mattering, and silently preferring a stale option would make the move look done while changing nothing.

## Audit chain

```text
payload_n = case_public_id | action | actor_role | actor_user_id | previous_hash | created_at
hash_n    = HMAC-SHA256(payload_n, key)
            where key = HKDF-SHA256(WM_HINSCHG_AUDIT_KEY, 'wm-hinschg-audit-chain-v1')
                     or AUTH_KEY / wp_salt('auth') when WM_HINSCHG_AUDIT_KEY is unset
previous_hash_n = hash_{n-1}, the first entry uses 64 zeros
```

`Vault::log_audit_event()` serialises concurrent appends with `SELECT GET_LOCK('wm_hinschg_audit_chain', 0)` using up to 6 jittered attempts (`15–45 ms`). On persistent lock contention, `RestController` catches the `\RuntimeException` and returns HTTP `503` with `code: 'wm_hinschg_audit_busy'` and `Retry-After: 2` before performing partial database writes.

`Vault::verify_audit_chain()` walks the table in id order and reports the first entry whose predecessor or signature does not match, an HMAC-signed `wm_whistle_audit_tip` that does not match the last entry (newest entries removed), or an empty table where the tip recorded entries. When `WM_HINSCHG_AUDIT_KEY` is configured, pre-rotation `AUTH_KEY` rows are dual-verified only before the first dedicated-key entry, and entries written before any key existed carry a plain SHA-256 (tolerated only at the head of the chain).

An HMAC mismatch cannot tell an edited entry from a different key. A site moved to a server with another `AUTH_KEY` fails at entry #1; so does every access token, which is keyed with the auth salt.

## What is missing

- Deletion three years after the procedure ends (§ 11 Abs. 5 HinSchG).
- Oral and in-person channels (§ 16 Abs. 3 HinSchG).
- Any notification; the plugin only fires an action (`wm_hinschg_sla_breach_detected`).
- A screen for assigning `wm_hinschg_read_cases`. Deliberate: WordPress roles and a role manager own that, and a second place to decide it is a second place for it to be wrong. Until an install takes the capability off the administrator role, every administrator can still open every report — the desk says so on screen.

---

<!-- wm-measured-inventory -->

## Measured inventory

Regenerated from the code, never hand-edited. Everything above this line is written by hand and stays.

```bash
python3 the fleet's architecture inventory tool wm-hinschg-whistleblower --append-to docs/ARCHITECTURE.md
```

## Inventory by layer

**16 PHP files, 4410 lines** (excluding `tests/`, `vendor/`, `node_modules/`, `languages/`).

| Layer | Files | Lines |
|---|---:|---:|
| `(raíz)` | 2 | 160 |
| `build` | 1 | 18 |
| `includes/API` | 1 | 596 |
| `includes/Adapters` | 1 | 158 |
| `includes/Admin` | 1 | 1053 |
| `includes/CLI` | 1 | 301 |
| `includes/Compliance` | 3 | 182 |
| `includes/Core` | 1 | 79 |
| `includes/Crypto` | 1 | 947 |
| `includes/Database` | 1 | 305 |
| `includes/Frontend` | 1 | 298 |
| `includes/Security` | 2 | 313 |

---

## Classes

| Class | File |
|---|---|
| `AdminDashboard` | [`includes/Admin/AdminDashboard.php`](../includes/Admin/AdminDashboard.php) |
| `Capabilities` | [`includes/Security/Capabilities.php`](../includes/Security/Capabilities.php) |
| `CaseStatus` | [`includes/Compliance/CaseStatus.php`](../includes/Compliance/CaseStatus.php) |
| `HinSchGCommand` | [`includes/CLI/HinSchGCommand.php`](../includes/CLI/HinSchGCommand.php) |
| `HinSchGSlaManager` | [`includes/Compliance/HinSchGSlaManager.php`](../includes/Compliance/HinSchGSlaManager.php) |
| `HinSchG_Spoke_Adapter` | [`includes/Adapters/HinSchG_Spoke_Adapter.php`](../includes/Adapters/HinSchG_Spoke_Adapter.php) |
| `Plugin` | [`includes/Core/Plugin.php`](../includes/Core/Plugin.php) |
| `RateLimiter` | [`includes/Security/RateLimiter.php`](../includes/Security/RateLimiter.php) |
| `ReportCategories` | [`includes/Compliance/ReportCategories.php`](../includes/Compliance/ReportCategories.php) |
| `RestController` | [`includes/API/RestController.php`](../includes/API/RestController.php) |
| `Schema` | [`includes/Database/Schema.php`](../includes/Database/Schema.php) |
| `Vault` | [`includes/Crypto/Vault.php`](../includes/Crypto/Vault.php) |
| `WhistlePortal` | [`includes/Frontend/WhistlePortal.php`](../includes/Frontend/WhistlePortal.php) |

---

## Entry points

**REST routes:** `/admin/ack`, `/admin/case`, `/admin/cases`, `/admin/reply`, `/report/chat`, `/report/status`, `/report/submit`

**WP-CLI:** `hinschg`

**Shortcodes:** `wm_hinschg_portal`, `wm_whistleblower_portal`

**Gutenberg blocks:** `wm/hinschg-portal`

**Cron events:** `wm_hinschg_hourly_sla_check`

---

## Persistence — who writes each key and who reads it

| Key | Written by | Read by |
|---|---|---|
| `wm_hinschg_delete_data_on_uninstall` | — | `uninstall.php` |
| `wm_hinschg_public_key` | `includes/Crypto/Vault.php`, `includes/Database/Schema.php` | `includes/Admin/AdminDashboard.php`, `includes/Crypto/Vault.php`, `includes/Database/Schema.php` |
| `wm_hinschg_test_report_` (transient) | — | — |

**Read but never written by this plugin:** `wm_hinschg_delete_data_on_uninstall`. The behaviour behind them is reachable only through `wp option update` or a filter — there is no screen that sets them, so an operator cannot switch it on.

**More than one writer:** `wm_hinschg_public_key`. Two layers writing one key is the shape that goes out of sync; check they agree on the default as well as on the value.


**Tables** (prefixed with `$wpdb->prefix`): `wm_whistle_audit_log`, `wm_whistle_messages`, `wm_whistle_reports`

---

## Gates

- `tests/bootstrap.php`
- `tests/mutations.php`
- `tests/probe-key-source.php`
- `tests/run-mutations.sh`
- `tests/test-audit-chain-forgery.php`
- `tests/test-chat-encryption.php`
- `tests/test-pot-freshness.php`
- `tests/test-rate-limiting.php`
- `tests/test-suite.php`
- `tests/test-ui-family.php`
- `tests/wp-runtime-desk.php`
- `.github/workflows/ci.yml`

What CI actually runs is in the workflow files above — a test file that no workflow invokes is not a gate.

---

## Drift detected against the documentation

Nothing measurable: versions agree and every class named in the documents exists.

