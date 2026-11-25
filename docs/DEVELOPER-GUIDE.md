# Developer Guide — WM HinSchG Whistleblower Desk

## WP-CLI

```bash
wp hinschg list        # every case: id, category, status, both deadlines, created (no report text)
wp hinschg sla-check   # overdue acknowledgments, acknowledgments due within 48 h, overdue feedback;
                       # fires wm_hinschg_sla_breach_detected when a deadline passed
wp hinschg audit       # verifies the audit chain; exits with an error at the first entry that does not verify
wp hinschg key-status  # where the private key lives, and whether a database dump is enough
wp hinschg protect-key # re-seal or re-export the stored key encrypted with WM_HINSCHG_MASTER_KEY (Libsodium) or WM_HINSCHG_KEY_PASSPHRASE
wp hinschg access      # who may open a report: the roles and the users
wp hinschg grant-access  --role=<slug> | --user=<id-or-login>
wp hinschg revoke-access --role=<slug> | --user=<id-or-login>
```

`wp hinschg audit` warns when `AUTH_KEY` is not defined (the key then comes from the database) and reports entries from before the key as unkeyed, never as verified.

`revoke-access` refuses the call that would leave nobody holding `wm_hinschg_read_cases`: the reports are encrypted, this plugin is the only way in, and § 17 HinSchG keeps counting either way. It applies the removal and then measures the remaining holders, because whether a user keeps the capability through another role is a question only WordPress can answer.

## REST API

Namespace `wm-hinschg/v1`. Bodies are JSON.

| Route | Method | Who | Request | Response |
| --- | --- | --- | --- | --- |
| `report/submit` | POST | anonymous portal (`check_anonymous_portal_access`, 5/h) | `category`, `description` | 201: `case_public_id`, `access_token`, `ack_deadline`, `feedback_deadline`, `notice` |
| `report/status` | POST | anonymous portal (`check_anonymous_portal_access`, 20/h) | `case_public_id`, `access_token` | `status`, `category`, `ack_sent_at`, `feedback_sent_at`, `ack_deadline`, `feedback_deadline`, `messages[]`; 403 on a wrong token |
| `report/chat` | POST | anonymous portal (`check_anonymous_portal_access`, 20/h) | `case_public_id`, `access_token`, `message` | 201 |
| `admin/cases` | GET | `wm_hinschg_read_cases` | — | the 100 newest cases, metadata only |
| `admin/case` | GET | `wm_hinschg_read_cases` | `case_public_id` | the decrypted report and the whole thread; writes `CASE_OPENED_BY_COMPLIANCE_OFFICER` to the audit chain before answering; 404 unknown, 500 `decryption_failed` with the key source, never the ciphertext |
| `admin/ack` | POST | `wm_hinschg_read_cases` | `case_public_id` | 200 with `ack_sent_at`, `status`, and a sealed acknowledgment message (with `reporter_box` for `offline-custody`); 409 `already_acknowledged` when `ack_sent_at` is set |
| `admin/reply` | POST | `wm_hinschg_read_cases` | `case_public_id`, `message`, optional `is_final_feedback` | 200 with `status` and `feedback_sent_at` (with `reporter_box` for `offline-custody`); with `is_final_feedback` sets `feedback_sent_at` and status `investigated` |

`messages[]` entries are `{id, sender_role, message, sealed, unreadable, created_at}`. A message that does not open with the current key comes back empty with `unreadable: true`; the ciphertext column is never returned. A rate-limited call gets 429 `wm_hinschg_rate_limited`, and audit-chain lock contention returns 503 `wm_hinschg_audit_busy` with header `Retry-After: 2`.

An unknown `category` is stored as `general_compliance`.

## Gutenberg Block, Block Bindings & GenerateBlocks 2.x

- **Block:** `wm/hinschg-portal` (`blocks/portal/block.json`, editor handle `wm-hinschg-blocks-editor`, attributes `title` and `showDescription`).
- **WP 6.5+ Block Bindings:** source `wm-hinschg/status` (`args.key`: `channel_label`, `ack_days`, `feedback_months`, or `open_cases` for `wm_hinschg_read_cases` holders).
- **GenerateBlocks 2.x Dynamic Tag:** `{{wm_hinschg_status}}` (supports `key` option matching `wm-hinschg/status`).

## Hooks

```php
// Fired when the plugin finishes booting on plugins_loaded.
add_action( 'wm_hinschg_ready', function ( \WMCyber\HinSchG\Core\Plugin $plugin ) {} );

// Fired by the hourly cron event and by `wp hinschg sla-check` when at least one deadline has passed.
add_action( 'wm_hinschg_sla_breach_detected', function ( array $counts ) {
    // $counts: breached_ack, breached_feedback, impending_ack (int)
} );

// Adjust per-bucket hourly rate limits ('portal', 'submit', 'status', 'chat').
add_filter( 'wm_hinschg_rest_rate_limit', function ( int $limit, string $bucket, int $window ): int {
    return $limit;
}, 10, 3 );

// Filter localized configuration passed to assets/js/portal-crypto.js.
add_filter( 'wm_hinschg_portal_config', function ( array $config ): array {
    return $config;
} );
```

`HinSchGSlaManager::status_counts()` returns the deadline counts plus `open` without firing `wm_hinschg_sla_breach_detected`; use it for anything that is read often.

## Tests

| Command | Needs | What it covers |
| --- | --- | --- |
| `php tests/test-suite.php` | PHP | Encryption, deadlines, hub adapter, REST (chat sealing, category, acknowledgment, rate-limit permission callback), desk and widget rendering, portal markup, Gutenberg block, hooks, Block Bindings/GenerateBlocks bridges, and uninstall. |
| `bash tests/run-mutations.sh` | PHP, git, tar | Each entry in `tests/mutations.php` undoes one fix in a copy of the repo; the suite must turn red. |
| `php tests/test-ui-family.php` | PHP | Family sheets identical to the hub, no `outline: none`, no hex colours outside token lines. |
| `php tests/test-pot-freshness.php` | PHP, wp-cli | Every string the code translates has an entry in `languages/*.pot`. |
| `vendor/bin/phpunit` (in `tests/`) | Composer dev dependencies | `tests/Unit`: vault, deadlines, message sealing. |
| `wp eval-file tests/wp-runtime-desk.php --user=1` | WordPress | Read-only check against real tables. |
| `WM_HINSCHG_SCRATCH_INSTALL=1 wp eval-file tests/test-audit-chain-forgery.php` | WordPress, scratch install | Forgery cases for the audit chain. Truncates the audit log. |
| `WM_HINSCHG_SCRATCH_INSTALL=1 wp eval-file tests/test-chat-encryption.php` | WordPress, scratch install | Chat sealing through the real REST stack. |
| `wp eval-file tests/test-rate-limiting.php` | WordPress | Rate limiter; clears the rate-limit counters. |

CI (`.github/workflows/ci.yml`) runs PHPUnit, the standalone suite and the UI gate on PHP 8.2 and 8.3, and the catalog freshness and mutation checks on 8.3.
