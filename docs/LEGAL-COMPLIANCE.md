# HinSchG: what the plugin covers and what it does not

Checked against the statute text at gesetze-im-internet.de on 2026-09-15 (§§ 8, 11, 12, 16, 17 HinSchG). This is a technical mapping, not legal advice. Whether an organisation meets its duties depends on its processes, not on this plugin.

The documentation duty for reports is § 11 HinSchG, and § 11 Abs. 5 requires deletion three years after the procedure ends.

## Mapping

| Provision | What the statute says (short) | What the plugin does | Gap |
| --- | --- | --- | --- |
| § 12 Abs. 2 | Employers with, as a rule, at least 50 employees must set up an internal reporting office. | Nothing; the plugin does not assess who is obliged. | — |
| § 12 Abs. 3 | For the entities listed there (e.g. securities service firms, credit and payment institutions, insurance undertakings) the duty applies regardless of headcount. | Nothing. | — |
| § 8 Abs. 1 | The reporting offices keep the identity of the reporting person, the persons concerned and other named persons confidential. | The form asks for no name or e-mail. Report and messages are encrypted at rest. The IP address is not stored with the report; the rate limiter keeps an hourly-rotated HMAC of it in a transient for up to one hour. | Web-server access logs are outside the plugin. Confidentiality inside the organisation is a process question; separate `wm_hinschg_read_cases` from general site administrators. |
| § 16 Abs. 1 | The internal reporting office should also process anonymous reports; there is no duty to design channels that enable them. | Reports need no name, e-mail or account. | — |
| § 16 Abs. 3 | Reports must be possible in writing and orally, and on request in person. | Written channel only. | Oral and in-person reporting must be offered some other way. |
| § 17 Abs. 1 Nr. 1 | Acknowledge receipt to the reporting person no later than after seven days. | Computes receipt + 7 days, counts overdue cases, fires `wm_hinschg_sla_breach_detected` hourly. The acknowledgment itself is `POST admin/ack`; it posts a message into the person's case view. | No screen to acknowledge; no e-mail. |
| § 17 Abs. 2 | Feedback within three months after the acknowledgment, or three months and seven days after receipt if not acknowledged. | Computes receipt + 3 months, which is never later than the statutory deadline. Feedback is `POST admin/reply` with `is_final_feedback`. | No screen to reply (REST `POST admin/reply`). |
| § 11 Abs. 1 | Document every incoming report in a permanently retrievable way, respecting confidentiality. | Reports and messages are stored encrypted; each action is recorded in the keyed audit log; `GET admin/case` and the desk case view decrypt them for `wm_hinschg_read_cases` holders. | — |
| § 11 Abs. 5 | Delete the documentation three years after the procedure ends. | Preserves records by default on plugin uninstall; does not auto-purge closed cases after three years. | Deletion after three years must be performed by the organisation. |

## Audit log

Each entry carries an HMAC-SHA256 over its predecessor, keyed with `AUTH_KEY` from `wp-config.php`, and the chain tip is kept outside the table. Editing, deleting, reordering or inserting an entry is detected by `wp hinschg audit`. It is tamper-evident rather than write-once: whoever can read `wp-config.php` can re-sign the chain. There is no external time stamp, so it proves no point in time against someone who controls the server.

## Sources

- § 8 HinSchG: <https://www.gesetze-im-internet.de/hinschg/__8.html>
- § 11 HinSchG: <https://www.gesetze-im-internet.de/hinschg/__11.html>
- § 12 HinSchG: <https://www.gesetze-im-internet.de/hinschg/__12.html>
- § 16 HinSchG: <https://www.gesetze-im-internet.de/hinschg/__16.html>
- § 17 HinSchG: <https://www.gesetze-im-internet.de/hinschg/__17.html>

All retrieved 2026-09-15.
