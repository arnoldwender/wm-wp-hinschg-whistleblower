<?php
/**
 * Standalone Automated Test Runner & Unit Suite for wm-hinschg-whistleblower.
 *
 * Runs without external WordPress/MySQL dependency by providing a deterministic
 * mock environment for wpdb, options, hooks, textdomain, and Spoke interfaces.
 *
 * @package WMCyber\HinSchG
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

// A warning is a failure: a render that reads a missing column still "passes" its string checks otherwise.
$GLOBALS['hinschg_php_warnings'] = [];
set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
    $GLOBALS['hinschg_php_warnings'][] = basename($file) . ':' . $line . ' ' . $msg;
    return false;
});

// Setup mock WordPress constants
if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__DIR__) . '/');
}
if (!defined('WM_HINSCHG_VERSION')) {
    define('WM_HINSCHG_VERSION', '1.4.0');
}
if (!defined('WM_HINSCHG_FILE')) {
    define('WM_HINSCHG_FILE', dirname(__DIR__) . '/wm-hinschg-whistleblower.php');
}
if (!defined('WM_HINSCHG_PATH')) {
    define('WM_HINSCHG_PATH', dirname(__DIR__) . '/');
}
if (!defined('WM_HINSCHG_URL')) {
    define('WM_HINSCHG_URL', 'https://demo.example.com/wp-content/plugins/wm-hinschg-whistleblower/');
}
if (!defined('ARRAY_A')) {
    define('ARRAY_A', 'ARRAY_A');
}

// Global Mocks & In-Memory Store
global $mock_options, $mock_filters, $mock_actions, $mock_db_tables, $wpdb;
$mock_options   = [];
$mock_filters   = [];
$mock_actions   = [];
$mock_db_tables = [
    'wp_wm_whistle_reports' => [],
    'wp_wm_whistle_audit'   => [],
];

// Generate RSA-4096 test keys
$res = openssl_pkey_new([
    'digest_alg'       => 'sha256',
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
openssl_pkey_export($res, $private_key);
$details = openssl_pkey_get_details($res);

$mock_options['wm_hinschg_private_key'] = $private_key;
$mock_options['wm_hinschg_public_key']  = $details['key'];

class Mock_WPDB_HinSchG {
    public string $prefix = 'wp_';
    public string $options = 'wp_options';
    public int $insert_id = 0;
    public array $table_auto_increment = [];
    public array $queries = [];
    public bool $refuse_lock = false;
    public int $refuse_lock_count = 0;
    public bool $refuse_lock_null = false;
    public int $get_lock_calls = 0;

    public function esc_like(string $text): string {
        return addcslashes($text, '_%\\');
    }

    public function get_charset_collate(): string {
        return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
    }

    public function insert(string $table, array $data, array $format = []): int {
        global $mock_db_tables;
        if (!isset($this->table_auto_increment[$table])) {
            $this->table_auto_increment[$table] = 0;
        }
        $this->table_auto_increment[$table]++;
        $id = $this->table_auto_increment[$table];
        $this->insert_id = $id;
        $row = array_merge(['id' => $id], $data);
        $mock_db_tables[$table][$id] = (object) $row;
        return 1;
    }

    public function query(string $query): int {
        $this->queries[] = $query;
        return 1;
    }

    public function prepare(string $query, ...$args): string {
        if (isset($args[0]) && is_array($args[0])) {
            $args = $args[0];
        }
        foreach ($args as $arg) {
            $val = is_numeric($arg) ? $arg : "'" . addslashes((string)$arg) . "'";
            $query = preg_replace('/%[sdfF]/', (string)$val, $query, 1);
        }
        return $query;
    }

    public function get_var(string $query) {
        global $mock_db_tables;
        if (preg_match('/SELECT\s+GET_LOCK\(/i', $query)) {
            $this->get_lock_calls++;
            if ($this->refuse_lock_null) {
                return null;
            }
            if ($this->refuse_lock) {
                return '0';
            }
            if ($this->refuse_lock_count > 0) {
                $this->refuse_lock_count--;
                return '0';
            }
            return '1';
        }
        if (preg_match('/SELECT\s+RELEASE_LOCK\(/i', $query)) {
            return '1';
        }
        if (preg_match('/SHOW\s+TABLES\s+LIKE\s+[\'"](.*)[\'"]/i', $query, $m)) {
            return $m[1];
        }
        // COUNT(*) honours the WHERE clause: a mock that counted every row gave the deadline counters a green they never earned.
        if (preg_match('/COUNT\(\*\)\s+FROM\s+([^\s]+)(?:\s+WHERE\s+(.+))?$/is', $query, $m)) {
            $rows = $mock_db_tables[$m[1]] ?? [];
            if (empty($m[2])) {
                return count($rows);
            }
            return count(array_filter($rows, fn($r) => $this->row_matches_where((array) $r, $m[2])));
        }
        return null;
    }

    public function get_row(string $query, string $output = 'OBJECT') {
        global $mock_db_tables;
        if (preg_match('/SELECT\s+.*FROM\s+([^\s]+)\s+ORDER\s+BY\s+id\s+DESC\s+LIMIT\s+1/i', $query, $m)) {
            $table = $m[1];
            $rows = $mock_db_tables[$table] ?? [];
            if (empty($rows)) {
                return null;
            }
            $last = end($rows);
            return $output === 'ARRAY_A' ? (array)$last : $last;
        }
        // Report lookups by case id (and token hash) as the REST controller issues them.
        if (preg_match('/FROM\s+([^\s]+)\s+WHERE\s+(.+)$/is', $query, $m)) {
            $table = $m[1];
            foreach ($mock_db_tables[$table] ?? [] as $row) {
                if ($this->row_matches_where((array) $row, $m[2])) {
                    return $output === 'ARRAY_A' ? (array) $row : $row;
                }
            }
        }
        return null;
    }

    public function get_results(string $query, string $output = 'OBJECT'): array {
        global $mock_db_tables;
        if (preg_match('/FROM\s+([^\s]+)\s+WHERE\s+(.+?)(\s+ORDER\s+BY.*)?$/is', $query, $m)) {
            $rows = array_values(array_filter($mock_db_tables[$m[1]] ?? [], fn($r) => $this->row_matches_where((array) $r, $m[2])));
            return $output === 'ARRAY_A' ? array_map(fn($r) => (array)$r, $rows) : $rows;
        }
        if (preg_match('/SELECT\s+.*FROM\s+([^\s]+)/i', $query, $m)) {
            $table = $m[1];
            $rows = array_values($mock_db_tables[$table] ?? []);
            return $output === 'ARRAY_A' ? array_map(fn($r) => (array)$r, $rows) : $rows;
        }
        return [];
    }

    public function update(string $table, array $data, array $where, $format = null, $where_format = null): int|false {
        global $mock_db_tables;
        $id = (int) ($where['id'] ?? 0);
        if (!isset($mock_db_tables[$table][$id])) {
            return false;
        }
        foreach ($data as $k => $v) {
            $mock_db_tables[$table][$id]->$k = $v;
        }
        return 1;
    }

    // "col = 'v' AND col2 < 'w' AND col3 IS NULL" against a row, with SQL NULL semantics. A clause the mock
    // does not understand throws: returning false (or true) for it would make a query look tested when it is not.
    private function row_matches_where(array $row, string $where): bool {
        foreach (preg_split('/\s+AND\s+/i', trim($where)) as $clause) {
            if (preg_match('/^\s*([a-z_]+)\s+IS\s+NULL\s*$/i', $clause, $c)) {
                if (null !== ($row[$c[1]] ?? null)) {
                    return false;
                }
                continue;
            }
            if (!preg_match("/^\s*([a-z_]+)\s*(=|!=|<>|<=|>=|<|>)\s*(?:'((?:[^'\\\\]|\\\\.)*)'|(\d+))\s*$/i", $clause, $c)) {
                throw new \RuntimeException('Mock_WPDB_HinSchG: unsupported WHERE clause: ' . $clause);
            }
            $actual = $row[$c[1]] ?? null;
            if (null === $actual) {
                return false;
            }
            $expected = isset($c[4]) && '' !== $c[4] ? $c[4] : stripslashes($c[3]);
            $cmp      = strcmp((string) $actual, (string) $expected);
            $ok       = match ($c[2]) {
                '='        => 0 === $cmp,
                '!=', '<>' => 0 !== $cmp,
                '<'        => $cmp < 0,
                '<='       => $cmp <= 0,
                '>'        => $cmp > 0,
                '>='       => $cmp >= 0,
            };
            if (!$ok) {
                return false;
            }
        }
        return true;
    }
}

$wpdb = new Mock_WPDB_HinSchG();

// Mock WP core functions
if (!function_exists('add_action')) {
    function add_action(string $tag, callable $callback, int $priority = 10, int $accepted_args = 1): void {
        global $mock_actions;
        $mock_actions[$tag][] = $callback;
    }
}
if (!function_exists('add_filter')) {
    function add_filter(string $tag, callable $callback, int $priority = 10, int $accepted_args = 1): void {
        global $mock_filters;
        $mock_filters[$tag][$priority][] = $callback;
    }
}
if (!function_exists('apply_filters')) {
    function apply_filters(string $tag, $value, ...$args) {
        global $mock_filters;
        if (empty($mock_filters[$tag])) {
            return $value;
        }
        ksort($mock_filters[$tag]);
        foreach ($mock_filters[$tag] as $cbs) {
            foreach ($cbs as $cb) {
                $value = $cb($value, ...$args);
            }
        }
        return $value;
    }
}
if (!function_exists('get_option')) {
    function get_option(string $option, $default = false) {
        global $mock_options;
        return $mock_options[$option] ?? $default;
    }
}
if (!function_exists('update_option')) {
    function update_option(string $option, $value, $autoload = null): bool {
        global $mock_options;
        $mock_options[$option] = $value;
        return true;
    }
}
if (!function_exists('admin_url')) {
    function admin_url(string $path = ''): string {
        return 'https://demo.example.com/wp-admin/' . ltrim($path, '/');
    }
}
if (!function_exists('esc_html')) {
    function esc_html($text) {
        return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
    }
}
if (!function_exists('wp_json_encode')) {
    function wp_json_encode($data, $options = 0, $depth = 512) {
        return json_encode($data, $options, $depth);
    }
}
if (!function_exists('wp_salt')) {
    function wp_salt(string $scheme = 'auth'): string {
        return 'mock-wm-hinschg-auth-salt-key-2026';
    }
}
if (!function_exists('current_time')) {
    function current_time(string $type, $gmt = 0) {
        return $type === 'mysql' ? ($gmt ? gmdate('Y-m-d H:i:s') : date('Y-m-d H:i:s')) : time();
    }
}
if (!function_exists('sanitize_key')) {
    function sanitize_key($key): string {
        return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $key));
    }
}
if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str): string {
        return trim(strip_tags((string) $str));
    }
}
if (!function_exists('sanitize_textarea_field')) {
    function sanitize_textarea_field($str): string {
        return trim(strip_tags((string) $str));
    }
}
if (!function_exists('wp_unslash')) {
    function wp_unslash($value) {
        return is_string($value) ? stripslashes($value) : $value;
    }
}
if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string {
        return $text;
    }
}
if (!function_exists('get_current_user_id')) {
    function get_current_user_id(): int {
        return 1;
    }
}
$GLOBALS['mock_transients'] = [];
if (!function_exists('get_transient')) {
    function get_transient(string $key) {
        return $GLOBALS['mock_transients'][$key] ?? false;
    }
}
if (!function_exists('set_transient')) {
    function set_transient(string $key, $value, int $expiration = 0): bool {
        $GLOBALS['mock_transients'][$key] = $value;
        return true;
    }
}
if (!class_exists('WP_Error')) {
    class WP_Error {
        public function __construct(public string $code = '', public string $message = '', public mixed $data = '') {}
        public function get_error_code(): string { return $this->code; }
        public function get_error_message(): string { return $this->message; }
        public function get_error_data(): mixed { return $this->data; }
    }
}
if (!function_exists('is_wp_error')) {
    function is_wp_error($thing): bool {
        return $thing instanceof WP_Error;
    }
}
if (!class_exists('WP_REST_Request')) {
    class WP_REST_Request {
        public function __construct(private array $json = []) {}
        public function get_json_params(): array { return $this->json; }
        public function get_param(string $key): mixed { return $this->json[$key] ?? null; }
    }
}
if (!class_exists('WP_REST_Response')) {
    class WP_REST_Response {
        public function __construct(private mixed $data = null, private int $status = 200, private array $headers = []) {}
        public function get_data(): mixed { return $this->data; }
        public function get_status(): int { return $this->status; }
        public function get_headers(): array { return $this->headers; }
    }
}

// Mock Suite Hub Interface
if (!interface_exists('ArnoldWender\SuiteHub\Contracts\WM_Plugin_Module_Interface')) {
    eval('namespace ArnoldWender\SuiteHub\Contracts {
        interface WM_Plugin_Module_Interface {
            public function get_module_slug(): string;
            public function get_name(): string;
            public function get_version(): string;
            public function get_description(): string;
            public function get_health_status(): string;
            public function get_sbom_data(): array;
            public function get_dependencies(): array;
            public function get_settings_url(): ?string;
            public function get_telemetry_metrics(): array;
            public function execute_action(string $action, array $params = []): array;
        }
    }');
}

// Autoloader for WMCyber\HinSchG
spl_autoload_register(function (string $class): void {
    $prefix = 'WMCyber\\HinSchG\\';
    $base_dir = WM_HINSCHG_PATH . 'includes/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) {
        require_once $file;
    }
});

// Require key classes
require_once ABSPATH . 'includes/Crypto/Vault.php';
require_once ABSPATH . 'includes/Compliance/HinSchGSlaManager.php';
require_once ABSPATH . 'includes/Core/Plugin.php';
require_once ABSPATH . 'includes/Adapters/HinSchG_Spoke_Adapter.php';

// Test Execution Harness
$passed_count = 0;
$failed_count = 0;

function assert_test(string $name, bool $condition, string $failure_details = ''): void {
    global $passed_count, $failed_count;
    if ($condition) {
        echo "  [PASS] {$name}\n";
        $passed_count++;
    } else {
        echo "  [FAIL] {$name}: {$failure_details}\n";
        $failed_count++;
    }
}

echo "==============================================================================\n";
echo "  WM HINSCHG WHISTLEBLOWER — STANDALONE TEST SUITE (no WordPress, no MySQL)\n";
echo "==============================================================================\n\n";

// ------------------------------------------------------------
// Test 1: Envelope Encryption & Access Token Entropy
// ------------------------------------------------------------
echo "[TEST GROUP 1] Hybrid Envelope Encryption (RSA-4096 / AES-256-GCM)\n";
$vault = new \WMCyber\HinSchG\Crypto\Vault();

$payload = [
    'category'    => 'financial_fraud',
    'description' => 'Unregelmäßige Buchungen auf Offshore-Konten festgestellt.',
    'amount'      => 450000,
];

$envelope = $vault->encrypt_envelope($payload);
assert_test(
    'encrypt_envelope produces secure payload, encrypted AES key, auth tag, and IV',
    isset($envelope['payload'], $envelope['key'], $envelope['tag'], $envelope['iv']),
    "Envelope keys: " . implode(', ', array_keys($envelope))
);

$decrypted = $vault->decrypt_envelope($envelope['payload'], $envelope['key'], $envelope['tag'], $envelope['iv']);
assert_test(
    'decrypt_envelope accurately restores original structured payload without data loss',
    $decrypted === $payload,
    "Decrypted: " . var_export($decrypted, true)
);

$token1 = $vault->generate_access_token();
$token2 = $vault->generate_access_token();
assert_test(
    'generate_access_token generates 64-char CSPRNG hex tokens with deterministic SHA-256 hash',
    strlen($token1) === 64 && strlen($token2) === 64 && $token1 !== $token2 && $vault->hash_token($token1) === $vault->hash_token($token1),
    "Tokens: {$token1}, {$token2}"
);

// ------------------------------------------------------------
// Test 2: Statutory HinSchG SLA Manager & Deadlines
// ------------------------------------------------------------
echo "\n[TEST GROUP 2] HinSchG § 17 SLA Timeline Engine\n";
$sla_manager = new \WMCyber\HinSchG\Compliance\HinSchGSlaManager();
$base_time = new \DateTimeImmutable('2026-08-01 10:00:00', new \DateTimeZone('UTC'));
$deadlines = $sla_manager->compute_deadlines($base_time);

assert_test(
    'compute_deadlines sets exact 7-day confirmation deadline (§ 17 Abs. 1 Nr. 1)',
    $deadlines['ack_deadline'] === '2026-08-08 10:00:00',
    "Ack Deadline: " . $deadlines['ack_deadline']
);

assert_test(
    'compute_deadlines sets exact 3-month feedback deadline (§ 17 Abs. 2)',
    $deadlines['feedback_deadline'] === '2026-11-01 10:00:00',
    "Feedback Deadline: " . $deadlines['feedback_deadline']
);

// ------------------------------------------------------------
// Test 3: Suite Hub Spoke Adapter & Compliance Contract
// ------------------------------------------------------------
echo "\n[TEST GROUP 3] Suite Hub Spoke Adapter Interface & Telemetry\n";
$adapter = new \WMCyber\HinSchG\Adapters\HinSchG_Spoke_Adapter();

assert_test(
    'Spoke Adapter returns exact module slug wm-hinschg-whistleblower',
    $adapter->get_module_slug() === 'wm-hinschg-whistleblower',
    "Slug: " . $adapter->get_module_slug()
);

assert_test(
    'Spoke Adapter reports HEALTHY status when audit chain is intact and SLAs are maintained',
    $adapter->get_health_status() === 'HEALTHY',
    "Status: " . $adapter->get_health_status()
);

$spoke_sbom = $adapter->get_sbom_data();
// The version constant defined above (bumped with the header): a literal here had to be edited on every release.
assert_test(
    'Spoke Adapter returns an SBOM component with bom-ref and file hash',
    $spoke_sbom['bom-ref'] === 'pkg:wordpress/wm-hinschg-whistleblower@' . WM_HINSCHG_VERSION && !empty($spoke_sbom['hashes'][0]['content']),
    "SBOM: " . var_export($spoke_sbom, true)
);

$action_res = $adapter->execute_action('self_test');
assert_test(
    'Spoke Adapter execute_action(self_test) returns success after verifying the audit chain',
    $action_res['success'] === true && str_contains($action_res['message'], 'Audit-Protokoll geprüft'),
    "Action: " . var_export($action_res, true)
);

$action_sla = $adapter->execute_action('sla_check');
assert_test(
    'Spoke Adapter execute_action(sla_check) reports the deadline check',
    $action_sla['success'] === true && str_contains($action_sla['message'], 'Fristenprüfung abgeschlossen'),
    "Action SLA: " . var_export($action_sla, true)
);

// ------------------------------------------------------------
// Test 4: The follow-up chat is sealed with the same envelope as the report
// ------------------------------------------------------------
echo "\n[TEST GROUP 4] Follow-up chat sealed with the vault envelope (was plaintext in encrypted_message)\n";

function hinschg_case(string $name, callable $fn): void {
    try {
        $fn();
    } catch (\Throwable $t) {
        assert_test($name, false, get_class($t) . ': ' . $t->getMessage());
    }
}

$mock_db_tables['wp_wm_whistle_messages'] = [];
$mock_db_tables['wp_wm_whistle_audit_log'] = [];
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$rest = new \WMCyber\HinSchG\API\RestController($vault, $sla_manager);

hinschg_case('Vault::seal_message / open_message round-trip; the stored form is an envelope, not the text', function () use ($vault) {
    $sealed = $vault->seal_message('Der Zeuge heißt Müller.', 'whistleblower');
    $json   = json_decode($sealed, true);
    $opened = $vault->open_message($sealed);
    assert_test(
        'Vault::seal_message / open_message round-trip; the stored form is an envelope, not the text',
        is_array($json) && isset($json['payload'], $json['key'], $json['tag'], $json['iv']) && !str_contains($sealed, 'Müller') && 'Der Zeuge heißt Müller.' === $opened['message'] && true === $opened['sealed'],
        var_export($opened, true)
    );
});

hinschg_case('Vault::open_message passes a legacy plaintext row through and says it was not sealed', function () use ($vault) {
    $opened = $vault->open_message('Alte Nachricht im Klartext.');
    assert_test(
        'Vault::open_message passes a legacy plaintext row through and says it was not sealed',
        'Alte Nachricht im Klartext.' === $opened['message'] && false === $opened['sealed'],
        var_export($opened, true)
    );
});

$submit = $rest->handle_report_submit(new WP_REST_Request(['category' => 'financial_fraud', 'description' => 'Doppelte Rechnungen an die Muster GmbH.']));
$case_id = $submit instanceof WP_REST_Response ? (string) ($submit->get_data()['case_public_id'] ?? '') : '';
$token   = $submit instanceof WP_REST_Response ? (string) ($submit->get_data()['access_token'] ?? '') : '';
assert_test('a report can be submitted in the mock environment (fixture for the chat tests)', '' !== $case_id && 64 === strlen($token), var_export($submit, true));

hinschg_case('whistleblower reply: the row in wm_whistle_messages does not contain the text', function () use ($rest, $case_id, $token) {
    global $mock_db_tables;
    $res = $rest->handle_whistleblower_reply(new WP_REST_Request(['case_public_id' => $case_id, 'access_token' => $token, 'message' => 'Ich habe die Belege gesehen.']));
    $row = end($mock_db_tables['wp_wm_whistle_messages']);
    assert_test(
        'whistleblower reply: the row in wm_whistle_messages does not contain the text',
        $res instanceof WP_REST_Response && 201 === $res->get_status() && $row && !str_contains((string) $row->encrypted_message, 'Belege') && is_array(json_decode((string) $row->encrypted_message, true)),
        var_export($row, true)
    );
});

hinschg_case('compliance officer ack and reply are sealed too', function () use ($rest, $case_id) {
    global $mock_db_tables;
    $rest->handle_admin_send_ack(new WP_REST_Request(['case_public_id' => $case_id]));
    $rest->handle_admin_send_reply(new WP_REST_Request(['case_public_id' => $case_id, 'message' => 'Wir prüfen die Rechnungen.']));
    $rows = array_values($mock_db_tables['wp_wm_whistle_messages']);
    $ok   = count($rows) >= 3;
    foreach (array_slice($rows, -2) as $r) {
        $ok = $ok && 'compliance_officer' === $r->sender_role && !str_contains((string) $r->encrypted_message, 'Eingangsbestätigung') && !str_contains((string) $r->encrypted_message, 'Rechnungen') && is_array(json_decode((string) $r->encrypted_message, true));
    }
    assert_test('compliance officer ack and reply are sealed too', $ok, var_export(array_slice($rows, -2), true));
});

hinschg_case('report/status opens the sealed messages for the token holder and flags legacy rows', function () use ($rest, $case_id, $token) {
    global $mock_db_tables, $wpdb;
    $report_id = (int) (end($mock_db_tables['wp_wm_whistle_messages'])->report_id ?? 0);
    $wpdb->insert('wp_wm_whistle_messages', ['report_id' => $report_id, 'sender_role' => 'compliance_officer', 'encrypted_message' => 'Altbestand im Klartext.', 'created_at' => current_time('mysql')]);
    $res  = $rest->handle_report_status(new WP_REST_Request(['case_public_id' => $case_id, 'access_token' => $token]));
    $data = $res instanceof WP_REST_Response ? (array) $res->get_data() : [];
    $msgs = (array) ($data['messages'] ?? []);
    $texts = array_map(fn($m) => (string) ($m['message'] ?? ''), $msgs);
    assert_test(
        'report/status opens the sealed messages for the token holder and flags legacy rows',
        4 === count($msgs)
            && 'Ich habe die Belege gesehen.' === $texts[0] && true === ($msgs[0]['sealed'] ?? null)
            && str_contains($texts[1], 'Eingangsbestätigung') && 'Wir prüfen die Rechnungen.' === $texts[2]
            && 'Altbestand im Klartext.' === $texts[3] && false === ($msgs[3]['sealed'] ?? null)
            && !isset($msgs[0]['encrypted_message']),
        var_export($msgs, true)
    );
});

// ------------------------------------------------------------
// The Meldestelle can read the report it is required to process, and every read is on the record
// ------------------------------------------------------------
echo "\n[TEST GROUP 4b] The Meldestelle reads a case (D13) and the read is audited\n";

hinschg_case('admin/case decrypts the report for the Meldestelle', function () use ($rest, $case_id) {
    $res  = $rest->handle_admin_read_case(new WP_REST_Request(['case_public_id' => $case_id]));
    $data = $res instanceof WP_REST_Response ? (array) $res->get_data() : [];
    assert_test(
        'admin/case decrypts the report for the Meldestelle',
        $res instanceof WP_REST_Response
            && 'Doppelte Rechnungen an die Muster GmbH.' === ($data['description'] ?? '')
            && 'financial_fraud' === ($data['category'] ?? '')
            && $case_id === ($data['case_public_id'] ?? ''),
        var_export(array_diff_key($data, ['messages' => 1]), true)
    );
});

hinschg_case('admin/case returns the whole thread in clear, not ciphertext', function () use ($rest, $case_id) {
    $res  = $rest->handle_admin_read_case(new WP_REST_Request(['case_public_id' => $case_id]));
    $msgs = $res instanceof WP_REST_Response ? (array) ($res->get_data()['messages'] ?? []) : [];
    $texts = array_map(fn($m) => (string) ($m['message'] ?? ''), $msgs);
    assert_test(
        'admin/case returns the whole thread in clear, not ciphertext',
        count($msgs) >= 3
            && in_array('Ich habe die Belege gesehen.', $texts, true)
            && in_array('Wir prüfen die Rechnungen.', $texts, true)
            && !isset($msgs[0]['encrypted_message']),
        var_export($texts, true)
    );
});

hinschg_case('every read of a case is written to the audit chain', function () use ($rest, $case_id) {
    global $mock_db_tables;
    $before = count($mock_db_tables['wp_wm_whistle_audit_log'] ?? []);
    $rest->handle_admin_read_case(new WP_REST_Request(['case_public_id' => $case_id]));
    $rows  = array_values($mock_db_tables['wp_wm_whistle_audit_log'] ?? []);
    $last  = end($rows);
    // § 8 HinSchG makes the content confidential towards everyone outside the channel, so WHO
    // opened a case and WHEN is part of what this log exists to answer. Reading is an event.
    assert_test(
        'every read of a case is written to the audit chain',
        count($rows) === $before + 1
            && $last && 'CASE_OPENED_BY_COMPLIANCE_OFFICER' === (string) $last->action
            && 'COMPLIANCE_OFFICER' === (string) $last->actor_role,
        var_export($last, true)
    );
});

hinschg_case('admin/case answers 404 for a case that does not exist, and writes no audit entry', function () use ($rest) {
    global $mock_db_tables;
    $before = count($mock_db_tables['wp_wm_whistle_audit_log'] ?? []);
    $res    = $rest->handle_admin_read_case(new WP_REST_Request(['case_public_id' => 'CASE-DOESNOTEXIST']));
    $after  = count($mock_db_tables['wp_wm_whistle_audit_log'] ?? []);
    assert_test(
        'admin/case answers 404 for a case that does not exist, and writes no audit entry',
        $res instanceof WP_Error && 'not_found' === $res->get_error_code() && $after === $before,
        get_class($res) . ' entries ' . $before . '->' . $after
    );
});

hinschg_case('admin/case says why it cannot decrypt instead of handing out the ciphertext', function () use ($rest) {
    global $wpdb;
    $wpdb->insert('wp_wm_whistle_reports', [
        'case_public_id'        => 'CASE-BROKENENV',
        'category'              => 'general_compliance',
        'encrypted_payload'     => base64_encode('not really a ciphertext'),
        'encrypted_key'         => json_encode(['key' => base64_encode('xx'), 'tag' => base64_encode('yy'), 'iv' => base64_encode('123456789012')]),
        'token_auth_hash'       => str_repeat('a', 64),
        'status'                => 'submitted',
        'ack_sla_deadline'      => current_time('mysql'),
        'feedback_sla_deadline' => current_time('mysql'),
        'created_at'            => current_time('mysql'),
        'updated_at'            => current_time('mysql'),
    ]);
    $res = $rest->handle_admin_read_case(new WP_REST_Request(['case_public_id' => 'CASE-BROKENENV']));
    $msg = $res instanceof WP_Error ? (string) $res->get_error_message() : '';
    assert_test(
        'admin/case says why it cannot decrypt instead of handing out the ciphertext',
        $res instanceof WP_Error
            && 'decryption_failed' === $res->get_error_code()
            && !str_contains($msg, 'not really a ciphertext')
            && str_contains($msg, 'Schlüsselquelle'),
        $msg
    );
});

// ------------------------------------------------------------
// Where the private key lives, and what a database dump is worth
// ------------------------------------------------------------
echo "\n[TEST GROUP 4c] The private key: three sources, and the migration for installs that ran\n";

/**
 * One probe process per mode: the three outcomes depend on PHP constants, and a constant cannot be
 * redefined. Testing them in one process tests whichever was defined first and calls the rest done.
 *
 * proc_open with an ARRAY, never a command string: no shell is involved, so nothing here can be
 * read as a shell metacharacter no matter what a mode name grows into later.
 *
 * @return array<string, mixed>
 */
function hinschg_probe_key(string $mode): array {
    $descriptors = [ 1 => ['pipe', 'w'], 2 => ['pipe', 'w'] ];
    $process = proc_open(
        [ PHP_BINARY, WM_HINSCHG_PATH . 'tests/probe-key-source.php', $mode ],
        $descriptors,
        $pipes
    );
    if (!is_resource($process)) {
        return ['error' => 'could not start the probe process'];
    }
    $stdout = (string) stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    $lines   = array_values(array_filter(explode("\n", trim($stdout))));
    $decoded = json_decode((string) end($lines), true);
    return is_array($decoded) ? $decoded : ['error' => trim($stdout . "\n" . $stderr)];
}

hinschg_case('with no constant configured the install says a database dump is enough — it does not stay silent', function () {
    $p = hinschg_probe_key('plain');
    assert_test(
        'with no constant configured the install says a database dump is enough — it does not stay silent',
        'database-plain' === ($p['source']['source'] ?? '') && true === ($p['source']['dump_is_enough'] ?? null) && true === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('a passphrase in wp-config.php makes a database dump insufficient, and reports still decrypt', function () {
    $p = hinschg_probe_key('passphrase');
    assert_test(
        'a passphrase in wp-config.php makes a database dump insufficient, and reports still decrypt',
        'database-encrypted' === ($p['source']['source'] ?? '') && false === ($p['source']['dump_is_enough'] ?? null) && true === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('the key in wp-config.php wins over the option, so moving it out actually moves it', function () {
    // The probe fills the option with "not-a-key-at-all". A round trip that still works can only
    // have used wp-config.php; if the option won, nothing would decrypt.
    $p = hinschg_probe_key('wp-config');
    assert_test(
        'the key in wp-config.php wins over the option, so moving it out actually moves it',
        'wp-config' === ($p['source']['source'] ?? '') && false === ($p['source']['dump_is_enough'] ?? null) && true === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('protect_private_key() encrypts the existing key in place and keeps every report readable', function () {
    $p = hinschg_probe_key('migrate');
    assert_test(
        'protect_private_key() encrypts the existing key in place and keeps every report readable',
        true === ($p['migration']['ok'] ?? null)
            && true === ($p['stored_changed'] ?? null)
            && false === ($p['stored_opens_without_passphrase'] ?? null)
            && true === ($p['stored_opens_with_passphrase'] ?? null)
            && true === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('protect_private_key() run twice changes nothing the second time', function () {
    $p = hinschg_probe_key('migrate-twice');
    assert_test(
        'protect_private_key() run twice changes nothing the second time',
        true === ($p['migration']['ok'] ?? null) && false === ($p['stored_changed'] ?? null) && true === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('protect_private_key() refuses a key encrypted with another passphrase and overwrites nothing', function () {
    // The dangerous case: overwrite here and every report filed so far becomes unreadable.
    $p = hinschg_probe_key('migrate-wrong-passphrase');
    assert_test(
        'protect_private_key() refuses a key encrypted with another passphrase and overwrites nothing',
        false === ($p['migration']['ok'] ?? null) && false === ($p['stored_changed'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('WM_HINSCHG_MASTER_KEY transparently migrates a legacy plaintext PEM in wp_options to sodium_crypto_secretbox and keeps reports readable', function () {
    $p = hinschg_probe_key('master-key');
    assert_test(
        'WM_HINSCHG_MASTER_KEY transparently migrates a legacy plaintext PEM in wp_options to sodium_crypto_secretbox and keeps reports readable',
        true === ($p['migrated_automatically'] ?? null)
            && 'database-sodium' === ($p['source']['source'] ?? '')
            && false === ($p['source']['dump_is_enough'] ?? null)
            && true === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('a tampered sodium_crypto_secretbox private key fails Poly1305 authentication and refuses decryption', function () {
    $p = hinschg_probe_key('master-key-tampered');
    assert_test(
        'a tampered sodium_crypto_secretbox private key fails Poly1305 authentication and refuses decryption',
        true === ($p['tampered_opens_null'] ?? null) && false === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('Schema::activate() with AUTH_KEY seals the generated RSA private key with sodium_crypto_secretbox and writes zero plaintext PEM to wp_options', function () {
    $p = hinschg_probe_key('activate-authkey');
    assert_test(
        'Schema::activate() with AUTH_KEY seals the generated RSA private key with sodium_crypto_secretbox and writes zero plaintext PEM to wp_options',
        false === ($p['has_plaintext_pem'] ?? null)
            && 'wm-sodium-authkey-v1:' === substr((string) ($p['stored_prefix'] ?? ''), 0, 21)
            && 'database-authkey-sodium' === ($p['source']['source'] ?? '')
            && false === ($p['source']['dump_is_enough'] ?? null)
            && true === ($p['round_trip'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('Schema::activate() with no wp-config.php secrets writes zero private key to wp_options or transients and leaves Zero-Knowledge custody unconfigured', function () {
    $p = hinschg_probe_key('activate-offline');
    assert_test(
        'Schema::activate() with no wp-config.php secrets writes zero private key to wp_options or transients and leaves Zero-Knowledge custody unconfigured',
        false === ($p['has_plaintext_pem'] ?? null)
            && false === ($p['has_offline_once'] ?? null)
            && '' === ($p['stored_prefix'] ?? 'x')
            && 'unconfigured-zero-knowledge' === ($p['source']['source'] ?? '')
            && false === ($p['source']['dump_is_enough'] ?? null)
            && false === ($p['can_seal'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('Vault::install_zero_knowledge_public_key() rejects private keys, stores only SPKI public key, and seals envelopes compatible with RSA-OAEP decryption', function () {
    $p = hinschg_probe_key('zero-knowledge-custody');
    assert_test(
        'Vault::install_zero_knowledge_public_key() rejects private keys, stores only SPKI public key, and seals envelopes compatible with RSA-OAEP decryption',
        true === ($p['refused_private'] ?? null)
            && true === ($p['installed_ok'] ?? null)
            && true === ($p['private_removed'] ?? null)
            && 'offline-custody' === ($p['source']['source'] ?? '')
            && false === ($p['source']['dump_is_enough'] ?? null)
            && true === ($p['can_seal'] ?? null)
            && true === ($p['offline_decrypts'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('WM_HINSCHG_AUDIT_KEY derives a dedicated HKDF-SHA256 audit key, dual-verifies pre-rotation AUTH_KEY rows, and refuses post-rotation AUTH_KEY downgrades', function () {
    $p = hinschg_probe_key('audit-key-dual');
    assert_test(
        'WM_HINSCHG_AUDIT_KEY derives a dedicated HKDF-SHA256 audit key, dual-verifies pre-rotation AUTH_KEY rows, and refuses post-rotation AUTH_KEY downgrades',
        'wp-config-dedicated' === ($p['key_source'] ?? '')
            && true === ($p['hash2_differs_auth'] ?? null)
            && true === ($p['dual_valid'] ?? null)
            && true === ($p['downgrade_refused'] ?? null),
        var_export($p, true)
    );
});

hinschg_case('report/status marks a message it cannot open instead of leaking ciphertext or dying', function () use ($rest, $case_id, $token) {
    global $mock_db_tables, $wpdb;
    $report_id = (int) (end($mock_db_tables['wp_wm_whistle_messages'])->report_id ?? 0);
    $broken = json_encode(['payload' => base64_encode('xx'), 'key' => base64_encode('yy'), 'tag' => base64_encode('zz'), 'iv' => base64_encode('123456789012')]);
    $wpdb->insert('wp_wm_whistle_messages', ['report_id' => $report_id, 'sender_role' => 'whistleblower', 'encrypted_message' => $broken, 'created_at' => current_time('mysql')]);
    $res  = $rest->handle_report_status(new WP_REST_Request(['case_public_id' => $case_id, 'access_token' => $token]));
    $last = $res instanceof WP_REST_Response ? end($res->get_data()['messages']) : null;
    assert_test(
        'report/status marks a message it cannot open instead of leaking ciphertext or dying',
        $res instanceof WP_REST_Response && $last && '' === ($last['message'] ?? 'x') && true === ($last['unreadable'] ?? null),
        var_export($last, true)
    );
});

// ------------------------------------------------------------
// Test 5: Desk, hub and portal show what the data and the code say
// ------------------------------------------------------------
echo "\n[TEST GROUP 5] Desk and hub read real deadline counts; portal, desk and uninstall carry no claims or dead options\n";

// Mocks for rendering the admin screens, the portal and uninstall.php.
$GLOBALS['mock_done_actions'] = [];
$GLOBALS['mock_menu_pages']   = [];
$GLOBALS['mock_shortcodes']   = [];
$GLOBALS['mock_deleted_options'] = [];
foreach ([
    'esc_attr'           => fn($t) => htmlspecialchars((string) $t, ENT_QUOTES, 'UTF-8'),
    'esc_textarea'       => fn($t) => htmlspecialchars((string) $t, ENT_QUOTES, 'UTF-8'),
    'esc_url'            => fn($u) => (string) $u,
    'esc_url_raw'        => fn($u) => (string) $u,
    'esc_html__'         => fn($t, $d = 'default') => htmlspecialchars((string) $t, ENT_QUOTES, 'UTF-8'),
    'esc_attr__'         => fn($t, $d = 'default') => htmlspecialchars((string) $t, ENT_QUOTES, 'UTF-8'),
    'rest_url'           => fn($p = '') => 'https://demo.example.com/wp-json/' . $p,
    'wp_create_nonce'    => fn($a = '') => 'nonce',
    'current_user_can'   => fn($c) => null === ($GLOBALS['mock_user_caps'] ?? null) || in_array($c, (array) $GLOBALS['mock_user_caps'], true),
    'check_admin_referer'=> fn(...$a) => true,
    'delete_transient'   => fn($k) => true,
    'wp_nonce_field'     => fn(...$a) => null,
    'wp_enqueue_style'   => fn(...$a) => null,
    'wp_enqueue_script'  => fn(...$a) => null,
    'wp_register_style'  => fn(...$a) => true,
    'wp_register_script' => fn(...$a) => true,
    'wp_localize_script' => fn(...$a) => true,
    'wp_add_dashboard_widget' => fn(...$a) => null,
    'wp_clear_scheduled_hook' => fn(...$a) => 0,
    'deactivate_plugins' => function ($p): void { $GLOBALS['mock_deactivated'][] = $p; },
    'wp_die'             => function ($m = '', $t = '', $a = []): void { throw new \RuntimeException('WP_DIE:' . (string) $m); },
] as $name => $impl) {
    if (!function_exists($name)) {
        $GLOBALS['mock_impl'][$name] = $impl;
        eval("function {$name}(...\$a) { return (\$GLOBALS['mock_impl']['{$name}'])(...\$a); }");
    }
}
if (!function_exists('esc_html_e')) {
    function esc_html_e(string $text, string $domain = 'default'): void { echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8'); }
}
if (!function_exists('esc_attr_e')) {
    function esc_attr_e(string $text, string $domain = 'default'): void { echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8'); }
}
if (!function_exists('_n')) {
    function _n(string $single, string $plural, int $number, string $domain = 'default'): string { return 1 === $number ? $single : $plural; }
}
if (!function_exists('do_action')) {
    function do_action(string $tag, ...$args): void { $GLOBALS['mock_done_actions'][] = $tag; }
}
if (!function_exists('add_menu_page')) {
    function add_menu_page(string $page_title, string $menu_title, string $capability, string $menu_slug, $callback = '', string $icon = '', $position = null): string {
        $GLOBALS['mock_menu_pages'][] = $menu_slug;
        $GLOBALS['mock_menu_caps'][$menu_slug] = $capability;
        return 'toplevel_page_' . $menu_slug;
    }
}
if (!function_exists('add_shortcode')) {
    function add_shortcode(string $tag, callable $callback): void { $GLOBALS['mock_shortcodes'][] = $tag; }
}
if (!function_exists('delete_option')) {
    function delete_option(string $option): bool {
        $GLOBALS['mock_deleted_options'][] = $option;
        // It used to only record the name. An uninstaller that deletes an option and a get_option()
        // that still returns it is the mock lying in the direction that passes.
        unset($GLOBALS['mock_options'][$option]);
        return true;
    }
}
if (!function_exists('__return_true')) {
    function __return_true(): bool { return true; }
}
if (!function_exists('delete_site_option')) {
    function delete_site_option(string $option): bool { return true; }
}
if (!function_exists('is_admin')) {
    function is_admin(): bool { return false; }
}
if (!function_exists('checked')) {
    function checked($checked, $current = true, bool $display = true): string {
        $result = ((string) $checked === (string) $current) ? ' checked="checked"' : '';
        if ($display) {
            echo $result;
        }
        return $result;
    }
}
if (!function_exists('plugin_basename')) {
    function plugin_basename(string $file): string {
        return 'wm-hinschg-whistleblower/' . basename($file);
    }
}
if (!function_exists('load_plugin_textdomain')) {
    function load_plugin_textdomain(string $domain, $deprecated = false, $plugin_rel_path = false): bool {
        $GLOBALS['mock_loaded_textdomains'][] = $domain;
        return true;
    }
}
if (!function_exists('wp_set_script_translations')) {
    function wp_set_script_translations(string $handle, string $domain = 'default', string $path = ''): bool {
        $GLOBALS['mock_script_translations'][$handle] = ['domain' => $domain, 'path' => $path];
        return true;
    }
}
if (!function_exists('register_block_type')) {
    function register_block_type(string $block_type, array $args = []): object {
        $GLOBALS['mock_registered_blocks'][$block_type] = $args;
        return (object) ['name' => $block_type, 'args' => $args];
    }
}
if (!function_exists('register_block_bindings_source')) {
    function register_block_bindings_source(string $source_name, array $source_properties): object {
        $GLOBALS['mock_block_bindings'][$source_name] = $source_properties;
        return (object) $source_properties;
    }
}
if (!class_exists('GenerateBlocks_Register_Dynamic_Tag')) {
    class GenerateBlocks_Register_Dynamic_Tag {
        public function __construct(array $options) {
            $GLOBALS['mock_gb_dynamic_tags'][$options['tag'] ?? ''] = $options;
        }
    }
}

// ------------------------------------------------------------
// Roles, users and capabilities.
//
// current_user_can was a flat `fn($c) => true`, so every capability check in the plugin passed
// whatever it asked for — a gate with no variance in its input, which is a gate that cannot fail.
// mock_user_caps === null keeps that behaviour for the tests that do not care; an array means the
// current user holds exactly those.
// ------------------------------------------------------------
$GLOBALS['mock_user_caps'] = null;
$GLOBALS['mock_roles']     = [
    'administrator' => ['manage_options' => true, 'read' => true],
    'editor'        => ['read' => true],
];
$GLOBALS['mock_users'] = [
    1 => ['login' => 'admin', 'role' => 'administrator', 'caps' => []],
    2 => ['login' => 'editor', 'role' => 'editor', 'caps' => []],
];

if (!class_exists('WP_Role')) {
    class WP_Role {
        public function __construct(public string $name) {}
        public function has_cap(string $cap): bool {
            return !empty($GLOBALS['mock_roles'][$this->name][$cap]);
        }
        public function add_cap(string $cap, bool $grant = true): void {
            $GLOBALS['mock_roles'][$this->name][$cap] = $grant;
        }
        public function remove_cap(string $cap): void {
            unset($GLOBALS['mock_roles'][$this->name][$cap]);
        }
    }
}
if (!class_exists('Mock_WP_User_HinSchG')) {
    class Mock_WP_User_HinSchG {
        public function __construct(public int $ID, public string $user_login) {}
        public function add_cap(string $cap, bool $grant = true): void {
            $GLOBALS['mock_users'][$this->ID]['caps'][$cap] = $grant;
        }
        public function remove_cap(string $cap): void {
            unset($GLOBALS['mock_users'][$this->ID]['caps'][$cap]);
            // A capability that comes from the role cannot be dropped per user in WordPress either;
            // the mock says so by leaving the role untouched, which is what makes the "would this
            // lock everyone out" guard honest.
        }
    }
}
if (!function_exists('get_role')) {
    function get_role(string $slug): ?WP_Role {
        return isset($GLOBALS['mock_roles'][$slug]) ? new WP_Role($slug) : null;
    }
}
if (!function_exists('add_role')) {
    function add_role(string $slug, string $name, array $caps = []): ?WP_Role {
        if (isset($GLOBALS['mock_roles'][$slug])) {
            return null;
        }
        $GLOBALS['mock_roles'][$slug] = $caps;
        $GLOBALS['mock_role_names'][$slug] = $name;
        return new WP_Role($slug);
    }
}
if (!function_exists('remove_role')) {
    function remove_role(string $slug): void {
        unset($GLOBALS['mock_roles'][$slug]);
    }
}
if (!function_exists('wp_roles')) {
    function wp_roles(): object {
        return new class {
            public array $roles;
            public function __construct() { $this->roles = $GLOBALS['mock_roles']; }
        };
    }
}
if (!function_exists('get_userdata')) {
    function get_userdata(int $id) {
        return isset($GLOBALS['mock_users'][$id])
            ? new Mock_WP_User_HinSchG($id, (string) $GLOBALS['mock_users'][$id]['login'])
            : false;
    }
}
if (!function_exists('get_user_by')) {
    function get_user_by(string $field, $value) {
        foreach ($GLOBALS['mock_users'] as $id => $u) {
            if ('login' === $field && $u['login'] === $value) {
                return new Mock_WP_User_HinSchG((int) $id, (string) $u['login']);
            }
        }
        return false;
    }
}
if (!function_exists('get_users')) {
    function get_users(array $args = []): array {
        $cap = (string) ($args['capability'] ?? '');
        $out = [];
        foreach ($GLOBALS['mock_users'] as $id => $u) {
            $from_role = !empty($GLOBALS['mock_roles'][$u['role']][$cap]);
            $from_user = !empty($u['caps'][$cap]);
            if ('' === $cap || $from_role || $from_user) {
                $out[] = (int) $id;
            }
        }
        return $out;
    }
}

$hinschg_emoji = '/[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]/u';
$breach_count  = static fn(): int => count(array_filter($GLOBALS['mock_done_actions'], fn($t) => 'wm_hinschg_sla_breach_detected' === $t));

// Five cases with known deadline states. ids continue from group 4; the table is replaced so nothing else is counted.
$mock_db_tables['wp_wm_whistle_reports'] = [];
$now_ts = time();
$at     = static fn(int $seconds): string => gmdate('Y-m-d H:i:s', $now_ts + $seconds);
$fixture = [
    // A: not acknowledged, 7-day deadline passed -> breached_ack, open.
    ['case_public_id' => 'CASE-AAAA0001', 'category' => 'financial_fraud', 'status' => 'submitted', 'ack_sla_deadline' => $at(-86400), 'feedback_sla_deadline' => $at(86400 * 80), 'ack_sent_at' => null, 'feedback_sent_at' => null],
    // B: acknowledged, feedback deadline passed -> breached_feedback, open.
    ['case_public_id' => 'CASE-BBBB0002', 'category' => 'data_protection', 'status' => 'acknowledged', 'ack_sla_deadline' => $at(-86400 * 90), 'feedback_sla_deadline' => $at(-3600), 'ack_sent_at' => $at(-86400 * 95), 'feedback_sent_at' => null],
    // C: not acknowledged, deadline in 24 h -> impending_ack, open.
    ['case_public_id' => 'CASE-CCCC0003', 'category' => 'no_such_category', 'status' => 'submitted', 'ack_sla_deadline' => $at(86400), 'feedback_sla_deadline' => $at(86400 * 85), 'ack_sent_at' => null, 'feedback_sent_at' => null],
    // D: closed with both deadlines passed and nothing sent -> counted nowhere.
    ['case_public_id' => 'CASE-DDDD0004', 'category' => 'workplace_safety', 'status' => 'closed', 'ack_sla_deadline' => $at(-86400 * 40), 'feedback_sla_deadline' => $at(-86400 * 2), 'ack_sent_at' => null, 'feedback_sent_at' => null],
    // E: feedback given -> counted nowhere.
    ['case_public_id' => 'CASE-EEEE0005', 'category' => 'it_security', 'status' => 'investigated', 'ack_sla_deadline' => $at(-86400 * 50), 'feedback_sla_deadline' => $at(-86400), 'ack_sent_at' => $at(-86400 * 55), 'feedback_sent_at' => $at(-86400 * 3)],
];
foreach ($fixture as $row) {
    $wpdb->insert('wp_wm_whistle_reports', $row + ['encrypted_payload' => 'x', 'encrypted_key' => 'x', 'token_auth_hash' => 'x', 'created_at' => $at(-86400 * 10), 'updated_at' => $at(-86400 * 10)]);
}

hinschg_case('status_counts counts each deadline state from the rows and fires no action', function () use ($sla_manager, $breach_count) {
    $before = $breach_count();
    $counts = $sla_manager->status_counts();
    assert_test(
        'status_counts counts each deadline state from the rows and fires no action',
        ['breached_ack' => 1, 'breached_feedback' => 1, 'impending_ack' => 1, 'open' => 3] === $counts && $before === $breach_count(),
        var_export($counts, true)
    );
});

hinschg_case('execute_hourly_check fires wm_hinschg_sla_breach_detected once when a deadline passed', function () use ($sla_manager, $breach_count) {
    $before = $breach_count();
    $res    = $sla_manager->execute_hourly_check();
    assert_test(
        'execute_hourly_check fires wm_hinschg_sla_breach_detected once when a deadline passed',
        1 === $res['breached_ack'] && 1 === $res['breached_feedback'] && $before + 1 === $breach_count(),
        var_export($res, true)
    );
});

hinschg_case('hub health and telemetry read the counts without firing the breach action', function () use ($adapter, $breach_count) {
    $before = $breach_count();
    $health = $adapter->get_health_status();
    $tm     = $adapter->get_telemetry_metrics();
    assert_test(
        'hub health and telemetry read the counts without firing the breach action',
        'DEGRADED' === $health && 1 === $tm['breached_ack_sla'] && 1 === $tm['breached_feed_sla'] && 1 === $tm['impending_warnings'] && 3 === $tm['open_cases'] && 5 === $tm['total_cases'] && $before === $breach_count(),
        $health . ' ' . var_export($tm, true)
    );
});

hinschg_case('hub health is NEEDS_CONFIG, not HEALTHY, without a key pair', function () use ($adapter) {
    global $mock_options;
    $reset = static function (): void {
        $prop = new \ReflectionProperty(\WMCyber\HinSchG\Core\Plugin::class, 'instance');
        $prop->setValue(null, null);
    };
    $saved = $mock_options['wm_hinschg_public_key'];
    unset($mock_options['wm_hinschg_public_key']);
    $reset();
    $health = $adapter->get_health_status();
    $mock_options['wm_hinschg_public_key'] = $saved;
    $reset();
    assert_test('hub health is NEEDS_CONFIG, not HEALTHY, without a key pair', 'NEEDS_CONFIG' === $health, $health);
});

$desk = new \WMCyber\HinSchG\Admin\AdminDashboard($vault, $sla_manager);

hinschg_case('the hub settings link opens the page the desk registers', function () use ($desk, $adapter) {
    $desk->register_admin_menu();
    $slug = (string) end($GLOBALS['mock_menu_pages']);
    assert_test(
        'the hub settings link opens the page the desk registers',
        '' !== $slug && str_ends_with((string) $adapter->get_settings_url(), 'admin.php?page=' . $slug),
        $slug . ' vs ' . $adapter->get_settings_url()
    );
});

$render = static function (callable $fn): string {
    ob_start();
    try {
        $fn();
    } finally {
        $out = (string) ob_get_clean();
    }
    return $out;
};

hinschg_case('dashboard widget shows the counted overdue and open cases', function () use ($desk, $render, $hinschg_emoji) {
    $html = $render(fn() => $desk->render_dashboard_widget());
    $kpis = [];
    preg_match_all('#<div class="wm-dash-kpi-val[^"]*">(\d+)</div>\s*<div class="wm-dash-kpi-lbl">([^<]+)</div>#', $html, $m, PREG_SET_ORDER);
    foreach ($m as $k) {
        $kpis[trim($k[2])] = (int) $k[1];
    }
    assert_test(
        'dashboard widget shows the counted overdue and open cases',
        ['Vorgänge' => 5, 'Offen' => 3, 'Überfällig' => 2] === $kpis && str_contains($html, '2 Fristen überschritten') && str_contains($html, 'is-warning') && !preg_match($hinschg_emoji, $html),
        var_export($kpis, true)
    );
});

hinschg_case('desk: overdue marks per row match the counters, statuses and categories are labelled, closed is never overdue', function () use ($desk, $render, $hinschg_emoji) {
    unset($_GET['tab']);
    $html = $render(fn() => $desk->render_dashboard_page());
    $rows = [];
    // The reference cell carries a link to the case view since 2026-09-19, so the pattern allows
    // the anchor around the <code>. Kept anchored on <tr>…</tr> rather than loosened to "anything
    // containing CASE-", which would still match if the table fell apart.
    preg_match_all('#<tr>\s*<td>\s*(?:<a[^>]*>\s*)?<code>(CASE-[A-Z0-9]+)</code>\s*(?:</a>\s*)?</td>(.*?)</tr>#s', $html, $m, PREG_SET_ORDER);
    foreach ($m as $r) {
        $rows[$r[1]] = $r[2];
    }
    $overdue = array_map(fn($cells) => substr_count($cells, '<strong>überfällig</strong>'), $rows);
    $ok = 5 === count($rows)
        && 1 === $overdue['CASE-AAAA0001'] && 1 === $overdue['CASE-BBBB0002'] && 0 === $overdue['CASE-CCCC0003'] && 0 === $overdue['CASE-DDDD0004'] && 0 === $overdue['CASE-EEEE0005']
        && str_contains($rows['CASE-AAAA0001'], 'Finanzbetrug') && str_contains($rows['CASE-AAAA0001'], 'Eingegangen')
        && str_contains($rows['CASE-CCCC0003'], 'no_such_category')
        && str_contains($rows['CASE-DDDD0004'], 'Abgeschlossen') && str_contains($rows['CASE-EEEE0005'], 'Rückmeldung gegeben')
        && str_contains($html, '2 Fristen überschritten')
        && !preg_match($hinschg_emoji, $html)
        && !preg_match('/Retrasos|PROTEGIDO|CIFRADO|CONTROL DE PLAZOS|Configuración/u', $html);
    assert_test('desk: overdue marks per row match the counters, statuses and categories are labelled, closed is never overdue', $ok, var_export($overdue, true));
});

hinschg_case('desk: every case row links to its case view, and the view renders the decrypted report', function () use ($desk, $render, $vault) {
    global $wpdb;
    unset($_GET['tab'], $_GET['case']);

    // A case with a REAL envelope, inserted into the table the desk reads: the five demo rows this
    // group seeds carry a payload that is not an envelope, so the view correctly refuses them and
    // testing against one would prove nothing about decryption.
    $envelope = $vault->encrypt_envelope(['category' => 'financial_fraud', 'description' => 'Sichtbarer Meldungstext für die Ansicht.', 'created_at' => current_time('mysql')]);
    $wpdb->insert('wp_wm_whistle_reports', [
        'case_public_id'        => 'CASE-READABLE1',
        'category'              => 'financial_fraud',
        'encrypted_payload'     => $envelope['payload'],
        'encrypted_key'         => json_encode(['key' => $envelope['key'], 'tag' => $envelope['tag'], 'iv' => $envelope['iv']]),
        'token_auth_hash'       => str_repeat('b', 64),
        'status'                => 'submitted',
        'ack_sla_deadline'      => current_time('mysql'),
        'feedback_sla_deadline' => current_time('mysql'),
        'created_at'            => current_time('mysql'),
        'updated_at'            => current_time('mysql'),
    ]);

    $list = $render(fn() => $desk->render_dashboard_page());
    $linked = substr_count($list, 'page=wm-hinschg-desk&case=CASE-');

    $_GET['case'] = 'CASE-READABLE1';
    $view = $render(fn() => $desk->render_dashboard_page());
    unset($_GET['case']);

    // The desk used to say outright that reading a report was not possible in this interface. The
    // notice that remains is about acknowledging and answering, which is still REST-only.
    assert_test(
        'desk: every case row links to its case view, and the view renders the decrypted report',
        $linked >= 5
            && str_contains($view, 'Sichtbarer Meldungstext für die Ansicht.')
            && str_contains($view, 'Zurück zur Übersicht')
            && !str_contains($view, 'Meldungen lesen, den Eingang'),
        'links=' . $linked . ' decrypted=' . (int) str_contains($view, 'Sichtbarer Meldungstext für die Ansicht.')
    );
});

hinschg_case('desk: an unprotected private key is stated on the screen, not left silent', function () use ($desk, $render) {
    unset($_GET['tab'], $_GET['case']);
    $html = $render(fn() => $desk->render_dashboard_page());
    // The suite runs without the constants, i.e. in the configuration where a database dump reads
    // every report. The screen has to say so, and say what to do about it.
    assert_test(
        'desk: an unprotected private key is stated on the screen, not left silent',
        str_contains($html, 'ungeschützt in der Datenbank')
            && str_contains($html, 'WM_HINSCHG_KEY_PASSPHRASE')
            && str_contains($html, 'wp hinschg protect-key'),
        substr($html, 0, 0) . 'notice missing'
    );
});

hinschg_case('desk: every shortcode the embed tab names is registered by the portal', function () use ($desk, $render) {
    (new \WMCyber\HinSchG\Frontend\WhistlePortal())->init();
    $_GET['tab'] = 'shortcode';
    $html = $render(fn() => $desk->render_dashboard_page());
    unset($_GET['tab']);
    preg_match_all('/\[([a-z_]+)\]/', $html, $m);
    $named = array_unique($m[1]);
    assert_test(
        'desk: every shortcode the embed tab names is registered by the portal',
        [] !== $named && [] === array_diff($named, $GLOBALS['mock_shortcodes']),
        'named ' . implode(',', $named) . ' registered ' . implode(',', $GLOBALS['mock_shortcodes'])
    );
});

hinschg_case('desk: no settings form, and a posted save_settings stores nothing', function () use ($desk, $render) {
    global $mock_options;
    $_GET['tab'] = 'deadlines';
    $html = $render(fn() => $desk->render_dashboard_page());
    unset($_GET['tab']);
    $_POST = ['wm_hinschg_action' => 'save_settings', 'wm_hinschg_nonce' => 'nonce', 'officer_email' => 'a@b.de'];
    $desk->handle_form_actions();
    $_POST = [];
    assert_test(
        'desk: no settings form, and a posted save_settings stores nothing',
        !str_contains($html, '<form') && str_contains($html, 'wm_hinschg_sla_breach_detected') && !array_key_exists('wm_hinschg_settings', $mock_options),
        substr($html, 0, 300)
    );
});

hinschg_case('portal: categories come from ReportCategories, no certification, E2E or zero-knowledge claims, no emoji', function () use ($render, $hinschg_emoji) {
    $html = (new \WMCyber\HinSchG\Frontend\WhistlePortal())->render_shortcode();
    preg_match_all('/<option value="([a-z_]+)"/', $html, $m);
    // BSI as a word and case-sensitive: "Website" contains "bsi".
    preg_match_all('/\bBSI\b|(?i:zero-knowledge|ende-zu-ende|garantie|geprüft)|§\s*2\b/u', $html, $claims);
    preg_match_all($hinschg_emoji, $html, $emoji);
    $ok = array_keys(\WMCyber\HinSchG\Compliance\ReportCategories::all()) === $m[1] && [] === $claims[0] && [] === $emoji[0];
    assert_test('portal: categories come from ReportCategories, no certification, E2E or zero-knowledge claims, no emoji', $ok, 'options ' . implode(',', $m[1]) . ' | claims ' . implode(',', $claims[0]) . ' | emoji ' . implode(',', $emoji[0]));
});

hinschg_case('portal script: no emoji and no encryption claims outside comments', function () use ($hinschg_emoji) {
    $js   = (string) file_get_contents(WM_HINSCHG_PATH . 'assets/js/portal-crypto.js');
    $code = preg_replace(['#/\*.*?\*/#s', '#^\s*//.*$#m'], '', $js);
    assert_test(
        'portal script: no emoji and no encryption claims outside comments',
        '' !== $code && !preg_match($hinschg_emoji, $code) && !preg_match('/Ende-zu-Ende|Verschlüsselt antworten|ordnungsgemäß/iu', $code) && str_contains($code, 'statusLabel(data.status)'),
        'see assets/js/portal-crypto.js'
    );
});

hinschg_case('REST: an unknown category is stored as general_compliance', function () use ($rest) {
    global $mock_db_tables;
    $res = $rest->handle_report_submit(new WP_REST_Request(['category' => '<b>anything</b>', 'description' => 'Test.']));
    $row = end($mock_db_tables['wp_wm_whistle_reports']);
    assert_test('REST: an unknown category is stored as general_compliance', $res instanceof WP_REST_Response && 'general_compliance' === ($row->category ?? ''), var_export($row, true));
});

hinschg_case('REST: a second acknowledgment is refused and keeps the first date', function () use ($rest, $case_id) {
    global $mock_db_tables;
    $find = static function () use ($case_id) {
        foreach ($GLOBALS['mock_db_tables']['wp_wm_whistle_reports'] as $r) {
            if ($case_id === $r->case_public_id) {
                return $r;
            }
        }
        return null;
    };
    // Group 4's case was replaced by the fixture: put it back as an acknowledged case.
    if (null === $find()) {
        $GLOBALS['wpdb']->insert('wp_wm_whistle_reports', ['case_public_id' => $case_id, 'category' => 'financial_fraud', 'created_at' => '2026-01-01 00:00:00', 'status' => 'investigated', 'ack_sent_at' => '2026-01-02 03:04:05', 'feedback_sent_at' => '2026-02-01 00:00:00', 'ack_sla_deadline' => '2026-01-08 00:00:00', 'feedback_sla_deadline' => '2026-04-01 00:00:00']);
    }
    $first = $find()->ack_sent_at;
    $res   = $rest->handle_admin_send_ack(new WP_REST_Request(['case_public_id' => $case_id]));
    assert_test(
        'REST: a second acknowledgment is refused and keeps the first date',
        $res instanceof WP_Error && 'already_acknowledged' === $res->get_error_code() && $first === $find()->ack_sent_at && 'investigated' === $find()->status,
        var_export($res, true)
    );
});

hinschg_case('REST: acknowledging a case that already has feedback keeps its status', function () use ($rest) {
    global $wpdb, $mock_db_tables;
    $wpdb->insert('wp_wm_whistle_reports', ['case_public_id' => 'CASE-FFFF0006', 'category' => 'general_compliance', 'created_at' => '2026-01-01 00:00:00', 'status' => 'investigated', 'ack_sent_at' => null, 'feedback_sent_at' => '2026-02-01 00:00:00', 'ack_sla_deadline' => '2026-01-08 00:00:00', 'feedback_sla_deadline' => '2026-04-01 00:00:00']);
    $id  = $wpdb->insert_id;
    $res = $rest->handle_admin_send_ack(new WP_REST_Request(['case_public_id' => 'CASE-FFFF0006']));
    $row = $mock_db_tables['wp_wm_whistle_reports'][$id];
    assert_test(
        'REST: acknowledging a case that already has feedback keeps its status',
        $res instanceof WP_REST_Response && null !== $row->ack_sent_at && 'investigated' === $row->status,
        var_export($row, true)
    );
});

assert_test(
    'unknown status and category keys are shown as stored; an unknown category is stored as the default',
    'something_new' === \WMCyber\HinSchG\Compliance\CaseStatus::label('something_new')
        && 'Abgeschlossen' === \WMCyber\HinSchG\Compliance\CaseStatus::label('closed')
        && 'x_y' === \WMCyber\HinSchG\Compliance\ReportCategories::label('x_y')
        && 'general_compliance' === \WMCyber\HinSchG\Compliance\ReportCategories::normalize('x_y')
        && 'it_security' === \WMCyber\HinSchG\Compliance\ReportCategories::normalize('it_security')
);

hinschg_case('desk quick guide: § 12 Abs. 3 extends the duty, the form covers only the written channel, § 11 Abs. 5 deletion is not automated', function () use ($desk, $render) {
    unset($_GET['tab']);
    $html = $render(fn() => $desk->render_dashboard_page());
    preg_match('#<section class="wm-quick-guide">(.*?)</section>#s', $html, $g);
    $guide = $g[1] ?? '';
    assert_test(
        'desk quick guide: § 12 Abs. 3 extends the duty, the form covers only the written channel, § 11 Abs. 5 deletion is not automated',
        str_contains($guide, 'unabhängig von der Zahl der Beschäftigten') && !str_contains($guide, 'Ausnahmen')
            && str_contains($guide, '§ 16 Abs. 3') && str_contains($guide, 'nur den schriftlichen Weg')
            && str_contains($guide, '§ 11 Abs. 5') && str_contains($guide, 'löscht nichts selbst'),
        strip_tags($guide)
    );
});

hinschg_case('a signature mismatch names both causes: an edited entry or another AUTH_KEY', function () {
    global $mock_db_tables, $mock_options;
    $table = 'wp_wm_whistle_audit_log';
    $saved = array_map(fn($r) => clone $r, $mock_db_tables[$table]);
    $tip   = $mock_options['wm_whistle_audit_tip'] ?? null;
    $first = array_key_first($mock_db_tables[$table]);
    $mock_db_tables[$table][$first]->current_hash = str_repeat('a', 64);
    $r = \WMCyber\HinSchG\Crypto\Vault::verify_audit_chain();
    $mock_db_tables[$table] = $saved;
    $mock_options['wm_whistle_audit_tip'] = $tip;
    assert_test(
        'a signature mismatch names both causes: an edited entry or another AUTH_KEY',
        null !== $first && false === $r['valid'] && str_contains((string) $r['error'], 'verändert') && str_contains((string) $r['error'], 'AUTH_KEY'),
        var_export($r, true)
    );
});

hinschg_case('the WordPress tests that write to the audit log refuse to run without WM_HINSCHG_SCRATCH_INSTALL', function () {
    $bad = [];
    foreach (['tests/test-audit-chain-forgery.php', 'tests/test-chat-encryption.php'] as $file) {
        $src   = (string) file_get_contents(WM_HINSCHG_PATH . $file);
        $gate  = strpos($src, "getenv( 'WM_HINSCHG_SCRATCH_INSTALL' )");
        $write = min(array_filter([strpos($src, '$wpdb->query('), strpos($src, 'wm_c_post(\'report/submit\''), strpos($src, "wm_c_post( 'report/submit'")], fn($x) => false !== $x) ?: [PHP_INT_MAX]);
        if (false === $gate || $gate > $write || !preg_match("/getenv\( 'WM_HINSCHG_SCRATCH_INSTALL' \) \) \{\s*echo [^;]+;\s*exit\( 1 \);/", $src)) {
            $bad[] = $file;
        }
    }
    assert_test('the WordPress tests that write to the audit log refuse to run without WM_HINSCHG_SCRATCH_INSTALL', [] === $bad, implode(', ', $bad));
});

hinschg_case('default uninstall preserves statutory 3-year HinSchG § 11 records and keys; opt-in uninstall wipes everything cleanly', function () {
    global $wpdb, $mock_options;
    $src = '';
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(WM_HINSCHG_PATH . 'includes', FilesystemIterator::SKIP_DOTS)) as $f) {
        $src .= (string) file_get_contents((string) $f);
    }
    preg_match_all("/update_option\(\s*'([a-z_]+)'/", $src, $o);
    preg_match_all("/const\s+[A-Z_]*OPTION\s*=\s*'([a-z_]+)'/", $src, $t);
    preg_match_all("/set_transient\(\s*'([a-z_]+)'/", $src, $tr);
    preg_match_all("/\\\$key\s*=\s*'([a-z_]+)'/", $src, $rl);
    preg_match_all("/\\\$wpdb->prefix\s*\.\s*'(wm_whistle_[a-z_]+)'/", (string) file_get_contents(WM_HINSCHG_PATH . 'includes/Database/Schema.php'), $tb);
    $options    = array_unique(array_merge($o[1], $t[1]));
    $prefixes   = array_unique(array_merge($tr[1], $rl[1]));
    $tables     = array_unique($tb[1]);

    if (!defined('WP_UNINSTALL_PLUGIN')) {
        define('WP_UNINSTALL_PLUGIN', 'wm-hinschg-whistleblower/wm-hinschg-whistleblower.php');
    }

    // 1. Default uninstall (opt-in OFF): preserves reports, messages, audit log, keys, chain tip and capabilities.
    $saved_options = $mock_options;
    $mock_options['wm_hinschg_settings'] = ['legacy' => 1];
    $mock_options['wm_hinschg_delete_data_on_uninstall'] = '0';
    $mock_options['wm_whistle_audit_tip'] = ['hash' => str_repeat('c', 64), 'count' => 1];
    $mock_options['wm_hinschg_recovery_public_key'] = "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n";
    $GLOBALS['mock_deleted_options'] = [];
    $wpdb->queries = [];
    require WM_HINSCHG_PATH . 'uninstall.php';
    $default_sql = implode("\n", $wpdb->queries);
    $default_ok  = !str_contains($default_sql, 'DROP TABLE')
        && isset($mock_options['wm_hinschg_private_key'], $mock_options['wm_hinschg_public_key'], $mock_options['wm_hinschg_recovery_public_key'], $mock_options['wm_whistle_audit_tip'])
        && !isset($mock_options['wm_hinschg_settings'], $mock_options['wm_hinschg_delete_data_on_uninstall']);
    assert_test(
        'default uninstall preserves statutory 3-year HinSchG § 11 records, keys and audit tip',
        $default_ok,
        'default_sql: ' . $default_sql
    );

    // 2. Opt-in full wipe (wm_hinschg_delete_data_on_uninstall = 1): removes every option, transient prefix, role and table.
    $mock_options['wm_hinschg_delete_data_on_uninstall'] = '1';
    $GLOBALS['mock_deleted_options'] = [];
    $wpdb->queries = [];
    require WM_HINSCHG_PATH . 'uninstall.php';
    $sql = implode("\n", $wpdb->queries);

    $missing = array_diff($options, $GLOBALS['mock_deleted_options']);
    foreach ($prefixes as $prefix) {
        if (!str_contains(stripslashes(str_replace('\\_', '_', $sql)), '_transient_' . $prefix)) {
            $missing[] = 'transient ' . $prefix;
        }
    }
    foreach ($tables as $table) {
        if (!str_contains($sql, 'DROP TABLE IF EXISTS wp_' . $table)) {
            $missing[] = 'table ' . $table;
        }
    }
    $mock_options = $saved_options;
    \WMCyber\HinSchG\Security\Capabilities::install();
    assert_test(
        'opt-in uninstall.php deletes every option, transient prefix and table the plugin writes',
        count($options) >= 3 && count($prefixes) >= 2 && 3 === count($tables) && [] === $missing,
        'missing: ' . implode(', ', $missing) . ' | options ' . implode(',', $options) . ' | prefixes ' . implode(',', $prefixes)
    );
});

// ------------------------------------------------------------
// Who may open a report: the plugin's own capability, not manage_options
// ------------------------------------------------------------
echo "\n[TEST GROUP 6] The desk and the admin routes check wm_hinschg_read_cases\n";

if (!function_exists('register_rest_route')) {
    function register_rest_route(string $namespace, string $route, array $args = []): bool {
        $GLOBALS['mock_rest_routes'][$route] = $args;
        return true;
    }
}

/** Register the routes for real and hand back the permission callbacks, keyed by route. */
$hinschg_route_perms = static function () use ($vault, $sla_manager): array {
    global $mock_actions;
    $GLOBALS['mock_rest_routes'] = [];
    $mock_actions['rest_api_init'] = [];
    (new \WMCyber\HinSchG\API\RestController($vault, $sla_manager))->register_routes();
    foreach ($mock_actions['rest_api_init'] as $cb) {
        $cb();
    }
    return array_map(fn(array $a) => $a['permission_callback'] ?? null, $GLOBALS['mock_rest_routes']);
};

hinschg_case('an administrator without the capability cannot reach the admin routes', function () use ($hinschg_route_perms) {
    $perms  = $hinschg_route_perms();
    $admin  = array_filter($perms, fn($r) => str_starts_with($r, '/admin/'), ARRAY_FILTER_USE_KEY);
    $public = array_filter($perms, fn($r) => str_starts_with($r, '/report/'), ARRAY_FILTER_USE_KEY);

    $saved = $GLOBALS['mock_user_caps'];
    // The case this exists for: manage_options is not something an install can take away from an
    // administrator, so while the routes checked it, every administrator could read every report.
    $GLOBALS['mock_user_caps'] = ['manage_options'];
    $with_admin_rights = array_map(fn($cb) => (bool) $cb(), $admin);
    $GLOBALS['mock_user_caps'] = [\WMCyber\HinSchG\Security\Capabilities::READ_CASES];
    $with_capability = array_map(fn($cb) => (bool) $cb(), $admin);
    $GLOBALS['mock_user_caps'] = [];
    $with_nothing   = array_map(fn($cb) => (bool) $cb(), $admin);
    $public_anyway  = array_map(fn($cb) => (bool) $cb(), $public);
    $GLOBALS['mock_user_caps'] = $saved;

    assert_test(
        'an administrator without the capability cannot reach the admin routes',
        4 === count($admin) && 3 === count($public)
            && [] === array_filter($with_admin_rights)
            && count($with_capability) === count(array_filter($with_capability))
            && [] === array_filter($with_nothing)
            && count($public_anyway) === count(array_filter($public_anyway)),
        'admin routes ' . implode(',', array_keys($admin))
            . ' | manage_options ' . json_encode($with_admin_rights)
            . ' | capability ' . json_encode($with_capability)
    );
});

hinschg_case('the desk menu and the dashboard widget are gated by the capability, not by manage_options', function () use ($desk) {
    $saved = $GLOBALS['mock_user_caps'];
    $desk->register_admin_menu();
    $menu_cap = (string) ($GLOBALS['mock_menu_caps']['wm-hinschg-desk'] ?? '');

    $widget_for = static function (array $caps) use ($desk): bool {
        $GLOBALS['mock_user_caps'] = $caps;
        $before = count($GLOBALS['mock_dashboard_widgets'] ?? []);
        $GLOBALS['mock_impl']['wp_add_dashboard_widget'] = static function (...$a) {
            $GLOBALS['mock_dashboard_widgets'][] = $a[0] ?? '';
        };
        $desk->register_dashboard_widget();
        return count($GLOBALS['mock_dashboard_widgets'] ?? []) > $before;
    };

    $admin_only = $widget_for(['manage_options']);
    $with_cap   = $widget_for([\WMCyber\HinSchG\Security\Capabilities::READ_CASES]);
    $GLOBALS['mock_user_caps'] = $saved;

    assert_test(
        'the desk menu and the dashboard widget are gated by the capability, not by manage_options',
        \WMCyber\HinSchG\Security\Capabilities::READ_CASES === $menu_cap && false === $admin_only && true === $with_cap,
        'menu cap ' . $menu_cap . ' | widget for manage_options ' . var_export($admin_only, true) . ' | for capability ' . var_export($with_cap, true)
    );
});

hinschg_case('an install that already ran gets the capability on upgrade, so nobody is locked out of their own desk', function () {
    global $mock_options, $mock_roles;
    $caps = \WMCyber\HinSchG\Security\Capabilities::class;
    // The state of an install updating into this version: no role, no capability, no version.
    unset($mock_options[$caps::VERSION_OPTION], $mock_roles[$caps::ROLE], $mock_roles['administrator'][$caps::READ_CASES]);
    $before = get_role('administrator')->has_cap($caps::READ_CASES);

    $caps::maybe_upgrade();

    assert_test(
        'an install that already ran gets the capability on upgrade, so nobody is locked out of their own desk',
        false === $before
            && true === get_role('administrator')->has_cap($caps::READ_CASES)
            && isset($mock_roles[$caps::ROLE][$caps::READ_CASES])
            && $caps::VERSION === (int) get_option($caps::VERSION_OPTION, 0),
        'before ' . var_export($before, true) . ' roles ' . implode(',', $caps::roles_with_access())
    );
});

hinschg_case('the Meldestelle role can open reports without being able to administer the site', function () {
    global $mock_roles;
    $caps = \WMCyber\HinSchG\Security\Capabilities::class;
    assert_test(
        'the Meldestelle role can open reports without being able to administer the site',
        !empty($mock_roles[$caps::ROLE][$caps::READ_CASES]) && empty($mock_roles[$caps::ROLE]['manage_options']),
        var_export($mock_roles[$caps::ROLE] ?? null, true)
    );
});

hinschg_case('revoking the last access is refused, and changes nothing', function () {
    global $mock_roles, $mock_users;
    $caps = \WMCyber\HinSchG\Security\Capabilities::class;
    $saved_roles = $mock_roles;
    $saved_users = $mock_users;

    // Only the administrator role holds it: taking it away here leaves the encrypted reports with
    // nobody able to open them, while the § 17 seven-day clock keeps running.
    $mock_roles[$caps::ROLE][$caps::READ_CASES] = false;
    unset($mock_roles[$caps::ROLE][$caps::READ_CASES]);
    $holders_before = $caps::holders();
    $refused = $caps::revoke_from_role('administrator');
    $still   = get_role('administrator')->has_cap($caps::READ_CASES);

    // With someone else able to open reports, the same call goes through.
    $mock_users[3] = ['login' => 'meldestelle', 'role' => 'editor', 'caps' => [$caps::READ_CASES => true]];
    $allowed = $caps::revoke_from_role('administrator');
    $gone    = ! get_role('administrator')->has_cap($caps::READ_CASES);

    $mock_roles = $saved_roles;
    $mock_users = $saved_users;

    assert_test(
        'revoking the last access is refused, and changes nothing',
        [] !== $holders_before
            && false === $refused['ok'] && true === $still && str_contains($refused['message'], '§ 17')
            && true === $allowed['ok'] && true === $gone,
        'refused ' . var_export($refused, true) . ' | allowed ' . var_export($allowed, true)
    );
});

hinschg_case('uninstall takes the role and the capability with it', function () {
    global $mock_roles, $mock_options;
    $caps = \WMCyber\HinSchG\Security\Capabilities::class;
    $caps::install();
    $had = isset($mock_roles[$caps::ROLE]) && get_role('administrator')->has_cap($caps::READ_CASES);

    $caps::remove();

    $role_gone    = ! isset($mock_roles[$caps::ROLE]);
    $no_holders   = [] === $caps::roles_with_access();
    $version_gone = ! array_key_exists($caps::VERSION_OPTION, $mock_options);

    $caps::install(); // later tests render against a normal install

    assert_test(
        'uninstall takes the role and the capability with it',
        true === $had && $role_gone && $no_holders && $version_gone,
        'had ' . var_export($had, true) . ' | role gone ' . var_export($role_gone, true)
            . ' | no holders ' . var_export($no_holders, true) . ' | version gone ' . var_export($version_gone, true)
    );
});

// readme.txt is the text WordPress shows and the directory publishes, and nothing watched it: for a
// day after admin/case shipped it still told the reader that no route decrypts a report for the
// officer and that the private key sits in the options table. Both had stopped being true. The input
// here is the CODE, never a hand-written list — a list would go stale exactly the same way.
hinschg_case('readme.txt names every admin route and CLI subcommand, and claims nothing the code contradicts', function () {
    $readme = (string) file_get_contents(WM_HINSCHG_PATH . 'readme.txt');
    $guide  = (string) file_get_contents(WM_HINSCHG_PATH . 'docs/DEVELOPER-GUIDE.md');
    $rest   = (string) file_get_contents(WM_HINSCHG_PATH . 'includes/API/RestController.php');
    $cli    = (string) file_get_contents(WM_HINSCHG_PATH . 'includes/CLI/HinSchGCommand.php');

    preg_match_all("#register_rest_route\(\s*self::NAMESPACE,\s*'/(admin/[a-z-]+)'#", $rest, $r);
    $missing = [];
    foreach (array_unique($r[1]) as $route) {
        if (!str_contains($readme, '`' . $route . '`')) {
            $missing[] = 'route ' . $route;
        }
        // The developer guide has a row per route. It went stale the same way readme.txt did:
        // admin/case was missing from it and the three others still named manage_options.
        if (!preg_match('#^\|\s*`' . preg_quote($route, '#') . '`\s*\|#m', $guide)) {
            $missing[] = 'guide row ' . $route;
        }
    }

    // Whatever the routes check is what the guide's "Who" column has to say.
    preg_match('#/admin/cases\'.*?\'permission_callback\'\s*=>\s*fn\(\)\s*=>\s*([A-Za-z:_\\\\]+)#s', $rest, $checked);
    preg_match_all('#^\|\s*`admin/[a-z-]+`\s*\|[^|]*\|\s*`([a-z_]+)`\s*\|#m', $guide, $documented);
    $wrong_capability = array_values(array_unique(array_filter(
        $documented[1] ?? [],
        fn(string $cap) => \WMCyber\HinSchG\Security\Capabilities::READ_CASES !== $cap
    )));

    // WP-CLI takes the subcommand from @subcommand when the docblock carries one, else from the
    // method name, so key_status would be announced as key-status only because of its annotation.
    preg_match_all('#(?:@subcommand\s+([a-z-]+)\s*\*/\s*)?public function ([a-z_]+)\(\s*array \$args#', $cli, $c, PREG_SET_ORDER);
    foreach ($c as $m) {
        $sub = '' !== ($m[1] ?? '') ? $m[1] : $m[2];
        if (!str_contains($readme, 'wp hinschg ' . $sub)) {
            $missing[] = 'cli ' . $sub;
        }
    }

    $contradiction = str_contains($rest, "'/admin/case'")
        && 1 === preg_match('#Meldestelle cannot read|no screen or route decrypts#', $readme);

    assert_test(
        'readme.txt names every admin route and CLI subcommand, and claims nothing the code contradicts',
        [] === $missing && !$contradiction && [] === $wrong_capability
            && count($r[1]) >= 4 && count($c) >= 5 && count($documented[1] ?? []) >= 4,
        'missing: ' . implode(', ', $missing) . ' | contradiction: ' . var_export($contradiction, true)
            . ' | documented capability: ' . implode(',', $wrong_capability)
            . ' | routes ' . count($r[1]) . ' | cli ' . count($c) . ' | guide rows ' . count($documented[1] ?? [])
    );
});

// ------------------------------------------------------------
// Test 7: Gutenberg Block, Ecosystem Bridges, Anonymous Portal Guard & Uninstall Checkbox
// ------------------------------------------------------------
echo "\n[TEST GROUP 7] Gutenberg block editorScript, hooks, Block Bindings, GenerateBlocks & anonymous portal guard\n";

hinschg_case('Gutenberg block wm/hinschg-portal ships compiled build assets, editorScript and script translations', function () {
    $block_json_path = WM_HINSCHG_PATH . 'blocks/portal/block.json';
    $block_meta      = is_file($block_json_path) ? json_decode((string) file_get_contents($block_json_path), true) : null;
    $asset_file      = WM_HINSCHG_PATH . 'build/index.asset.php';
    $build_js        = WM_HINSCHG_PATH . 'build/index.js';

    $GLOBALS['mock_registered_blocks']   = [];
    $GLOBALS['mock_script_translations'] = [];
    $GLOBALS['mock_registered_scripts']  = [];
    $GLOBALS['mock_impl']['wp_register_script'] = static function (string $handle, string $src = '', array $deps = [], $ver = false) {
        $GLOBALS['mock_registered_scripts'][$handle] = ['src' => $src, 'deps' => $deps, 'ver' => $ver];
        return true;
    };

    $portal = new \WMCyber\HinSchG\Frontend\WhistlePortal();
    $portal->register_gutenberg_block();

    $asset = is_file($asset_file) ? require $asset_file : [];
    $ok = is_array($block_meta)
        && 'wm/hinschg-portal' === ($block_meta['name'] ?? '')
        && 'wm-hinschg-blocks-editor' === ($block_meta['editorScript'] ?? '')
        && is_file($build_js)
        && str_contains((string) file_get_contents($build_js), 'InspectorControls')
        && str_contains((string) file_get_contents($build_js), 'ServerSideRender')
        && in_array('wp-server-side-render', (array) ($asset['dependencies'] ?? []), true)
        && isset($GLOBALS['mock_registered_scripts']['wm-hinschg-blocks-editor'])
        && 'wm-hinschg-whistleblower' === ($GLOBALS['mock_script_translations']['wm-hinschg-blocks-editor']['domain'] ?? '')
        && isset($GLOBALS['mock_registered_blocks'][WM_HINSCHG_PATH . 'blocks/portal']);

    assert_test(
        'Gutenberg block wm/hinschg-portal ships compiled build assets, editorScript and script translations',
        $ok,
        var_export(['meta' => $block_meta, 'scripts' => $GLOBALS['mock_registered_scripts']], true)
    );
});

hinschg_case('Plugin::boot fires wm_hinschg_ready and WhistlePortal registers Block Bindings, GenerateBlocks tag and wm_hinschg_portal_config filter', function () {
    global $mock_filters;
    $GLOBALS['mock_done_actions']    = [];
    $GLOBALS['mock_block_bindings']  = [];
    $GLOBALS['mock_gb_dynamic_tags'] = [];
    $GLOBALS['mock_localized']       = [];
    $GLOBALS['mock_impl']['wp_localize_script'] = static function (string $handle, string $name, array $data) {
        $GLOBALS['mock_localized'][$handle] = ['name' => $name, 'data' => $data];
        return true;
    };

    \WMCyber\HinSchG\Core\Plugin::instance()->boot();

    $portal = new \WMCyber\HinSchG\Frontend\WhistlePortal();
    $portal->register_block_bindings();
    $portal->register_generateblocks_tags();

    add_filter('wm_hinschg_portal_config', static function (array $cfg): array {
        $cfg['customMarker'] = 'filtered-ok';
        return $cfg;
    });
    $portal->enqueue_frontend_assets();
    $mock_filters['wm_hinschg_portal_config'] = [];

    $binding_cb = $GLOBALS['mock_block_bindings']['wm-hinschg/status']['get_value_callback'] ?? null;
    $gb_cb      = $GLOBALS['mock_gb_dynamic_tags']['wm_hinschg_status']['return'] ?? null;

    $saved_caps = $GLOBALS['mock_user_caps'];
    $GLOBALS['mock_user_caps'] = [];
    $public_label = is_callable($binding_cb) ? $binding_cb(['key' => 'channel_label']) : '';
    $hidden_open  = is_callable($binding_cb) ? $binding_cb(['key' => 'open_cases']) : 'leaked';
    $gb_label     = is_callable($gb_cb) ? $gb_cb(['key' => 'ack_days']) : '';
    $GLOBALS['mock_user_caps'] = $saved_caps;

    assert_test(
        'Plugin::boot fires wm_hinschg_ready and WhistlePortal registers Block Bindings, GenerateBlocks tag and wm_hinschg_portal_config filter',
        in_array('wm_hinschg_ready', $GLOBALS['mock_done_actions'], true)
            && 'Interne Meldestelle aktiv' === $public_label
            && '' === $hidden_open
            && str_contains($gb_label, '7 Tage')
            && 'filtered-ok' === ($GLOBALS['mock_localized']['wm-hinschg-portal-js']['data']['customMarker'] ?? ''),
        var_export(['actions' => $GLOBALS['mock_done_actions'], 'label' => $public_label, 'gb' => $gb_label], true)
    );
});

hinschg_case('public REST routes use check_anonymous_portal_access (never __return_true), honour wm_hinschg_rest_rate_limit and never store raw IPs', function () use ($hinschg_route_perms, $vault, $sla_manager) {
    global $mock_filters;
    $perms  = $hinschg_route_perms();
    $public = array_filter($perms, fn($r) => str_starts_with($r, '/report/'), ARRAY_FILTER_USE_KEY);
    $no_return_true = !in_array('__return_true', $public, true);

    $GLOBALS['mock_transients'] = [];
    $_SERVER['REMOTE_ADDR'] = '198.51.100.77';
    add_filter('wm_hinschg_rest_rate_limit', static fn(int $limit, string $bucket): int => 'portal' === $bucket ? 2 : $limit, 10, 2);

    $ctrl = new \WMCyber\HinSchG\API\RestController($vault, $sla_manager);
    $r1   = $ctrl->check_anonymous_portal_access();
    $r2   = $ctrl->check_anonymous_portal_access();
    $r3   = $ctrl->check_anonymous_portal_access();

    $mock_filters['wm_hinschg_rest_rate_limit'] = [];
    $transient_keys = implode(',', array_keys($GLOBALS['mock_transients']));
    $GLOBALS['mock_transients'] = [];

    assert_test(
        'public REST routes use check_anonymous_portal_access (never __return_true), honour wm_hinschg_rest_rate_limit and never store raw IPs',
        $no_return_true
            && true === $r1
            && true === $r2
            && $r3 instanceof WP_Error
            && 'wm_hinschg_rate_limited' === $r3->get_error_code()
            && !str_contains($transient_keys, '198.51.100.77'),
        'transient_keys=' . $transient_keys
    );
});

hinschg_case('desk uninstall tab renders the delete_data_on_uninstall checkbox via checked()', function () use ($desk, $render) {
    global $mock_options;
    $saved_opt  = $mock_options['wm_hinschg_delete_data_on_uninstall'] ?? null;
    $saved_caps = $GLOBALS['mock_user_caps'];
    $GLOBALS['mock_user_caps'] = ['manage_options', \WMCyber\HinSchG\Security\Capabilities::READ_CASES];
    $_GET['tab'] = 'uninstall';

    $mock_options['wm_hinschg_delete_data_on_uninstall'] = '0';
    $html_unchecked = $render(fn() => $desk->render_dashboard_page());

    $mock_options['wm_hinschg_delete_data_on_uninstall'] = '1';
    $html_checked = $render(fn() => $desk->render_dashboard_page());

    unset($_GET['tab']);
    $GLOBALS['mock_user_caps'] = $saved_caps;
    if (null === $saved_opt) {
        unset($mock_options['wm_hinschg_delete_data_on_uninstall']);
    } else {
        $mock_options['wm_hinschg_delete_data_on_uninstall'] = $saved_opt;
    }

    assert_test(
        'desk uninstall tab renders the delete_data_on_uninstall checkbox via checked()',
        str_contains($html_unchecked, 'name="delete_data_on_uninstall"')
            && !str_contains($html_unchecked, 'checked="checked"')
            && str_contains($html_checked, 'checked="checked"'),
        'unchecked/checked mismatch'
    );
});

hinschg_case('Vault::log_audit_event() fails closed when MySQL GET_LOCK fails and verify_audit_chain() detects tampered AUDIT_TIP_OPTION signatures', function () use ($vault) {
    global $wpdb, $mock_options;
    $wpdb->refuse_lock = true;
    $threw = false;
    try {
        $vault->log_audit_event('CASE-LOCKFAIL', 'TEST_LOCK', 'COMPLIANCE_OFFICER', 1);
    } catch (\RuntimeException $e) {
        $threw = str_contains($e->getMessage(), 'lock');
    } finally {
        $wpdb->refuse_lock = false;
    }

    $vault->log_audit_event('CASE-LOCKOK', 'TEST_LOCK_OK', 'COMPLIANCE_OFFICER', 1);
    $valid_before = \WMCyber\HinSchG\Crypto\Vault::verify_audit_chain();

    $saved_tip = $mock_options[\WMCyber\HinSchG\Crypto\Vault::AUDIT_TIP_OPTION] ?? null;
    $mock_options[\WMCyber\HinSchG\Crypto\Vault::AUDIT_TIP_OPTION]['sig'] = str_repeat('0', 64);
    $tampered_tip = \WMCyber\HinSchG\Crypto\Vault::verify_audit_chain();
    $mock_options[\WMCyber\HinSchG\Crypto\Vault::AUDIT_TIP_OPTION] = $saved_tip;

    assert_test(
        'Vault::log_audit_event() fails closed when MySQL GET_LOCK fails and verify_audit_chain() detects tampered AUDIT_TIP_OPTION signatures',
        $threw
            && true === ($valid_before['valid'] ?? false)
            && isset($saved_tip['sig'])
            && false === ($tampered_tip['valid'] ?? true),
        var_export(['threw' => $threw, 'valid_before' => $valid_before, 'tampered_tip' => $tampered_tip], true)
    );
});

hinschg_case('Schema::enforce_prerequisites() deactivates cleanly with wp_die() when openssl or sodium is missing, and custody tab exposes WebCrypto Zero-Knowledge UI', function () use ($desk, $render) {
    $GLOBALS['mock_deactivated'] = [];
    $died_msg = '';
    try {
        \WMCyber\HinSchG\Database\Schema::enforce_prerequisites(static fn(string $ext): bool => 'sodium' !== $ext);
    } catch (\RuntimeException $e) {
        $died_msg = $e->getMessage();
    }

    $saved_caps = $GLOBALS['mock_user_caps'];
    $GLOBALS['mock_user_caps'] = ['manage_options', \WMCyber\HinSchG\Security\Capabilities::READ_CASES];
    $_GET['tab'] = 'custody';
    $custody_html = $render(fn() => $desk->render_dashboard_page());
    unset($_GET['tab']);
    $GLOBALS['mock_user_caps'] = $saved_caps;

    $zk_js = (string) file_get_contents(WM_HINSCHG_PATH . 'assets/js/wm-hinschg-zero-knowledge.js');

    assert_test(
        'Schema::enforce_prerequisites() deactivates cleanly with wp_die() when openssl or sodium is missing, and custody tab exposes WebCrypto Zero-Knowledge UI',
        str_contains($died_msg, 'sodium')
            && !empty($GLOBALS['mock_deactivated'])
            && str_contains($custody_html, 'wm-hinschg-zk-generate-btn')
            && str_contains($custody_html, 'save_zero_knowledge_public_key')
            && str_contains($zk_js, 'RSA-OAEP')
            && str_contains($zk_js, 'AES-GCM')
            && !str_contains($zk_js, 'innerHTML'),
        $died_msg
    );
});

// ------------------------------------------------------------
// Test 8: R2-B3 (Dual-Envelope Recovery Key), R2-B2 (Desk Ack/Reply UI & reporter_box),
//         R2-B6 (GET_LOCK Backoff + 503 Retry-After), R2-B8 (Multisite wp_initialize_site)
// ------------------------------------------------------------
echo "\n[TEST GROUP 8] Dual-envelope recovery key, Desk § 17 UI + reporter_box, GET_LOCK 503 backoff, and Multisite wp_initialize_site\n";

hinschg_case('R2-B3: Vault::install_recovery_public_key validates, stores, clears, and dual-seals AES key into encrypted_key & offline bundle', function () use ($vault, $sla_manager, $desk, $render) {
    global $mock_options, $mock_db_tables, $wpdb;

    $saved_options = $mock_options;
    $saved_tables  = array_map(fn($rows) => array_map(fn($r) => is_object($r) ? clone $r : $r, $rows), $mock_db_tables);

    $rec_res = openssl_pkey_new(['digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($rec_res, $rec_priv_pem);
    $rec_pub_pem = (string) openssl_pkey_get_details($rec_res)['key'];

    $weak_res = openssl_pkey_new(['digest_alg' => 'sha256', 'private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $weak_pub_pem = (string) openssl_pkey_get_details($weak_res)['key'];

    $rej_priv = \WMCyber\HinSchG\Crypto\Vault::install_recovery_public_key($rec_pub_pem . "\n" . $rec_priv_pem);
    $rej_weak = \WMCyber\HinSchG\Crypto\Vault::install_recovery_public_key($weak_pub_pem);
    $rej_bad  = \WMCyber\HinSchG\Crypto\Vault::install_recovery_public_key('not-a-pem');
    $ok_save  = \WMCyber\HinSchG\Crypto\Vault::install_recovery_public_key($rec_pub_pem);

    $dual_payload = ['category' => 'it_security', 'description' => 'Backup-Schlüssel Testfall.', 'created_at' => '2026-11-18 12:00:00'];
    $env = $vault->encrypt_envelope($dual_payload);
    $rec_aes = '';
    $dec_ok  = false;
    if (!empty($env['recovery_key'])) {
        openssl_private_decrypt((string) base64_decode($env['recovery_key'], true), $rec_aes, $rec_res, OPENSSL_PKCS1_OAEP_PADDING);
        $raw_plain = openssl_decrypt((string) base64_decode($env['payload'], true), 'aes-256-gcm', $rec_aes, OPENSSL_RAW_DATA, (string) base64_decode($env['iv'], true), (string) base64_decode($env['tag'], true));
        $dec_ok = is_string($raw_plain) && json_decode($raw_plain, true) === $dual_payload;
    }

    // REST submit preserves recovery_key in encrypted_key JSON; seal_message preserves it in message JSON; offline bundle exposes both.
    $rest = new \WMCyber\HinSchG\API\RestController($vault, $sla_manager);
    $GLOBALS['mock_transients'] = [];
    $sub = $rest->handle_report_submit(new WP_REST_Request(['category' => 'it_security', 'description' => 'Dual-Envelope Bericht.']));
    $sub_case = $sub instanceof WP_REST_Response ? (string) ($sub->get_data()['case_public_id'] ?? '') : '';
    $sub_tok  = $sub instanceof WP_REST_Response ? (string) ($sub->get_data()['access_token'] ?? '') : '';
    $sub_row  = end($mock_db_tables['wp_wm_whistle_reports']);
    $sub_key_json = $sub_row ? json_decode((string) $sub_row->encrypted_key, true) : null;

    $rest->handle_whistleblower_reply(new WP_REST_Request(['case_public_id' => $sub_case, 'access_token' => $sub_tok, 'message' => 'Dual-Envelope Nachricht.']));
    $msg_row = end($mock_db_tables['wp_wm_whistle_messages']);
    $msg_json = $msg_row ? json_decode((string) $msg_row->encrypted_message, true) : null;

    // Simulate offline-custody mode so AdminDashboard renders data-wm-hinschg-offline-envelope.
    unset($mock_options['wm_hinschg_private_key']);
    $offline_vault = new \WMCyber\HinSchG\Crypto\Vault();
    $offline_desk  = new \WMCyber\HinSchG\Admin\AdminDashboard($offline_vault, $sla_manager);
    $_GET['case']  = $sub_case;
    $offline_html  = $render(fn() => $offline_desk->render_dashboard_page());
    unset($_GET['case']);

    $bundle = [];
    if (preg_match('/data-wm-hinschg-offline-envelope="([^"]+)"/', $offline_html, $bm)) {
        $bundle = json_decode(html_entity_decode($bm[1], ENT_QUOTES, 'UTF-8'), true) ?: [];
    }

    // Clear recovery key via empty string.
    $cleared = \WMCyber\HinSchG\Crypto\Vault::install_recovery_public_key('');
    $env_after_clear = $vault->encrypt_envelope(['description' => 'Ohne Recovery']);

    $zk_js = (string) file_get_contents(WM_HINSCHG_PATH . 'assets/js/wm-hinschg-zero-knowledge.js');

    $mock_options   = $saved_options;
    $mock_db_tables = $saved_tables;

    assert_test(
        'R2-B3: Vault::install_recovery_public_key validates, stores, clears, and dual-seals AES key into encrypted_key & offline bundle',
        false === $rej_priv['ok']
            && false === $rej_weak['ok']
            && false === $rej_bad['ok']
            && true === $ok_save['ok']
            && !empty($env['recovery_key'])
            && $env['recovery_key'] !== $env['key']
            && true === $dec_ok
            && is_array($sub_key_json) && !empty($sub_key_json['recovery_key'])
            && is_array($msg_json) && !empty($msg_json['recovery_key'])
            && !empty($bundle['report']['recovery_key'])
            && !empty($bundle['messages'][0]['envelope']['recovery_key'])
            && true === $cleared['ok']
            && '' === (string) get_option(\WMCyber\HinSchG\Crypto\Vault::RECOVERY_PUBLIC_KEY_OPTION, '')
            && !isset($env_after_clear['recovery_key'])
            && 1 === preg_match('/catch\s*\([^)]+\)\s*\{\s*if\s*\(\s*!env\.recovery_key\s*\)/s', $zk_js)
            && str_contains($zk_js, 'base64ToUint8Array(env.recovery_key)')
            && str_contains($zk_js, 'hinschg-meldestelle-recovery-private-key.pem'),
        var_export([
            'rej_priv' => $rej_priv, 'ok_save' => $ok_save, 'dec_ok' => $dec_ok,
            'sub_key' => array_keys((array) $sub_key_json), 'bundle_rep' => array_keys((array) ($bundle['report'] ?? [])),
            'cleared' => $cleared,
        ], true)
    );
});

hinschg_case('R2-B3: custody tab renders Notfall- & Vertretungsschlüssel UI citing § 8 Abs. 1 and § 15 HinSchG', function () use ($desk, $render) {
    $saved_caps = $GLOBALS['mock_user_caps'];
    $GLOBALS['mock_user_caps'] = ['manage_options', \WMCyber\HinSchG\Security\Capabilities::READ_CASES];
    $_GET['tab'] = 'custody';
    $html = $render(fn() => $desk->render_dashboard_page());
    unset($_GET['tab']);
    $GLOBALS['mock_user_caps'] = $saved_caps;

    assert_test(
        'R2-B3: custody tab renders Notfall- & Vertretungsschlüssel UI citing § 8 Abs. 1 and § 15 HinSchG',
        str_contains($html, 'Notfall- &amp; Vertretungsschlüssel (2. betraute Person der Meldestelle / Ombudsperson)')
            && str_contains($html, '§ 8 Abs. 1')
            && str_contains($html, '§ 15 HinSchG')
            && str_contains($html, 'niemals bei der Geschäftsführung')
            && str_contains($html, 'id="wm-hinschg-zk-generate-recovery-btn"')
            && str_contains($html, 'id="wm-hinschg-zk-recovery-public-pem"')
            && str_contains($html, 'value="save_recovery_public_key"'),
        'custody HTML missing recovery card elements'
    );
});

hinschg_case('R2-B2: reporter_box enables reporter reading officer replies in offline-custody while whistleblower messages stay 100% Zero-Knowledge', function () use ($sla_manager) {
    global $mock_options, $mock_db_tables, $wpdb;

    $saved_options = $mock_options;
    $saved_tables  = array_map(fn($rows) => array_map(fn($r) => is_object($r) ? clone $r : $r, $rows), $mock_db_tables);

    // Offline-custody setup: server holds ONLY the public key, zero private key.
    unset($mock_options['wm_hinschg_private_key']);
    $zk_vault = new \WMCyber\HinSchG\Crypto\Vault();
    $zk_rest  = new \WMCyber\HinSchG\API\RestController($zk_vault, $sla_manager);
    $GLOBALS['mock_transients'] = [];

    // 1. Direct Vault invariant: whistleblower NEVER carries reporter_box even if token_hash is passed!
    $fake_hash = hash('sha256', 'probe-token');
    $wb_direct = $zk_vault->seal_message('Geheimer Hinweis des Whistleblowers.', 'whistleblower', $fake_hash);
    $wb_json   = json_decode($wb_direct, true);

    $co_direct = $zk_vault->seal_message('Antwort der Meldestelle.', 'compliance_officer', $fake_hash);
    $co_json   = json_decode($co_direct, true);
    $opened_co = \WMCyber\HinSchG\Crypto\Vault::open_message_for_reporter($co_direct, $fake_hash);

    $wrong_tok_threw = false;
    try {
        \WMCyber\HinSchG\Crypto\Vault::open_message_for_reporter($co_direct, hash('sha256', 'wrong-token'));
    } catch (\RuntimeException $e) {
        $wrong_tok_threw = true;
    }

    $tampered_co = $co_json;
    $tampered_co['reporter_box']['box'] = base64_encode(strrev((string) base64_decode($co_json['reporter_box']['box'])));
    $tamper_threw = false;
    try {
        \WMCyber\HinSchG\Crypto\Vault::open_message_for_reporter((string) json_encode($tampered_co), $fake_hash);
    } catch (\RuntimeException $e) {
        $tamper_threw = true;
    }

    // 2. End-to-end REST flow in offline-custody mode.
    $sub      = $zk_rest->handle_report_submit(new WP_REST_Request(['category' => 'financial_fraud', 'description' => 'Offline-Custody Meldung.']));
    $case_id  = (string) ($sub->get_data()['case_public_id'] ?? '');
    $raw_tok  = (string) ($sub->get_data()['access_token'] ?? '');
    $tok_hash = $zk_vault->hash_token($raw_tok);

    $zk_rest->handle_whistleblower_reply(new WP_REST_Request(['case_public_id' => $case_id, 'access_token' => $raw_tok, 'message' => 'Nur fuer Meldestelle lesbar.']));
    $wb_row = end($mock_db_tables['wp_wm_whistle_messages']);
    $wb_row_json = json_decode((string) $wb_row->encrypted_message, true);

    $ack_res = $zk_rest->handle_admin_send_ack(new WP_REST_Request(['case_public_id' => $case_id]));
    $ack_data = $ack_res instanceof WP_REST_Response ? (array) $ack_res->get_data() : [];

    $rep_res = $zk_rest->handle_admin_send_reply(new WP_REST_Request(['case_public_id' => $case_id, 'message' => 'Rueckfrage der Meldestelle im Offline-Modus.', 'is_final_feedback' => true]));

    // Adversarial check: even if an attacker planted a reporter_box on a whistleblower row in DB,
    // handle_report_status MUST NEVER open whistleblower rows via reporter_box.
    $forged_wb = json_decode($zk_vault->seal_message('Angeblicher Klartext', 'compliance_officer', $tok_hash), true);
    $wpdb->insert('wp_wm_whistle_messages', [
        'report_id'         => (int) $wb_row->report_id,
        'sender_role'       => 'whistleblower',
        'encrypted_message' => (string) json_encode($forged_wb),
        'created_at'        => current_time('mysql'),
    ]);

    $status_res  = $zk_rest->handle_report_status(new WP_REST_Request(['case_public_id' => $case_id, 'access_token' => $raw_tok]));
    $status_msgs = $status_res instanceof WP_REST_Response ? (array) ($status_res->get_data()['messages'] ?? []) : [];

    $mock_options   = $saved_options;
    $mock_db_tables = $saved_tables;

    assert_test(
        'R2-B2: reporter_box enables reporter reading officer replies in offline-custody while whistleblower messages stay 100% Zero-Knowledge',
        !isset($wb_json['reporter_box'])
            && !isset($wb_row_json['reporter_box'])
            && isset($co_json['reporter_box']['nonce'], $co_json['reporter_box']['box'])
            && 'Antwort der Meldestelle.' === $opened_co['message']
            && true === $wrong_tok_threw
            && true === $tamper_threw
            && !empty($ack_data['ack_sent_at'])
            && 'acknowledged' === ($ack_data['status'] ?? '')
            && $rep_res instanceof WP_REST_Response
            && 4 === count($status_msgs)
            && true === ($status_msgs[0]['unreadable'] ?? null) && '' === ($status_msgs[0]['message'] ?? 'x')
            && false === ($status_msgs[1]['unreadable'] ?? null) && str_contains((string) $status_msgs[1]['message'], 'Eingangsbestätigung')
            && false === ($status_msgs[2]['unreadable'] ?? null) && 'Rueckfrage der Meldestelle im Offline-Modus.' === $status_msgs[2]['message']
            && true === ($status_msgs[3]['unreadable'] ?? null) && '' === ($status_msgs[3]['message'] ?? 'x'),
        var_export(['ack_data' => $ack_data, 'status_msgs' => $status_msgs], true)
    );
});

hinschg_case('R2-B2: Admin Desk removes obsolete banner, localizes REST nonce, and renders Fallbearbeitung § 17 UI in both normal & offline-custody modes', function () use ($vault, $sla_manager, $desk, $render) {
    global $mock_options, $mock_db_tables;

    $saved_options = $mock_options;
    $saved_tables  = array_map(fn($rows) => array_map(fn($r) => is_object($r) ? clone $r : $r, $rows), $mock_db_tables);

    // Check localized script config on desk page hook.
    $GLOBALS['mock_localized'] = [];
    $desk->enqueue_admin_assets('toplevel_page_wm-hinschg-desk');
    $zk_cfg = $GLOBALS['mock_localized']['wm-hinschg-zero-knowledge']['data'] ?? [];

    $rest = new \WMCyber\HinSchG\API\RestController($vault, $sla_manager);
    $GLOBALS['mock_transients'] = [];
    $sub = $rest->handle_report_submit(new WP_REST_Request(['category' => 'data_protection', 'description' => 'Desk UI Testfall.']));
    $cid = (string) ($sub->get_data()['case_public_id'] ?? '');

    // Normal mode (unacknowledged).
    $_GET['case'] = $cid;
    $normal_unacked = $render(fn() => $desk->render_dashboard_page());

    // Normal mode (acknowledged -> button disabled, data-ack-sent="1").
    $rest->handle_admin_send_ack(new WP_REST_Request(['case_public_id' => $cid]));
    $normal_acked = $render(fn() => $desk->render_dashboard_page());

    // Offline-custody mode (no private key, case still exists -> Fallbearbeitung UI AND offline decryptor both present).
    unset($mock_options['wm_hinschg_private_key']);
    $offline_desk = new \WMCyber\HinSchG\Admin\AdminDashboard(new \WMCyber\HinSchG\Crypto\Vault(), $sla_manager);
    $offline_view = $render(fn() => $offline_desk->render_dashboard_page());

    // Non-existent case -> NO Fallbearbeitung UI.
    $_GET['case'] = 'CASE-NOPE9999';
    $missing_view = $render(fn() => $desk->render_dashboard_page());

    // Glossary check.
    $_GET['tab'] = 'glossary';
    unset($_GET['case']);
    $glossary_html = $render(fn() => $desk->render_dashboard_page());
    unset($_GET['tab']);

    $mock_options   = $saved_options;
    $mock_db_tables = $saved_tables;

    assert_test(
        'R2-B2: Admin Desk removes obsolete banner, localizes REST nonce, and renders Fallbearbeitung § 17 UI in both normal & offline-custody modes',
        str_ends_with((string) ($zk_cfg['restUrl'] ?? ''), 'wm-hinschg/v1')
            && 'nonce' === ($zk_cfg['restNonce'] ?? '')
            && !str_contains($normal_unacked, 'Noch nicht in dieser Oberfläche')
            && str_contains($normal_unacked, 'Fallbearbeitung nach § 17 HinSchG')
            && str_contains($normal_unacked, 'data-case-id="' . $cid . '"')
            && str_contains($normal_unacked, 'data-ack-sent="0"')
            && preg_match('/id="wm-hinschg-ack-btn"[^>]*>/', $normal_unacked)
            && !preg_match('/id="wm-hinschg-ack-btn"[^>]*disabled/', $normal_unacked)
            && str_contains($normal_unacked, 'id="wm-hinschg-reply-text"')
            && str_contains($normal_unacked, 'id="wm-hinschg-reply-final"')
            && str_contains($normal_unacked, 'id="wm-hinschg-reply-btn"')
            && str_contains($normal_unacked, 'id="wm-hinschg-case-action-status"')
            && str_contains($normal_unacked, 'role="status"')
            && str_contains($normal_acked, 'data-ack-sent="1"')
            && 1 === preg_match('/id="wm-hinschg-ack-btn"[^>]*disabled="disabled"/', $normal_acked)
            && str_contains($offline_view, 'data-wm-hinschg-offline-envelope=')
            && str_contains($offline_view, 'id="wm-hinschg-case-actions"')
            && !str_contains($missing_view, 'id="wm-hinschg-case-actions"')
            && !str_contains($glossary_html, 'ohne beides im Klartext in der Datenbank'),
        var_export(['cfg' => $zk_cfg, 'cid' => $cid], true)
    );
});

hinschg_case('R2-B6: GET_LOCK retries on contention, fails fast on null, returns 503 Retry-After: 2 across REST handlers & renders cleanly on desk', function () use ($vault, $sla_manager, $desk, $render) {
    global $wpdb, $mock_db_tables;

    $saved_tables = array_map(fn($rows) => array_map(fn($r) => is_object($r) ? clone $r : $r, $rows), $mock_db_tables);

    // 1. Transient contention (2 failures then lock acquired on 3rd attempt) succeeds!
    $wpdb->get_lock_calls    = 0;
    $wpdb->refuse_lock_count = 2;
    $hash = $vault->log_audit_event('CASE-RETRY3', 'TEST_RETRY', 'COMPLIANCE_OFFICER', 1);
    $retried_calls = $wpdb->get_lock_calls;

    // 2. NULL lock response fails immediately on 1st call without sleeping through 6 retries.
    $wpdb->get_lock_calls   = 0;
    $wpdb->refuse_lock_null = true;
    $null_threw = false;
    try {
        $vault->log_audit_event('CASE-LOCKNULL', 'TEST_NULL', 'COMPLIANCE_OFFICER', 1);
    } catch (\RuntimeException $e) {
        $null_threw = str_contains($e->getMessage(), 'lock');
    } finally {
        $wpdb->refuse_lock_null = false;
    }
    $null_calls = $wpdb->get_lock_calls;

    // 3. Persistent lock refusal -> all 5 REST handlers return 503 + Retry-After: 2 without partial writes.
    $rest = new \WMCyber\HinSchG\API\RestController($vault, $sla_manager);
    $GLOBALS['mock_transients'] = [];
    $sub = $rest->handle_report_submit(new WP_REST_Request(['category' => 'financial_fraud', 'description' => 'Lock 503 Basis.']));
    $cid = (string) ($sub->get_data()['case_public_id'] ?? '');
    $tok = (string) ($sub->get_data()['access_token'] ?? '');
    $reports_before = count($mock_db_tables['wp_wm_whistle_reports']);
    $msgs_before    = count($mock_db_tables['wp_wm_whistle_messages']);

    $wpdb->refuse_lock = true;
    try {
        $r_read   = $rest->handle_admin_read_case(new WP_REST_Request(['case_public_id' => $cid]));
        $r_submit = $rest->handle_report_submit(new WP_REST_Request(['category' => 'financial_fraud', 'description' => 'Soll 503 liefern.']));
        $r_chat   = $rest->handle_whistleblower_reply(new WP_REST_Request(['case_public_id' => $cid, 'access_token' => $tok, 'message' => 'Chat 503.']));
        $r_ack    = $rest->handle_admin_send_ack(new WP_REST_Request(['case_public_id' => $cid]));
        $r_reply  = $rest->handle_admin_send_reply(new WP_REST_Request(['case_public_id' => $cid, 'message' => 'Reply 503.']));

        $_GET['case'] = $cid;
        $desk_503_html = $render(fn() => $desk->render_dashboard_page());
        unset($_GET['case']);
    } finally {
        $wpdb->refuse_lock = false;
    }

    $all_503 = true;
    foreach ([$r_read, $r_submit, $r_chat, $r_ack, $r_reply] as $resp) {
        $all_503 = $all_503
            && $resp instanceof WP_REST_Response
            && 503 === $resp->get_status()
            && '2' === ($resp->get_headers()['Retry-After'] ?? '')
            && 'wm_hinschg_audit_busy' === ($resp->get_data()['code'] ?? '');
    }

    $reports_after = count($mock_db_tables['wp_wm_whistle_reports']);
    $msgs_after    = count($mock_db_tables['wp_wm_whistle_messages']);

    // Verify retry on ack succeeds once lock clears!
    $ack_after_clear = $rest->handle_admin_send_ack(new WP_REST_Request(['case_public_id' => $cid]));

    $mock_db_tables = $saved_tables;

    assert_test(
        'R2-B6: GET_LOCK retries on contention, fails fast on null, returns 503 Retry-After: 2 across REST handlers & renders cleanly on desk',
        '' !== $hash
            && 3 === $retried_calls
            && true === $null_threw && 1 === $null_calls
            && true === $all_503
            && $reports_before === $reports_after
            && $msgs_before === $msgs_after
            && $ack_after_clear instanceof WP_REST_Response && 200 === $ack_after_clear->get_status()
            && str_contains($desk_503_html, 'Audit-Protokoll ist vorübergehend belegt')
            && !str_contains($desk_503_html, 'id="wm-hinschg-case-actions"'),
        var_export([
            'retried_calls' => $retried_calls, 'null_calls' => $null_calls, 'all_503' => $all_503,
            'reports' => "{$reports_before}->{$reports_after}", 'msgs' => "{$msgs_before}->{$msgs_after}",
        ], true)
    );
});

hinschg_case('R2-B8: wp_initialize_site initializes schema and keys on new multisite blogs only when network-activated', function () {
    $p = hinschg_probe_key('multisite-init');
    assert_test(
        'R2-B8: wp_initialize_site initializes schema and keys on new multisite blogs only when network-activated',
        true === ($p['hook_registered'] ?? null)
            && true === ($p['ignored_when_not_network'] ?? null)
            && true === ($p['switched_to_42'] ?? null)
            && true === ($p['restored_to_1'] ?? null)
            && true === ($p['blog42_tables_created'] ?? null)
            && true === ($p['blog42_public_key_set'] ?? null)
            && true === ($p['blog1_untouched'] ?? null),
        var_export($p, true)
    );
});

assert_test('no PHP warning, notice or deprecation during the run', [] === $GLOBALS['hinschg_php_warnings'], implode(' | ', array_slice($GLOBALS['hinschg_php_warnings'], 0, 5)));

// ------------------------------------------------------------
// Summary & Exit Code
// ------------------------------------------------------------
echo "\n==============================================================================\n";
echo "  TEST SUITE RESULTS: {$passed_count} PASSED | {$failed_count} FAILED\n";
echo "==============================================================================\n\n";

exit($failed_count === 0 ? 0 : 1);
