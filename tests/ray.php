<?php
declare(strict_types=1);

// Local-only integration test helper for Raymon <-> Ray (PHP global install).
//
// This script is intentionally **one Ray command per run** so the Rust integration
// test can correlate “1 command ⇒ 1 entry (or none)” deterministically.
//
// Usage:
//   php tests/ray.php --list
//   php tests/ray.php --case log --token abc123
//   php tests/ray.php --case custom_text --token abc123
//
// Optional (best-effort; depends on your Ray PHP install):
//   php tests/ray.php --case log --ray-host 127.0.0.1 --ray-port 23517
//
// Notes:
// - This is not intended for CI.
// - Requires the global `ray()` helper to be available.

if (getenv("CI")) {
    fwrite(STDERR, "tests/ray.php is a local-only integration test helper; skipping because CI is set.\n");
    exit(0);
}

$options = getopt("", [
    "help",
    "list",
    "case:",
    "token:",
    "ray-host:",
    "ray-port:",
    "global-ray-loader:",
]);

$cases = [
    // Core payload types Raymon treats specially.
    "log",
    "table",
    "json",
    "custom_html",
    "custom_text",

    // Common command groups (smoke coverage; mostly asserts “ingests successfully”).
    "color_named",
    "color_method",
    "label",
    "xml",
    "file",
    "image_url",
    "phpinfo",
    "trace",
    "count",
    "measure",
    "limit",
    "once",
    "showif_true",
    "showif_false",
    "if_true",
    "exception",
    "send",
];

$usage = implode("\n", [
    "Usage:",
    "  php tests/ray.php --list",
    "  php tests/ray.php --case <name> [--token <token>] [--ray-host <host>] [--ray-port <port>]",
    "",
    "Cases:",
    "  " . implode(", ", $cases),
    "",
]);

if (isset($options["help"])) {
    echo $usage;
    exit(0);
}

if (isset($options["list"])) {
    echo implode("\n", $cases) . "\n";
    exit(0);
}

$case = $options["case"] ?? null;
if (!$case || !in_array($case, $cases, true)) {
    fwrite(STDERR, "Missing or invalid --case.\n\n" . $usage);
    exit(2);
}

$token = $options["token"] ?? bin2hex(random_bytes(8));
$marker = "raymon-it:" . $token . ":" . $case;

// Configure Ray PHP to talk to Raymon.
//
// `spatie/global-ray` reads `ray.php` (cwd + parents) for host/port, so when `--ray-host/--ray-port`
// are provided we create a temporary `ray.php` and `chdir()` into that folder before calling `ray()`.
$rayHost = $options["ray-host"] ?? null;
$rayPort = $options["ray-port"] ?? null;

if (
    (is_string($rayHost) && $rayHost !== "") ||
    (is_string($rayPort) && $rayPort !== "")
) {
    $host = (is_string($rayHost) && $rayHost !== "") ? $rayHost : "localhost";
    $port = (is_string($rayPort) && $rayPort !== "") ? (int)$rayPort : 23517;

    $dir = rtrim(sys_get_temp_dir(), "/") . "/raymon-raycfg-" . bin2hex(random_bytes(8));
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }

    $configPath = $dir . "/ray.php";
    $config = "<?php\n\nreturn " . var_export([
        "enable" => true,
        "host" => $host,
        "port" => $port,
    ], true) . ";\n";

    @file_put_contents($configPath, $config);
    @chdir($dir);
}

if (!function_exists("ray")) {
    $loader = $options["global-ray-loader"] ?? getenv("GLOBAL_RAY_LOADER") ?: null;
    $candidates = [];

    if (is_string($loader) && $loader !== "") {
        $candidates[] = $loader;
    }

    $composerHome = getenv("COMPOSER_HOME") ?: null;
    if (is_string($composerHome) && $composerHome !== "") {
        $candidates[] = rtrim($composerHome, "/") . "/vendor/spatie/global-ray/src/scripts/global-ray-loader.php";
    }

    $home = $_SERVER["HOME"] ?? null;
    if (is_string($home) && $home !== "") {
        $candidates[] = rtrim($home, "/") . "/.composer/vendor/spatie/global-ray/src/scripts/global-ray-loader.php";
        $candidates[] = rtrim($home, "/") . "/.config/composer/vendor/spatie/global-ray/src/scripts/global-ray-loader.php";
    }

    foreach ($candidates as $candidate) {
        if (is_string($candidate) && $candidate !== "" && file_exists($candidate)) {
            try {
                require_once $candidate;
            } catch (\Throwable $e) {
                // ignore; we'll fail with a friendly message below
            }

            if (function_exists("ray")) {
                break;
            }
        }
    }
}

if (!function_exists("ray")) {
    fwrite(
        STDERR,
        "The global ray() helper is not available.\n" .
            "Install Ray globally for PHP first (see https://myray.app/docs/php/vanilla-php/installation#global-installation),\n" .
            "then re-run this script.\n"
    );
    exit(3);
}

send_case($case, $marker);

echo json_encode(
    [
        "ok" => true,
        "case" => $case,
        "token" => $token,
        "marker" => $marker,
        "ray_host" => $rayHost,
        "ray_port" => $rayPort,
    ],
    JSON_UNESCAPED_SLASHES
) . "\n";

function send_case(string $case, string $marker): void
{
    switch ($case) {
        case "log":
            ray($marker);
            return;
        case "color_named":
            ray(["marker" => $marker])->color("red");
            return;
        case "color_method":
            ray($marker)->green();
            return;
        case "label":
            ray(["marker" => $marker])->label($marker);
            return;
        case "table":
            ray()->table(["marker" => $marker], $marker);
            return;
        case "json":
            ray()->toJson(["marker" => $marker]);
            return;
        case "xml":
            ray()->xml("<root><marker>" . htmlspecialchars($marker, ENT_XML1) . "</marker></root>");
            return;
        case "file":
            ray($marker)->file(__FILE__);
            return;
        case "image_url":
            ray($marker)->image("https://placekitten.com/200/300");
            return;
        case "custom_html":
            ray()->html("<b>" . htmlspecialchars($marker, ENT_QUOTES) . "</b>");
            return;
        case "custom_text":
            ray()->text("Marker: " . $marker);
            return;
        case "phpinfo":
            ray($marker)->phpinfo("default_mimetype");
            return;
        case "trace":
            ray($marker)->trace();
            return;
        case "count":
            ray($marker)->count();
            return;
        case "measure":
            ray($marker)->measure();
            return;
        case "limit":
            ray()->limit(1)->text($marker);
            return;
        case "once":
            ray()->once($marker);
            return;
        case "showif_true":
            ray()->showIf(true)->text($marker);
            return;
        case "showif_false":
            ray()->showIf(false)->text($marker);
            return;
        case "if_true":
            ray()->if(true)->text($marker)->blue();
            return;
        case "exception":
            try {
                throw new \Exception($marker);
            } catch (\Exception $e) {
                ray()->exception($e);
            }
            return;
        case "send":
            ray($marker)->send("update:" . $marker);
            return;
        default:
            throw new \RuntimeException("unhandled case: " . $case);
    }
}
