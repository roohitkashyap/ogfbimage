<?php
/**
 * FB Anti-Ban Link System v4 — Production Ready
 * ---
 * Single file system that serves OG tags to Facebook crawlers
 * and instantly redirects real visitors to the target URL.
 * Admin panel included for link management.
 */

// ============================================================
// PRODUCTION CONFIG
// ============================================================
error_reporting(0);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

define('ADMIN_PASSWORD', 'admin123');       // ⚠️ CHANGE THIS ON LIVE SERVER!
define('DATA_DIR', __DIR__ . '/fb_data');
define('IMAGE_DIR', __DIR__ . '/fb_images');
define('LINKS_FILE', DATA_DIR . '/links.json');
define('RATE_FILE', DATA_DIR . '/rate_limit.json');
define('MAX_IMAGE_SIZE', 5 * 1024 * 1024); // 5MB
define('SITE_TITLE', 'FB Link Manager');
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 900); // 15 minutes

// Auto-create directories
if (!is_dir(DATA_DIR))
    @mkdir(DATA_DIR, 0755, true);
if (!is_dir(IMAGE_DIR))
    @mkdir(IMAGE_DIR, 0755, true);
if (!file_exists(LINKS_FILE))
    @file_put_contents(LINKS_FILE, '{}');

// Secure session configuration
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_strict_mode', '1');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}
session_start();
// Regenerate session ID periodically to prevent fixation
if (!isset($_SESSION['_created'])) {
    $_SESSION['_created'] = time();
} elseif (time() - $_SESSION['_created'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['_created'] = time();
}

// CSRF Token
function generateCsrf()
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}
function verifyCsrf($token)
{
    return !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Rate limiting for login
function checkLoginRateLimit()
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $data = [];
    if (file_exists(RATE_FILE)) {
        $data = json_decode(file_get_contents(RATE_FILE), true) ?: [];
    }
    // Clean old entries
    $data = array_filter($data, fn($entry) => (time() - ($entry['time'] ?? 0)) < LOGIN_LOCKOUT_TIME);
    $ipAttempts = array_filter($data, fn($entry) => ($entry['ip'] ?? '') === $ip);
    return count($ipAttempts) < MAX_LOGIN_ATTEMPTS;
}
function recordLoginAttempt()
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $data = [];
    if (file_exists(RATE_FILE)) {
        $data = json_decode(file_get_contents(RATE_FILE), true) ?: [];
    }
    $data = array_filter($data, fn($entry) => (time() - ($entry['time'] ?? 0)) < LOGIN_LOCKOUT_TIME);
    $data[] = ['ip' => $ip, 'time' => time()];
    @file_put_contents(RATE_FILE, json_encode(array_values($data)), LOCK_EX);
}

// ============================================================
// ROUTING
// ============================================================

// Image serving: ?img=xxx
if (isset($_GET['img'])) {
    serveImage(sanitizeId($_GET['img']));
    exit;
}

// Redirect handler: ?id=xxx
if (isset($_GET['id'])) {
    handleRedirect(sanitizeId($_GET['id']));
    exit;
}

// API endpoints
if (isset($_GET['api'])) {
    requireAuth();
    $action = $_GET['api'];

    if ($action === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        apiCreate();
    } elseif ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        apiDelete();
    } elseif ($action === 'list') {
        apiList();
    } elseif ($action === 'fetch-og' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        apiFetchOG();
    } else {
        jsonResponse(['error' => 'Invalid API action'], 400);
    }
    exit;
}

// Login handler
if (isset($_POST['login_password'])) {
    if (!checkLoginRateLimit()) {
        $login_error = 'Too many attempts. Try again in 15 minutes.';
    } elseif ($_POST['login_password'] === ADMIN_PASSWORD) {
        $_SESSION['fb_admin_auth'] = true;
        session_regenerate_id(true);
        $_SESSION['_created'] = time();
        header('Location: ' . getBaseUrl() . '?admin=1');
        exit;
    } else {
        recordLoginAttempt();
        $login_error = 'Wrong password!';
    }
}

// Logout
if (isset($_GET['logout'])) {
    unset($_SESSION['fb_admin_auth']);
    header('Location: ' . getBaseUrl() . '?admin=1');
    exit;
}

// Admin panel or default
showAdminPanel(isset($login_error) ? $login_error : null);
exit;


// ============================================================
// REDIRECT HANDLER — Core Logic
// ============================================================
function handleRedirect($id)
{
    $links = loadLinks();

    if (!isset($links[$id])) {
        http_response_code(200); // Don't return 404 — some firewalls block it
        echo '<!DOCTYPE html><html><head><title>Page</title></head><body><p>Content not available.</p></body></html>';
        return;
    }

    $link = $links[$id];
    $url = $link['url'];

    // Increment click count
    $links[$id]['clicks'] = ($links[$id]['clicks'] ?? 0) + 1;
    $links[$id]['last_click'] = date('Y-m-d H:i:s');
    saveLinks($links);

    // Check if Facebook crawler
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $isCrawler = isFacebookCrawler($ua);

    if ($isCrawler) {
        // Serve OG tags to crawler
        serveCrawlerPage($id, $link);
    } else {
        // Redirect real visitor
        serveRedirectPage($url);
    }
}

function isFacebookCrawler($ua)
{
    $bots = [
        'facebookexternalhit',
        'Facebot',
        'FacebookBot',
        'Facebook',
        'MetaInspector',
        'Twitterbot',       // Twitter cards too
        'LinkedInBot',      // LinkedIn preview
        'WhatsApp',         // WhatsApp preview
        'TelegramBot',      // Telegram preview
        'Slackbot',         // Slack preview
        'Discordbot',       // Discord preview
        'Googlebot',        // Google preview
    ];

    foreach ($bots as $bot) {
        if (stripos($ua, $bot) !== false) {
            return true;
        }
    }
    return false;
}

function serveCrawlerPage($id, $link)
{
    $title = htmlspecialchars($link['title'] ?? 'Untitled', ENT_QUOTES, 'UTF-8');
    $desc = htmlspecialchars($link['desc'] ?? '', ENT_QUOTES, 'UTF-8');
    $siteName = htmlspecialchars($link['site_name'] ?? SITE_TITLE, ENT_QUOTES, 'UTF-8');
    $imgUrl = getBaseUrl() . '?img=' . $id;
    $pageUrl = getBaseUrl() . '?id=' . $id;

    // Get actual image dimensions
    $imgFile = IMAGE_DIR . '/' . $id . '.jpg';
    $imgW = 1200;
    $imgH = 630; // defaults
    if (file_exists($imgFile)) {
        $dims = @getimagesize($imgFile);
        if ($dims) {
            $imgW = $dims[0];
            $imgH = $dims[1];
        }
    }

    // Explicit headers to bypass Hostinger WAF
    http_response_code(200);
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Robots-Tag: all');
    header('Cache-Control: no-cache, must-revalidate');
    header('Access-Control-Allow-Origin: *');
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$title}</title>
    
    <!-- Open Graph Tags -->
    <meta property="og:type" content="article" />
    <meta property="og:url" content="{$pageUrl}" />
    <meta property="og:title" content="{$title}" />
    <meta property="og:description" content="{$desc}" />
    <meta property="og:image" content="{$imgUrl}" />
    <meta property="og:image:type" content="image/jpeg" />
    <meta property="og:image:width" content="{$imgW}" />
    <meta property="og:image:height" content="{$imgH}" />
    <meta property="og:site_name" content="{$siteName}" />
    
    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="{$title}" />
    <meta name="twitter:description" content="{$desc}" />
    <meta name="twitter:image" content="{$imgUrl}" />
</head>
<body>
    <h1>{$title}</h1>
    <p>{$desc}</p>
    <img src="{$imgUrl}" alt="{$title}" />
</body>
</html>
HTML;
}

function serveRedirectPage($url)
{
    $safeUrl = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    $jsUrl = addslashes($url);

    header('Content-Type: text/html; charset=UTF-8');
    echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0;url={$safeUrl}">
    <script>window.location.replace("{$jsUrl}");</script>
    <title>Redirecting...</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex; align-items: center; justify-content: center; 
            min-height: 100vh; margin: 0; 
            background: #0a0a0f; color: #fff;
        }
        .loader { text-align: center; }
        .spinner {
            width: 40px; height: 40px; margin: 0 auto 16px;
            border: 3px solid rgba(255,255,255,0.1);
            border-top-color: #6366f1;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        a { color: #818cf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="loader">
        <div class="spinner"></div>
        <p>Redirecting...</p>
        <p><a href="{$safeUrl}">Click here if not redirected</a></p>
    </div>
</body>
</html>
HTML;
}


// ============================================================
// IMAGE SERVER
// ============================================================
function serveImage($id)
{
    $file = IMAGE_DIR . '/' . $id . '.jpg';

    if (!file_exists($file)) {
        http_response_code(404);
        // Serve a 1x1 transparent pixel as fallback
        header('Content-Type: image/gif');
        echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
        return;
    }

    $etag = md5_file($file);
    $lastModified = filemtime($file);

    // Cache headers — 7 days
    header('Content-Type: image/jpeg');
    header('Cache-Control: public, max-age=604800');
    header('ETag: "' . $etag . '"');
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $lastModified) . ' GMT');
    header('Access-Control-Allow-Origin: *');

    // 304 Not Modified
    if (
        (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim($_SERVER['HTTP_IF_NONE_MATCH'], '"') === $etag) ||
        (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= $lastModified)
    ) {
        http_response_code(304);
        return;
    }

    header('Content-Length: ' . filesize($file));
    readfile($file);
}


// ============================================================
// API ENDPOINTS
// ============================================================
function apiCreate()
{
    header('Content-Type: application/json; charset=UTF-8');

    // Validate URL
    $url = trim($_POST['url'] ?? '');
    if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
        jsonResponse(['error' => 'Valid URL is required'], 400);
        return;
    }

    // Validate image
    if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        jsonResponse(['error' => 'Image upload is required'], 400);
        return;
    }

    $file = $_FILES['image'];
    if ($file['size'] > MAX_IMAGE_SIZE) {
        jsonResponse(['error' => 'Image must be under 5MB'], 400);
        return;
    }

    // Validate image type
    $imageInfo = @getimagesize($file['tmp_name']);
    if (!$imageInfo) {
        jsonResponse(['error' => 'Invalid image file'], 400);
        return;
    }

    $allowedTypes = [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF, IMAGETYPE_WEBP];
    if (!in_array($imageInfo[2], $allowedTypes)) {
        jsonResponse(['error' => 'Supported formats: JPG, PNG, GIF, WebP'], 400);
        return;
    }

    // Generate unique ID
    $id = generateId();

    // Convert & save image as JPG
    if (!convertAndSave($file['tmp_name'], $imageInfo[2], $id)) {
        jsonResponse(['error' => 'Image processing failed. Check GD library.'], 500);
        return;
    }

    // Get title & description
    $title = trim($_POST['title'] ?? '');
    $desc = trim($_POST['desc'] ?? '');
    $siteName = trim($_POST['site_name'] ?? '');

    // Auto-fetch OG data if title or desc empty
    if (empty($title) || empty($desc)) {
        $og = fetchOGFromUrl($url);
        if (empty($title))
            $title = $og['title'] ?? '';
        if (empty($desc))
            $desc = $og['desc'] ?? '';
        if (empty($siteName))
            $siteName = $og['site_name'] ?? '';
    }

    // Fallback title
    if (empty($title)) {
        $title = 'Untitled Link';
    }

    // Save to links.json
    $links = loadLinks();
    $links[$id] = [
        'id' => $id,
        'url' => $url,
        'title' => $title,
        'desc' => $desc,
        'site_name' => $siteName,
        'created' => date('Y-m-d H:i:s'),
        'updated' => time(),
        'clicks' => 0,
        'last_click' => null,
    ];
    saveLinks($links);

    $baseUrl = getBaseUrl();
    jsonResponse([
        'success' => true,
        'id' => $id,
        'go_url' => $baseUrl . '?id=' . $id,
        'img_url' => $baseUrl . '?img=' . $id,
        'title' => $title,
        'desc' => $desc,
    ]);
}

function apiDelete()
{
    header('Content-Type: application/json; charset=UTF-8');

    $id = sanitizeId($_POST['id'] ?? '');
    if (empty($id)) {
        jsonResponse(['error' => 'ID is required'], 400);
        return;
    }

    $links = loadLinks();
    if (!isset($links[$id])) {
        jsonResponse(['error' => 'Link not found'], 404);
        return;
    }

    // Delete image file
    $imgFile = IMAGE_DIR . '/' . $id . '.jpg';
    if (file_exists($imgFile))
        unlink($imgFile);

    // Remove from data
    unset($links[$id]);
    saveLinks($links);

    jsonResponse(['success' => true]);
}

function apiList()
{
    header('Content-Type: application/json; charset=UTF-8');
    $links = loadLinks();
    // Sort by created date (newest first)
    uasort($links, function ($a, $b) {
        return strtotime($b['created'] ?? '0') - strtotime($a['created'] ?? '0');
    });
    jsonResponse(['success' => true, 'links' => array_values($links), 'total' => count($links)]);
}

function apiFetchOG()
{
    header('Content-Type: application/json; charset=UTF-8');
    $url = trim($_POST['url'] ?? '');
    if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
        jsonResponse(['error' => 'Valid URL required'], 400);
        return;
    }
    $og = fetchOGFromUrl($url);
    jsonResponse(['success' => true, 'data' => $og]);
}


// ============================================================
// HELPER FUNCTIONS
// ============================================================

function convertAndSave($tmpFile, $imageType, $id)
{
    $src = null;
    switch ($imageType) {
        case IMAGETYPE_JPEG:
            $src = @imagecreatefromjpeg($tmpFile);
            break;
        case IMAGETYPE_PNG:
            $src = @imagecreatefrompng($tmpFile);
            break;
        case IMAGETYPE_GIF:
            $src = @imagecreatefromgif($tmpFile);
            break;
        case IMAGETYPE_WEBP:
            $src = @imagecreatefromwebp($tmpFile);
            break;
    }

    if (!$src)
        return false;

    $origW = imagesx($src);
    $origH = imagesy($src);

    // Resize to max 1200px width, keep original aspect ratio
    $maxW = 1200;
    if ($origW > $maxW) {
        $newW = $maxW;
        $newH = (int) round($origH * ($maxW / $origW));
    } else {
        $newW = $origW;
        $newH = $origH;
    }

    // Create new image with white background (handles transparency)
    $dst = imagecreatetruecolor($newW, $newH);
    $white = imagecolorallocate($dst, 255, 255, 255);
    imagefill($dst, 0, 0, $white);

    // Resize — no crop, original ratio maintained
    imagecopyresampled($dst, $src, 0, 0, 0, 0, $newW, $newH, $origW, $origH);

    // Save as JPG (quality 90)
    $result = imagejpeg($dst, IMAGE_DIR . '/' . $id . '.jpg', 90);

    imagedestroy($src);
    imagedestroy($dst);

    return $result;
}

function fetchOGFromUrl($url)
{
    $html = fetchUrl($url);
    if (!$html)
        return ['title' => '', 'desc' => '', 'site_name' => ''];

    $result = [
        'title' => '',
        'desc' => '',
        'site_name' => '',
        'image' => '',
    ];

    // OG title
    $result['title'] = getMeta($html, 'og:title');
    if (empty($result['title'])) {
        $result['title'] = getMeta($html, 'twitter:title');
    }
    if (empty($result['title'])) {
        // Fallback to <title> tag
        if (preg_match('/<title[^>]*>(.*?)<\/title>/si', $html, $m)) {
            $result['title'] = trim(html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'));
        }
    }

    // OG description
    $result['desc'] = getMeta($html, 'og:description');
    if (empty($result['desc'])) {
        $result['desc'] = getMeta($html, 'twitter:description');
    }
    if (empty($result['desc'])) {
        // Fallback to meta description
        if (preg_match('/<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']/si', $html, $m)) {
            $result['desc'] = trim(html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'));
        }
    }

    // OG site_name
    $result['site_name'] = getMeta($html, 'og:site_name');

    // OG image
    $result['image'] = getMeta($html, 'og:image');

    return $result;
}

function fetchUrl($url)
{
    // Try cURL first
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            CURLOPT_HTTPHEADER => ['Accept-Language: en-US,en;q=0.9'],
        ]);
        $html = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($httpCode >= 200 && $httpCode < 400 && $html)
            return $html;
    }

    // Fallback to file_get_contents
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 10,
            'header' => "User-Agent: Mozilla/5.0\r\n",
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    return @file_get_contents($url, false, $ctx);
}

function getMeta($html, $property)
{
    // Try property="..."
    $patterns = [
        '/<meta\s+property=["\']' . preg_quote($property, '/') . '["\']\s+content=["\'](.*?)["\']/si',
        '/<meta\s+content=["\'](.*?)["\']\s+property=["\']' . preg_quote($property, '/') . '["\']/si',
        '/<meta\s+name=["\']' . preg_quote($property, '/') . '["\']\s+content=["\'](.*?)["\']/si',
        '/<meta\s+content=["\'](.*?)["\']\s+name=["\']' . preg_quote($property, '/') . '["\']/si',
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $html, $m)) {
            return trim(html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'));
        }
    }
    return '';
}

function generateId()
{
    $links = loadLinks();
    do {
        $id = bin2hex(random_bytes(4)); // 8-char hex
    } while (isset($links[$id]));
    return $id;
}

function sanitizeId($id)
{
    return preg_replace('/[^a-zA-Z0-9]/', '', $id);
}

function loadLinks()
{
    if (!file_exists(LINKS_FILE))
        return [];
    $data = json_decode(file_get_contents(LINKS_FILE), true);
    return is_array($data) ? $data : [];
}

function saveLinks($links)
{
    file_put_contents(LINKS_FILE, json_encode($links, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function getBaseUrl()
{
    // Detect HTTPS from proxy headers (Railway, Cloudflare, Heroku, etc.)
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
        || (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on')
        || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
    $protocol = $isHttps ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = $_SERVER['SCRIPT_NAME'] ?? '/go.php';
    return $protocol . '://' . $host . $script;
}

function jsonResponse($data, $code = 200)
{
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function requireAuth()
{
    if (empty($_SESSION['fb_admin_auth'])) {
        jsonResponse(['error' => 'Unauthorized. Login required.'], 401);
    }
}

function isLoggedIn()
{
    return !empty($_SESSION['fb_admin_auth']);
}


// ============================================================
// ADMIN PANEL
// ============================================================
function showAdminPanel($loginError = null)
{
    $loggedIn = isLoggedIn();
    $baseUrl = getBaseUrl();

    ?><!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?= SITE_TITLE ?> — Admin</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
            rel="stylesheet">
        <style>
            /* ===== RESET & BASE ===== */
            *,
            *::before,
            *::after {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            :root {
                --bg-primary: #06060a;
                --bg-secondary: #0d0d14;
                --bg-card: #111118;
                --bg-input: #16161f;
                --bg-hover: #1c1c28;
                --border: #222233;
                --border-focus: #6366f1;
                --text-primary: #f0f0f5;
                --text-secondary: #8888a0;
                --text-muted: #55556a;
                --accent: #6366f1;
                --accent-hover: #818cf8;
                --accent-glow: rgba(99, 102, 241, 0.3);
                --success: #22c55e;
                --success-bg: rgba(34, 197, 94, 0.1);
                --danger: #ef4444;
                --danger-bg: rgba(239, 68, 68, 0.1);
                --warning: #f59e0b;
                --radius: 12px;
                --radius-sm: 8px;
                --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            }

            body {
                font-family: var(--font);
                background: var(--bg-primary);
                color: var(--text-primary);
                min-height: 100vh;
                line-height: 1.6;
                -webkit-font-smoothing: antialiased;
            }

            /* ===== LOGIN PAGE ===== */
            .login-container {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                background:
                    radial-gradient(ellipse at 50% 0%, rgba(99, 102, 241, 0.08) 0%, transparent 60%),
                    var(--bg-primary);
            }

            .login-card {
                width: 100%;
                max-width: 400px;
                background: var(--bg-card);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: 40px 32px;
                text-align: center;
                animation: fadeUp 0.5s ease;
            }

            .login-card .logo {
                width: 56px;
                height: 56px;
                background: linear-gradient(135deg, var(--accent), #a855f7);
                border-radius: 14px;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 20px;
                font-size: 24px;
            }

            .login-card h1 {
                font-size: 22px;
                font-weight: 700;
                margin-bottom: 6px;
            }

            .login-card p {
                color: var(--text-secondary);
                font-size: 14px;
                margin-bottom: 28px;
            }

            .login-card .error-msg {
                background: var(--danger-bg);
                color: var(--danger);
                padding: 10px 14px;
                border-radius: var(--radius-sm);
                font-size: 13px;
                margin-bottom: 16px;
                border: 1px solid rgba(239, 68, 68, 0.2);
            }

            /* ===== FORM ELEMENTS ===== */
            .form-group {
                margin-bottom: 16px;
                text-align: left;
            }

            .form-group label {
                display: block;
                font-size: 13px;
                font-weight: 500;
                color: var(--text-secondary);
                margin-bottom: 6px;
            }

            input[type="text"],
            input[type="password"],
            input[type="url"],
            textarea {
                width: 100%;
                padding: 11px 14px;
                background: var(--bg-input);
                border: 1px solid var(--border);
                border-radius: var(--radius-sm);
                color: var(--text-primary);
                font-family: var(--font);
                font-size: 14px;
                outline: none;
                transition: all 0.2s;
            }

            input:focus,
            textarea:focus {
                border-color: var(--border-focus);
                box-shadow: 0 0 0 3px var(--accent-glow);
            }

            textarea {
                resize: vertical;
                min-height: 70px;
            }

            input::placeholder,
            textarea::placeholder {
                color: var(--text-muted);
            }

            .btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                padding: 11px 20px;
                border: none;
                border-radius: var(--radius-sm);
                font-family: var(--font);
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
                text-decoration: none;
            }

            .btn-primary {
                background: linear-gradient(135deg, var(--accent), #7c3aed);
                color: #fff;
                width: 100%;
            }

            .btn-primary:hover {
                background: linear-gradient(135deg, var(--accent-hover), #8b5cf6);
                transform: translateY(-1px);
                box-shadow: 0 4px 15px var(--accent-glow);
            }

            .btn-primary:active {
                transform: translateY(0);
            }

            .btn-sm {
                padding: 6px 12px;
                font-size: 12px;
                border-radius: 6px;
            }

            .btn-ghost {
                background: transparent;
                border: 1px solid var(--border);
                color: var(--text-secondary);
            }

            .btn-ghost:hover {
                background: var(--bg-hover);
                color: var(--text-primary);
                border-color: var(--text-muted);
            }

            .btn-danger {
                background: var(--danger-bg);
                color: var(--danger);
                border: 1px solid rgba(239, 68, 68, 0.2);
            }

            .btn-danger:hover {
                background: rgba(239, 68, 68, 0.2);
            }

            .btn-success {
                background: var(--success-bg);
                color: var(--success);
                border: 1px solid rgba(34, 197, 94, 0.2);
            }

            /* ===== DASHBOARD ===== */
            .dashboard {
                max-width: 1100px;
                margin: 0 auto;
                padding: 24px 20px;
            }

            .dashboard-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 28px;
                padding-bottom: 20px;
                border-bottom: 1px solid var(--border);
            }

            .dashboard-header .brand {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .dashboard-header .brand-icon {
                width: 40px;
                height: 40px;
                background: linear-gradient(135deg, var(--accent), #a855f7);
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 18px;
            }

            .dashboard-header .brand h1 {
                font-size: 20px;
                font-weight: 700;
            }

            .dashboard-header .brand span {
                font-size: 12px;
                color: var(--text-muted);
            }

            /* ===== STATS ===== */
            .stats-row {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                gap: 12px;
                margin-bottom: 28px;
            }

            .stat-card {
                background: var(--bg-card);
                border: 1px solid var(--border);
                border-radius: var(--radius);
                padding: 18px;
            }

            .stat-card .stat-label {
                font-size: 12px;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 6px;
            }

            .stat-card .stat-value {
                font-size: 28px;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary), var(--accent-hover));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            /* ===== CREATE LINK SECTION ===== */
            .section-card {
                background: var(--bg-card);
                border: 1px solid var(--border);
                border-radius: var(--radius);
                padding: 24px;
                margin-bottom: 24px;
            }

            .section-card h2 {
                font-size: 16px;
                font-weight: 700;
                margin-bottom: 20px;
                display: flex;
                align-items: center;
                gap: 8px;
            }

            .form-row {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 14px;
            }

            @media (max-width: 640px) {
                .form-row {
                    grid-template-columns: 1fr;
                }
            }

            /* ===== DROP ZONE ===== */
            .drop-zone {
                border: 2px dashed var(--border);
                border-radius: var(--radius);
                padding: 32px;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s;
                position: relative;
                overflow: hidden;
            }

            .drop-zone:hover,
            .drop-zone.dragover {
                border-color: var(--accent);
                background: rgba(99, 102, 241, 0.05);
            }

            .drop-zone .dz-icon {
                font-size: 36px;
                margin-bottom: 8px;
                opacity: 0.6;
            }

            .drop-zone .dz-text {
                color: var(--text-secondary);
                font-size: 14px;
            }

            .drop-zone .dz-hint {
                color: var(--text-muted);
                font-size: 12px;
                margin-top: 4px;
            }

            .drop-zone input[type="file"] {
                position: absolute;
                inset: 0;
                opacity: 0;
                cursor: pointer;
            }

            .image-preview {
                max-height: 160px;
                border-radius: var(--radius-sm);
                margin-top: 10px;
                display: none;
            }

            /* ===== RESULT BOX ===== */
            .result-box {
                display: none;
                background: var(--success-bg);
                border: 1px solid rgba(34, 197, 94, 0.2);
                border-radius: var(--radius);
                padding: 20px;
                margin-top: 16px;
                animation: fadeUp 0.3s ease;
            }

            .result-box h3 {
                font-size: 15px;
                color: var(--success);
                margin-bottom: 12px;
                display: flex;
                align-items: center;
                gap: 6px;
            }

            .copy-row {
                display: flex;
                gap: 8px;
                margin-bottom: 8px;
            }

            .copy-row input {
                flex: 1;
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(34, 197, 94, 0.15);
                color: var(--success);
                font-family: 'SF Mono', 'Consolas', monospace;
                font-size: 13px;
            }

            .copy-row .btn {
                white-space: nowrap;
            }

            /* ===== LINKS TABLE ===== */
            .links-table {
                width: 100%;
                border-collapse: collapse;
            }

            .links-table th {
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 0.7px;
                color: var(--text-muted);
                text-align: left;
                padding: 10px 12px;
                border-bottom: 1px solid var(--border);
                font-weight: 600;
            }

            .links-table td {
                padding: 12px;
                border-bottom: 1px solid rgba(34, 34, 51, 0.5);
                font-size: 13px;
                vertical-align: middle;
            }

            .links-table tr:hover td {
                background: var(--bg-hover);
            }

            .link-thumb {
                width: 56px;
                height: 36px;
                object-fit: cover;
                border-radius: 6px;
                border: 1px solid var(--border);
            }

            .link-id {
                font-family: 'SF Mono', 'Consolas', monospace;
                font-size: 12px;
                color: var(--accent-hover);
                background: rgba(99, 102, 241, 0.1);
                padding: 3px 8px;
                border-radius: 4px;
            }

            .link-url {
                max-width: 220px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                color: var(--text-secondary);
                font-size: 12px;
            }

            .link-clicks {
                font-weight: 700;
                color: var(--text-primary);
            }

            .link-date {
                color: var(--text-muted);
                font-size: 12px;
            }

            .link-actions {
                display: flex;
                gap: 6px;
                flex-wrap: wrap;
            }

            /* ===== EMPTY STATE ===== */
            .empty-state {
                text-align: center;
                padding: 48px 20px;
                color: var(--text-muted);
            }

            .empty-state .empty-icon {
                font-size: 48px;
                margin-bottom: 12px;
                opacity: 0.4;
            }

            .empty-state p {
                font-size: 14px;
            }

            /* ===== TOAST ===== */
            .toast-container {
                position: fixed;
                bottom: 20px;
                right: 20px;
                z-index: 9999;
                display: flex;
                flex-direction: column;
                gap: 8px;
            }

            .toast {
                background: var(--bg-card);
                border: 1px solid var(--border);
                border-radius: var(--radius-sm);
                padding: 12px 18px;
                font-size: 13px;
                animation: fadeUp 0.3s ease;
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.5);
                max-width: 320px;
            }

            .toast.success {
                border-left: 3px solid var(--success);
            }

            .toast.error {
                border-left: 3px solid var(--danger);
            }

            /* ===== LOADING OVERLAY ===== */
            .loading-overlay {
                display: none;
                position: fixed;
                inset: 0;
                background: rgba(6, 6, 10, 0.8);
                z-index: 9998;
                align-items: center;
                justify-content: center;
            }

            .loading-overlay.active {
                display: flex;
            }

            .loading-spinner {
                width: 44px;
                height: 44px;
                border: 3px solid rgba(255, 255, 255, 0.1);
                border-top-color: var(--accent);
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
            }

            /* ===== ANIMATIONS ===== */
            @keyframes fadeUp {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }

                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            @keyframes spin {
                to {
                    transform: rotate(360deg);
                }
            }

            /* ===== RESPONSIVE ===== */
            @media (max-width: 768px) {
                .dashboard {
                    padding: 16px 12px;
                }

                .dashboard-header {
                    flex-direction: column;
                    gap: 12px;
                    align-items: flex-start;
                }

                .links-table {
                    font-size: 12px;
                }

                .links-table th:nth-child(4),
                .links-table td:nth-child(4) {
                    display: none;
                }

                .section-card {
                    padding: 16px;
                }
            }

            /* ===== SCROLLBAR ===== */
            ::-webkit-scrollbar {
                width: 6px;
            }

            ::-webkit-scrollbar-track {
                background: var(--bg-primary);
            }

            ::-webkit-scrollbar-thumb {
                background: var(--border);
                border-radius: 3px;
            }

            ::-webkit-scrollbar-thumb:hover {
                background: var(--text-muted);
            }

            /* ===== Fetch OG button ===== */
            .fetch-og-btn {
                position: absolute;
                right: 8px;
                top: 50%;
                transform: translateY(-50%);
                background: var(--accent);
                color: #fff;
                border: none;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 11px;
                cursor: pointer;
                font-family: var(--font);
                font-weight: 600;
                transition: all 0.2s;
            }

            .fetch-og-btn:hover {
                background: var(--accent-hover);
            }

            .url-input-wrap {
                position: relative;
            }

            .url-input-wrap input {
                padding-right: 90px;
            }
        </style>
    </head>

    <body>

        <?php if (!$loggedIn): ?>
            <!-- ===== LOGIN SCREEN ===== -->
            <div class="login-container">
                <div class="login-card">
                    <div class="logo">🔗</div>
                    <h1><?= SITE_TITLE ?></h1>
                    <p>Login to manage your Facebook links</p>

                    <?php if ($loginError): ?>
                        <div class="error-msg"><?= htmlspecialchars($loginError) ?></div>
                    <?php endif; ?>

                    <form method="POST" action="">
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" name="login_password" placeholder="Enter admin password" autofocus required>
                        </div>
                        <button type="submit" class="btn btn-primary">Login →</button>
                    </form>
                </div>
            </div>

        <?php else: ?>
            <!-- ===== DASHBOARD ===== -->
            <div class="dashboard">

                <!-- Header -->
                <div class="dashboard-header">
                    <div class="brand">
                        <div class="brand-icon">🔗</div>
                        <div>
                            <h1><?= SITE_TITLE ?></h1>
                            <span>Anti-Ban Link System</span>
                        </div>
                    </div>
                    <div style="display:flex;gap:8px;align-items:center;">
                        <a href="<?= $baseUrl ?>?logout=1" class="btn btn-ghost btn-sm">Logout ↗</a>
                    </div>
                </div>

                <!-- Stats -->
                <div class="stats-row" id="statsRow">
                    <div class="stat-card">
                        <div class="stat-label">Total Links</div>
                        <div class="stat-value" id="statTotal">—</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total Clicks</div>
                        <div class="stat-value" id="statClicks">—</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Today's Clicks</div>
                        <div class="stat-value" id="statToday">—</div>
                    </div>
                </div>

                <!-- Create Link -->
                <div class="section-card">
                    <h2>⚡ Create New Link</h2>
                    <form id="createForm" enctype="multipart/form-data">
                        <div class="form-group">
                            <label>Target URL <span style="color:var(--danger)">*</span></label>
                            <div class="url-input-wrap">
                                <input type="url" name="url" id="inputUrl" placeholder="https://example.com/article-page"
                                    required>
                                <button type="button" class="fetch-og-btn" id="fetchOgBtn"
                                    title="Auto-fetch title & description from URL">🔍 Fetch</button>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>OG Image <span style="color:var(--danger)">*</span></label>
                            <div class="drop-zone" id="dropZone">
                                <div class="dz-icon">🖼️</div>
                                <div class="dz-text">Drop image here or click to upload</div>
                                <div class="dz-hint">JPG, PNG, WebP, GIF — Max 5MB — Auto-converts to JPG</div>
                                <input type="file" name="image" id="inputImage" accept="image/*" required>
                                <img class="image-preview" id="imagePreview" alt="Preview">
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Title <span style="color:var(--text-muted)">(auto-fetch if empty)</span></label>
                                <input type="text" name="title" id="inputTitle" placeholder="Article title for FB preview">
                            </div>
                            <div class="form-group">
                                <label>Site Name</label>
                                <input type="text" name="site_name" id="inputSiteName" placeholder="e.g. NewsHoxs, TechCrunch">
                            </div>
                        </div>

                        <div class="form-group">
                            <label>Description <span style="color:var(--text-muted)">(auto-fetch if empty)</span></label>
                            <textarea name="desc" id="inputDesc"
                                placeholder="Short description for FB preview card..."></textarea>
                        </div>

                        <button type="submit" class="btn btn-primary" id="createBtn">
                            ⚡ Create FB Link
                        </button>
                    </form>

                    <!-- Result Box -->
                    <div class="result-box" id="resultBox">
                        <h3>✅ Link Created Successfully!</h3>
                        <div style="margin-bottom:4px;">
                            <label style="font-size:11px;color:var(--text-muted);margin-bottom:4px;display:block;">Share this
                                link on Facebook:</label>
                            <div class="copy-row">
                                <input type="text" id="resultGoUrl" readonly>
                                <button class="btn btn-success btn-sm" onclick="copyText('resultGoUrl')">📋 Copy</button>
                            </div>
                        </div>
                        <div>
                            <label style="font-size:11px;color:var(--text-muted);margin-bottom:4px;display:block;">Image URL
                                (for debugging):</label>
                            <div class="copy-row">
                                <input type="text" id="resultImgUrl" readonly>
                                <button class="btn btn-success btn-sm" onclick="copyText('resultImgUrl')">📋 Copy</button>
                            </div>
                        </div>
                        <div style="margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap;">
                            <a id="resultTestLink" href="#" target="_blank" class="btn btn-ghost btn-sm">🔗 Test Link</a>
                            <a id="resultDebugLink" href="#" target="_blank" class="btn btn-ghost btn-sm">🐛 FB Debugger</a>
                        </div>
                    </div>
                </div>

                <!-- Links List -->
                <div class="section-card">
                    <h2>📋 All Links <span id="linksCount"
                            style="font-size:13px;color:var(--text-muted);font-weight:400;"></span></h2>
                    <div id="linksContainer">
                        <div class="empty-state">
                            <div class="empty-icon">🔗</div>
                            <p>Loading links...</p>
                        </div>
                    </div>
                </div>

            </div>

            <!-- Loading Overlay -->
            <div class="loading-overlay" id="loadingOverlay">
                <div class="loading-spinner"></div>
            </div>

            <!-- Toast Container -->
            <div class="toast-container" id="toastContainer"></div>

            <script>
                const BASE_URL = <?= json_encode($baseUrl) ?>;

                // ===== INIT =====
                document.addEventListener('DOMContentLoaded', () => {
                    loadLinks();
                    setupDropZone();
                    setupForm();
                    setupFetchOG();
                });

                // ===== LOAD LINKS =====
                async function loadLinks() {
                    try {
                        const res = await fetch(BASE_URL + '?api=list');
                        const data = await res.json();

                        if (data.success) {
                            renderLinks(data.links);
                            updateStats(data.links);
                        }
                    } catch (e) {
                        showToast('Failed to load links', 'error');
                    }
                }

                function updateStats(links) {
                    document.getElementById('statTotal').textContent = links.length;

                    let totalClicks = 0;
                    let todayClicks = 0;
                    const today = new Date().toISOString().split('T')[0];

                    links.forEach(l => {
                        totalClicks += l.clicks || 0;
                        if (l.last_click && l.last_click.startsWith(today)) {
                            todayClicks += 1;
                        }
                    });

                    document.getElementById('statClicks').textContent = totalClicks.toLocaleString();
                    document.getElementById('statToday').textContent = todayClicks;
                }

                function renderLinks(links) {
                    const container = document.getElementById('linksContainer');
                    document.getElementById('linksCount').textContent = `(${links.length})`;

                    if (links.length === 0) {
                        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🔗</div>
                <p>No links yet. Create your first one above!</p>
            </div>`;
                        return;
                    }

                    let html = `
        <div style="overflow-x:auto;">
        <table class="links-table">
            <thead>
                <tr>
                    <th>Image</th>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Target URL</th>
                    <th>Clicks</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>`;

                    links.forEach(link => {
                        const imgUrl = BASE_URL + '?img=' + link.id;
                        const goUrl = BASE_URL + '?id=' + link.id;
                        const title = escapeHtml(link.title || 'Untitled');
                        const shortTitle = title.length > 40 ? title.substring(0, 40) + '…' : title;
                        const shortUrl = (link.url || '').replace(/^https?:\/\//, '').substring(0, 35);
                        const dateStr = link.created ? link.created.split(' ')[0] : '—';

                        html += `
            <tr>
                <td><img src="${imgUrl}" class="link-thumb" alt="" onerror="this.style.display='none'"></td>
                <td><span class="link-id">${link.id}</span></td>
                <td title="${title}">${shortTitle}</td>
                <td><div class="link-url" title="${escapeHtml(link.url)}">${escapeHtml(shortUrl)}</div></td>
                <td><span class="link-clicks">${(link.clicks || 0).toLocaleString()}</span></td>
                <td><span class="link-date">${dateStr}</span></td>
                <td>
                    <div class="link-actions">
                        <button class="btn btn-ghost btn-sm" onclick="copyToClipboard('${goUrl}')" title="Copy link">📋</button>
                        <a href="${goUrl}" target="_blank" class="btn btn-ghost btn-sm" title="Test link">🔗</a>
                        <a href="https://developers.facebook.com/tools/debug/?q=${encodeURIComponent(goUrl)}" target="_blank" class="btn btn-ghost btn-sm" title="FB Debugger">🐛</a>
                        <button class="btn btn-danger btn-sm" onclick="deleteLink('${link.id}')" title="Delete">🗑</button>
                    </div>
                </td>
            </tr>`;
                    });

                    html += '</tbody></table></div>';
                    container.innerHTML = html;
                }

                // ===== CREATE LINK =====
                function setupForm() {
                    document.getElementById('createForm').addEventListener('submit', async (e) => {
                        e.preventDefault();

                        const form = e.target;
                        const formData = new FormData(form);
                        const btn = document.getElementById('createBtn');

                        btn.disabled = true;
                        btn.textContent = '⏳ Creating...';
                        showLoading(true);

                        try {
                            const res = await fetch(BASE_URL + '?api=create', {
                                method: 'POST',
                                body: formData,
                            });

                            const data = await res.json();

                            if (data.success) {
                                // Show result
                                document.getElementById('resultGoUrl').value = data.go_url;
                                document.getElementById('resultImgUrl').value = data.img_url;
                                document.getElementById('resultTestLink').href = data.go_url;
                                document.getElementById('resultDebugLink').href = 'https://developers.facebook.com/tools/debug/?q=' + encodeURIComponent(data.go_url);
                                document.getElementById('resultBox').style.display = 'block';

                                // Reset form
                                form.reset();
                                document.getElementById('imagePreview').style.display = 'none';
                                document.getElementById('dropZone').querySelector('.dz-icon').textContent = '🖼️';
                                document.getElementById('dropZone').querySelector('.dz-text').textContent = 'Drop image here or click to upload';

                                showToast('Link created successfully!', 'success');
                                loadLinks();
                            } else {
                                showToast(data.error || 'Creation failed', 'error');
                            }
                        } catch (e) {
                            showToast('Network error. Try again.', 'error');
                        } finally {
                            btn.disabled = false;
                            btn.textContent = '⚡ Create FB Link';
                            showLoading(false);
                        }
                    });
                }

                // ===== DROP ZONE =====
                function setupDropZone() {
                    const zone = document.getElementById('dropZone');
                    const input = document.getElementById('inputImage');
                    const preview = document.getElementById('imagePreview');

                    ['dragenter', 'dragover'].forEach(evt => {
                        zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.add('dragover'); });
                    });

                    ['dragleave', 'drop'].forEach(evt => {
                        zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.remove('dragover'); });
                    });

                    zone.addEventListener('drop', (e) => {
                        const files = e.dataTransfer.files;
                        if (files.length > 0) {
                            input.files = files;
                            showPreview(files[0]);
                        }
                    });

                    input.addEventListener('change', () => {
                        if (input.files.length > 0) {
                            showPreview(input.files[0]);
                        }
                    });

                    function showPreview(file) {
                        if (!file.type.startsWith('image/')) return;
                        const reader = new FileReader();
                        reader.onload = (e) => {
                            preview.src = e.target.result;
                            preview.style.display = 'block';
                            zone.querySelector('.dz-icon').textContent = '✅';
                            zone.querySelector('.dz-text').textContent = file.name;
                        };
                        reader.readAsDataURL(file);
                    }
                }

                // ===== FETCH OG DATA =====
                function setupFetchOG() {
                    document.getElementById('fetchOgBtn').addEventListener('click', async () => {
                        const url = document.getElementById('inputUrl').value.trim();
                        if (!url) {
                            showToast('Enter a URL first', 'error');
                            return;
                        }

                        const btn = document.getElementById('fetchOgBtn');
                        btn.textContent = '⏳';
                        btn.disabled = true;

                        try {
                            const formData = new FormData();
                            formData.append('url', url);

                            const res = await fetch(BASE_URL + '?api=fetch-og', {
                                method: 'POST',
                                body: formData,
                            });
                            const data = await res.json();

                            if (data.success && data.data) {
                                if (data.data.title) document.getElementById('inputTitle').value = data.data.title;
                                if (data.data.desc) document.getElementById('inputDesc').value = data.data.desc;
                                if (data.data.site_name) document.getElementById('inputSiteName').value = data.data.site_name;
                                showToast('OG data fetched!', 'success');
                            } else {
                                showToast('Could not fetch OG data', 'error');
                            }
                        } catch (e) {
                            showToast('Fetch failed', 'error');
                        } finally {
                            btn.textContent = '🔍 Fetch';
                            btn.disabled = false;
                        }
                    });
                }

                // ===== DELETE LINK =====
                async function deleteLink(id) {
                    if (!confirm('Delete this link? This cannot be undone.')) return;

                    showLoading(true);
                    try {
                        const formData = new FormData();
                        formData.append('id', id);

                        const res = await fetch(BASE_URL + '?api=delete', {
                            method: 'POST',
                            body: formData,
                        });
                        const data = await res.json();

                        if (data.success) {
                            showToast('Link deleted', 'success');
                            loadLinks();
                        } else {
                            showToast(data.error || 'Delete failed', 'error');
                        }
                    } catch (e) {
                        showToast('Network error', 'error');
                    } finally {
                        showLoading(false);
                    }
                }

                // ===== COPY =====
                function copyText(inputId) {
                    const input = document.getElementById(inputId);
                    input.select();
                    navigator.clipboard.writeText(input.value).then(() => {
                        showToast('Copied to clipboard!', 'success');
                    }).catch(() => {
                        document.execCommand('copy');
                        showToast('Copied!', 'success');
                    });
                }

                function copyToClipboard(text) {
                    navigator.clipboard.writeText(text).then(() => {
                        showToast('Copied to clipboard!', 'success');
                    }).catch(() => {
                        // Fallback
                        const input = document.createElement('input');
                        input.value = text;
                        document.body.appendChild(input);
                        input.select();
                        document.execCommand('copy');
                        document.body.removeChild(input);
                        showToast('Copied!', 'success');
                    });
                }

                // ===== TOAST =====
                function showToast(message, type = 'success') {
                    const container = document.getElementById('toastContainer');
                    const toast = document.createElement('div');
                    toast.className = 'toast ' + type;
                    toast.textContent = (type === 'success' ? '✅ ' : '❌ ') + message;
                    container.appendChild(toast);
                    setTimeout(() => toast.remove(), 3500);
                }

                // ===== LOADING =====
                function showLoading(show) {
                    const overlay = document.getElementById('loadingOverlay');
                    if (show) overlay.classList.add('active');
                    else overlay.classList.remove('active');
                }

                // ===== HELPERS =====
                function escapeHtml(str) {
                    const div = document.createElement('div');
                    div.textContent = str || '';
                    return div.innerHTML;
                }
            </script>

        <?php endif; ?>
    </body>

    </html>
<?php } ?>