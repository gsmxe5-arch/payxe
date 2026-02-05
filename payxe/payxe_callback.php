<?php

ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);
date_default_timezone_set('Asia/Karachi');

// DHRU Fusion Integration
define("DEFINE_MY_ACCESS", true);
define("DEFINE_DHRU_FILE", true);
define("ROOTDIR", dirname(__FILE__));

// Include DHRU files
include ROOTDIR . "/comm.php";
require ROOTDIR . "/includes/fun.inc.php";
include ROOTDIR . "/includes/gateway.fun.php";
include ROOTDIR . "/includes/invoice.fun.php";

$version = 1.0;
$GATEWAY = loadGatewayModule('payxe');

// Check if gateway is active
if ($GATEWAY["active"] != 1) {
    http_response_code(503);
    exit(json_encode(['success' => false, 'message' => 'Gateway not activated']));
}

// Get webhook secret from gateway settings
$secret_key = isset($GATEWAY['api_secret']) ? $GATEWAY['api_secret'] : '';

if (empty($secret_key)) {
    logTransaction('payxe', [], "Webhook Error: API Secret not configured");
    http_response_code(500);
    exit(json_encode(['success' => false, 'message' => 'Gateway not properly configured']));
}

// ===== SECURITY LAYER 1: Domain/Origin Check (Optional) =====
$allowed_domains = [
    'payxe.net',
    'www.payxe.net'
];

$client_ip = getClientIP();
$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
$referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
$user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

// Check if request is from allowed domain (soft check, not blocking)
$is_valid_origin = false;

if (!empty($origin)) {
    $parsed = parse_url($origin);
    $origin_host = isset($parsed['host']) ? $parsed['host'] : '';
    if (in_array($origin_host, $allowed_domains)) {
        $is_valid_origin = true;
    }
}

if (!$is_valid_origin && !empty($referer)) {
    $parsed = parse_url($referer);
    $referer_host = isset($parsed['host']) ? $parsed['host'] : '';
    if (in_array($referer_host, $allowed_domains)) {
        $is_valid_origin = true;
    }
}

// Log warning if domain check fails (but don't block - rely on HMAC)
if (!$is_valid_origin) {
    logTransaction('payxe', [
        'ip' => $client_ip,
        'origin' => $origin,
        'referer' => $referer,
        'user_agent' => $user_agent
    ], "Security Warning: Request from unverified domain (proceeding with HMAC check)");
}

// ===== TEST CALLBACK FEATURE (Optional) =====
// Check if this is a test request from pay panel
if (isset($_GET['test']) || (isset($_POST['test']) && $_POST['test'] === 'true')) {
    $test_response = [
        'success' => true,
        'message' => 'Webhook endpoint is working correctly',
        'server_info' => [
            'ip' => getClientIP(),
            'time' => date('Y-m-d H:i:s'),
            'version' => $version
        ],
        'gateway_status' => $GATEWAY["active"] == 1 ? 'active' : 'inactive',
        'webhook_url' => $_SERVER['REQUEST_URI']
    ];
    
    logTransaction('payxe', $test_response, "Test webhook request received");
    http_response_code(200);
    exit(json_encode($test_response));
}

// Get raw POST data
$payload = file_get_contents('php://input');

if (empty($payload)) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'No data received']));
}

// ===== SECURITY LAYER 2: HMAC Signature Verification (Primary Security) =====
$signature = isset($_SERVER['HTTP_X_WEBHOOK_SIGNATURE']) ? $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] : '';

if (empty($signature)) {
    logTransaction('payxe', [
        'ip' => $client_ip,
        'payload' => substr($payload, 0, 200)
    ], "Security Error: Missing signature header");
    http_response_code(401);
    exit(json_encode(['success' => false, 'message' => 'Missing signature']));
}

// Verify HMAC signature
$expected_signature = hash_hmac('sha256', $payload, $secret_key);

if (!hash_equals($expected_signature, $signature)) {
    logTransaction('payxe', [
        'ip' => $client_ip,
        'payload' => substr($payload, 0, 200),
        'signature_received' => substr($signature, 0, 20) . '...',
        'signature_expected' => substr($expected_signature, 0, 20) . '...'
    ], "Security Error: Invalid HMAC signature - POSSIBLE ATTACK DETECTED");
    http_response_code(401);
    exit(json_encode(['success' => false, 'message' => 'Invalid signature']));
}

// Decode JSON payload
$webhook_data = json_decode($payload, true);

if (!$webhook_data || !isset($webhook_data['event'], $webhook_data['data'])) {
    logTransaction('payxe', $payload, "Webhook Error: Invalid JSON structure");
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Invalid webhook data']));
}

// ===== SECURITY LAYER 3: Replay Attack Prevention =====
if (isset($webhook_data['timestamp'])) {
    $webhook_timestamp = strtotime($webhook_data['timestamp']);
    $current_timestamp = time();
    $time_difference = abs($current_timestamp - $webhook_timestamp);
    
    // Reject webhooks older than 5 minutes (300 seconds)
    if ($time_difference > 300) {
        logTransaction('payxe', [
            'webhook_time' => $webhook_data['timestamp'],
            'current_time' => date('Y-m-d H:i:s', $current_timestamp),
            'time_diff_seconds' => $time_difference
        ], "Security Error: Replay attack prevented - Webhook timestamp too old");
        http_response_code(400);
        exit(json_encode(['success' => false, 'message' => 'Webhook expired - possible replay attack']));
    }
}

// Extract webhook data
$event = $webhook_data['event'];
$invoice_data = $webhook_data['data'];

// Only process 'invoice.paid' events
if ($event !== 'invoice.paid') {
    http_response_code(200);
    exit(json_encode(['success' => true, 'message' => 'Event ignored: ' . $event]));
}

// Extract required fields
$invoice_id = isset($invoice_data['metadata']['order_id']) ? intval($invoice_data['metadata']['order_id']) : 0;
$transaction_id = isset($invoice_data['transaction_id']) ? $invoice_data['transaction_id'] : '';
$amount = isset($invoice_data['amount']) ? floatval($invoice_data['amount']) : 0;
$status = isset($invoice_data['status']) ? $invoice_data['status'] : '';
$customer_email = isset($invoice_data['customer']['email']) ? $invoice_data['customer']['email'] : '';
$gateway_name = isset($invoice_data['gateway']) ? $invoice_data['gateway'] : 'payxe';
$currency = isset($invoice_data['currency']) ? $invoice_data['currency'] : 'USD';
$paid_at = isset($invoice_data['paid_at']) ? $invoice_data['paid_at'] : '';

// Validate required data
if ($invoice_id <= 0) {
    logTransaction('payxe', $payload, "Webhook Error: Invalid or missing order_id in metadata");
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Invalid order_id in metadata']));
}

if (empty($transaction_id)) {
    logTransaction('payxe', $payload, "Webhook Error: Missing transaction_id");
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Missing transaction_id']));
}

if ($amount <= 0) {
    logTransaction('payxe', $payload, "Webhook Error: Invalid amount - must be greater than 0");
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Invalid amount']));
}

if ($status !== 'paid') {
    logTransaction('payxe', [
        'invoice_id' => $invoice_id,
        'status' => $status
    ], "Webhook Info: Status is not 'paid', current status: " . $status);
    http_response_code(200);
    exit(json_encode(['success' => true, 'message' => 'Status not paid: ' . $status]));
}

// ===== SECURITY LAYER 4: Duplicate Transaction Prevention =====
if (searchTxid($transaction_id)) {
    logTransaction('payxe', [
        'invoice_id' => $invoice_id,
        'transaction_id' => $transaction_id,
        'ip' => $client_ip
    ], "Security Error: Duplicate transaction attempt - Already processed");
    http_response_code(409);
    exit(json_encode(['success' => false, 'message' => 'Transaction already processed']));
}

// Get invoice details from DHRU database
$orderDetails = getInvoiceDetails($invoice_id, $customer_email);

if (!$orderDetails) {
    logTransaction('payxe', [
        'invoice_id' => $invoice_id,
        'customer_email' => $customer_email
    ], "Webhook Error: Invoice not found in database");
    http_response_code(404);
    exit(json_encode(['success' => false, 'message' => 'Invoice not found']));
}

// Check if invoice is already paid
if ($orderDetails['status'] == "Paid") {
    logTransaction('payxe', [
        'invoice_id' => $invoice_id,
        'status' => $orderDetails['status']
    ], "Webhook Info: Invoice already marked as paid - Skipping");
    http_response_code(200);
    exit(json_encode(['success' => true, 'message' => 'Invoice already paid']));
}

// ===== SECURITY LAYER 5: Amount Validation =====
$expected_amount = floatval($orderDetails['total']);
$amount_difference = abs($amount - $expected_amount);

// Allow small floating point difference (0.01)
if ($amount_difference > 0.01) {
    logTransaction('payxe', [
        'invoice_id' => $invoice_id,
        'expected_amount' => $expected_amount,
        'received_amount' => $amount,
        'difference' => $amount_difference
    ], "Security Error: Amount mismatch - Possible tampering detected");
    http_response_code(400);
    exit(json_encode([
        'success' => false, 
        'message' => 'Amount mismatch',
        'expected' => $expected_amount,
        'received' => $amount
    ]));
}

// ===== PROCESS PAYMENT =====
try {
    $fee = 0; // Set fee if applicable
    $payment_method = 'payxe';
    
    
    
    // Add payment to DHRU system
    addPayment($invoice_id, $transaction_id, $amount, $fee, $payment_method);
    
    // Log successful transaction
    $log_data = [
        'invoice_id' => $invoice_id,
        'transaction_id' => $transaction_id,
        'amount' => $amount,
        'currency' => $currency,
        'customer_email' => $customer_email,
        'gateway' => $gateway_name,
        'paid_at' => $paid_at,
        'status' => 'paid',
        'user_id' => $orderDetails['userid'],
        'ip' => $client_ip
    ];
    
    logTransaction('payxe', $log_data, "SUCCESS: Payment processed and invoice marked as paid");
    
    // Success response
    http_response_code(200);
    exit(json_encode([
        'success' => true,
        'message' => 'Payment processed successfully',
        'invoice_id' => $invoice_id,
        'amount' => $amount,
        'currency' => $currency,
        'transaction_id' => $transaction_id
    ]));
    
} catch (Exception $e) {
    logTransaction('payxe', [
        'invoice_id' => $invoice_id,
        'error' => $e->getMessage()
    ], "CRITICAL ERROR: Payment processing failed - " . $e->getMessage());
    http_response_code(500);
    exit(json_encode(['success' => false, 'message' => 'Payment processing failed']));
}


// ===== HELPER FUNCTIONS =====

function getClientIP() {
    $ip = '';
    
    // Check for Cloudflare IP headers first
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Get first IP if multiple IPs
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]);
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    
    // Validate IP format
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }
    
    return 'Unknown';
}

function getInvoiceDetails($order_id, $user_email) {
    $order_id_safe = intval($order_id);
    $user_email_safe = addslashes($user_email);

    $query = "
        SELECT 
            i.*, 
            GROUP_CONCAT(ii.`type` SEPARATOR ',') AS item_types
        FROM `tbl_invoices` AS i
        INNER JOIN `tblUsers` AS u 
            ON i.`userid` = u.`id`
        LEFT JOIN `tbl_invoiceitems` AS ii 
            ON ii.`invoiceid` = i.`id`
        WHERE 
            i.`id` = '$order_id_safe'
        AND u.`email` = '$user_email_safe'
        GROUP BY i.`id`
        LIMIT 1
    ";

    $result = dquery($query);
    if (!$result || mysqli_num_rows($result) == 0) {
        return false;
    }

    return mysqli_fetch_assoc($result);
}

function searchTxid($transid) {
    $transid_safe = addslashes($transid);
    $result = select_query("tbl_transaction", "id", ["transid" => $transid_safe]);
    
    if (!$result) {
        return false;
    }
    
    $num_rows = mysqli_num_rows($result);
    return ($num_rows > 0);
}

// ===== OPTIONAL: PayXe API Verification Function =====

function verifyPaymentWithPayXe($invoice_id, $transaction_id, $amount, $GATEWAY) {
   
    
    return true; // Return true if verification not implemented
}

?>