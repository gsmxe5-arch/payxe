<?php

class PayXe_Service
{
    private $gateway_url = "https://payxe.net/api/v1/merchant/invoices";
    private $params = [];
    private $args = [];
    public $http_code = 0;

    public function __construct($params) {
        $this->params = $params;

        $this->args = [
            "customer_name" => $this->params["clientdetails"]["firstname"] . " " . $this->params["clientdetails"]["lastname"],
            "customer_email" => $this->params["clientdetails"]["email"],
            "items" => [
                [
                    "description" => $this->params["description"],
                    "quantity" => 1,
                    "unit_price" => ($this->params["amount"] - $this->params["invtax"])
                ]
            ],
            "redirect_url" => $this->params['systemurl'] . 'viewinvoice/id/'.md5($this->params["invoiceid"]),
            "metadata" => [
                "order_id" => $this->params["invoiceid"]
            ]
        ];
    }
   
    public function generate_link() {
        $timestamp = time();
        $body = json_encode($this->args);
        $current_domain = $_SERVER['HTTP_HOST'];
        $referer_url = "https://" . $current_domain;
        // HMAC-SHA256 signature generate karna
        $signature_string = $this->params['api_key'] . $timestamp . $body;
        $signature = hash_hmac('sha256', $signature_string, $this->params['api_secret']);
        $headers = [
            'Content-Type: application/json',
            'X-API-Key: ' . $this->params['api_key'],
            'X-API-Timestamp: ' . $timestamp,
            'X-API-Signature: ' . $signature,
            'Referer: ' . $referer_url
        ];
        // Optional: Add Origin header as well if needed
       // $headers[] = 'Origin: ' . $referer_url;
    
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->gateway_url);
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
        
            'Content-Type: application/json',
            'X-API-Key: ' . $this->params['api_key'],
            'X-API-Timestamp: ' . $timestamp,
            'X-API-Signature: ' . $signature
        ]);
        // Add Referer cURL option
        curl_setopt($ch, CURLOPT_REFERER, $referer_url);
        // SSL verification enable karein production ke liye
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        $response = curl_exec($ch);
        
        if(curl_errno($ch)) {
            // Log error internally, user ko generic message show karein
            error_log("PayXe Curl Error: " . curl_error($ch));
        }
        
        $this->http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return json_decode($response);
    }
}

function payxe_config()
{
    $configarray = array(
        'name' => array(
            'Type' => 'System',
            'Value' => 'PayXe - Payment Gateway'
        ),
        'api_key' => array(
            'Name' => 'API Key',
            'Type' => 'text',
            'Value' => '',
            'Size' => '50',
            'Description' => 'Enter your PayXe API Key'
        ),
        'api_secret' => array(
            'Name' => 'API Secret Key',
            'Type' => 'text',
            'Value' => '',
            'Size' => '50',
            'Description' => 'Enter your PayXe API Secret Key'
        ),
    );
    
    return $configarray;
}

function payxe_link($params)
{   
    global $lng_languag;
    $client = new PayXe_Service($params);
    $server_response = $client->generate_link();

    if($client->http_code === 403) {
        return '<p style="color:red;">Please check your API credentials</p>';
    }

    // 201 (Created) ko bhi success status mana jaye
    if($client->http_code !== 200 && $client->http_code !== 201) {
        return '<p style="color:red;">PayXe Server Offline</p>';
    }

    if (!$server_response->success || isset($server_response->error)) {
        $error_message = isset($server_response->message) ? $server_response->message : 'Payment link generation failed';
        return '<p style="color:red;">'.$error_message.'</p>';
    }

    if (isset($server_response->invoice->view_url)) {
        return '<a class="btn btn-success pt-3 pb-3" style="width: 100%; background-color: green!important;" href="'.$server_response->invoice->view_url.'">'.$lng_languag["invoicespaynow"].'</a>';
    } else {
        return '<p style="color:red;">Payment link not generated</p>';
    }
}

?>