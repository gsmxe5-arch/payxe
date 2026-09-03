# PAYXE.NET – DHRU Fusion Payment Gateway Setup Guide

Follow this complete guide to connect **PAYXE.NET** with your **DHRU Fusion** website.

---

# Step 1 – Upload PAYXE Gateway Files

Before configuring PAYXE, you must upload the PAYXE gateway files to your DHRU Fusion installation.

After downloading the **PAYXE DHRU Fusion Gateway ZIP file**, extract the ZIP file on your computer.

You should have these two files:

```text
payxe_callback.php
payxe.php
```

## 1.1 Upload `payxe_callback.php`

Login to your DHRU Fusion hosting **cPanel**.

Open:

**File Manager → public_html/**

Upload:

```text
payxe_callback.php
```

The final location must be:

```text
public_html/payxe_callback.php
```

For example, if your DHRU Fusion website is:

```text
https://gsmxe.com
```

the callback URL will be:

```text
https://gsmxe.com/payxe_callback.php
```

### Important

Do **not** upload `payxe_callback.php` inside:

```text
public_html/modules/gateways/
```

It must be directly inside the main `public_html` directory.

---

## 1.2 Upload `payxe.php`

Now open:

```text
public_html/modules/gateways/
```

Upload:

```text
payxe.php
```

The final location must be:

```text
public_html/modules/gateways/payxe.php
```

Your file structure should look like:

```text
public_html/
│
├── payxe_callback.php
│
├── modules/
│   └── gateways/
│       └── payxe.php
│
├── admin/
├── includes/
├── templates/
└── other DHRU Fusion files
```

## 1.3 Verify the Files

Make sure both files exist in the correct locations.

**Callback:**

```text
public_html/payxe_callback.php
```

**Gateway module:**

```text
public_html/modules/gateways/payxe.php
```

Do not rename either file.

The filenames must remain exactly:

```text
payxe_callback.php
payxe.php
```

Once both files are uploaded, continue to Step 2.

---

# Step 2 – Add Your DHRU Fusion Domain to PAYXE.NET

Now you need to authorize the DHRU Fusion website where PAYXE will be used.

Login to your **PAYXE.NET Dashboard**.

Go to:

**Domains → Add Domain**

## 2.1 Enter Your Domain

Enter the domain of your DHRU Fusion installation.

For example:

```text
gsmxe.com
```

You can enter **your own DHRU Fusion domain**.

For example:

```text
mygsmstore.com
example.com
gsmxe.com
```

The domain does not have to be a specific fixed domain. Each customer can add their own DHRU Fusion domain.

### Example

If your DHRU Fusion website is:

```text
https://gsmxe.com
```

add:

```text
gsmxe.com
```

If your DHRU Fusion website is:

```text
https://example.com
```

add:

```text
example.com
```

> **Important:** Enter the actual domain where your DHRU Fusion installation is running.

Save the domain after adding it.

---

# Step 3 – Create Your PAYXE API Key

After adding your domain, go to:

**API → Create API Key**

You will see the API configuration page.

## 3.1 API Environment Name

Enter any name you want to identify this API key.

For example:

```text
DHRU Fusion
```

You can use any name you prefer, such as:

```text
GSMXE
```

```text
My DHRU Gateway
```

```text
DHRU Production
```

```text
GSM Store
```

The **API Environment Name is only for identification**, so you can choose your own name.

---

## 3.2 Webhook Notification URL

Enter the callback URL of your DHRU Fusion website.

Use:

```text
https://YOUR-DOMAIN.COM/payxe_callback.php
```

Replace `YOUR-DOMAIN.COM` with your actual DHRU Fusion domain.

### Example

If your domain is:

```text
gsmxe.com
```

enter:

```text
https://gsmxe.com/payxe_callback.php
```

If your domain is:

```text
example.com
```

enter:

```text
https://example.com/payxe_callback.php
```

> **Important:** The webhook URL must point to the `payxe_callback.php` file uploaded in Step 1.

---

## 3.3 Authorized Domains

Under **Authorized Domains**, select the DHRU Fusion domain you added in Step 2.

For example:

```text
gsmxe.com
```

This authorizes PAYXE to create and process payment invoices for that domain.

---

## 3.4 Allowed Payment Gateways

Select the payment methods you want to make available to your DHRU Fusion customers.

Available methods may include:

* **USDT C2C (Binance)**
* **USDT (BEP20 – BSC)**
* **USDT (TRC20 – Tron)**

Select the payment methods you want to use.

Then click:

**Generate API Key**

After the API key is generated, securely save:

```text
API Key
API Secret
```

> **Security:** Never share your API Secret publicly or include it in screenshots, forum posts, or support messages.

---

# Step 4 – Configure Payment Methods

Now configure the payment methods you selected in the PAYXE.NET Dashboard.

## 4.1 USDT C2C – Binance

Open the **USDT C2C (Binance)** payment method.

Enter the required Binance credentials:

```text
Binance API Key
Binance Secret Key
```

Complete the required configuration and save the settings.

Make sure the Binance API credentials have the permissions required by PAYXE.

---

## 4.2 USDT BEP20 – BSC

If you want to accept **USDT BEP20**, configure the required wallet and BSC network settings in PAYXE.NET.

Make sure the configured wallet/network matches the payment method selected for your customers.

---

## 4.3 USDT TRC20 – Tron

If you want to accept **USDT TRC20**, configure the required wallet and Tron network settings in PAYXE.NET.

Save the configuration after completing the required settings.

---

# Step 5 – Configure PAYXE in DHRU Fusion

Now login to your **DHRU Fusion Admin Panel**.

Go to:

**Settings → Payment Gateways**

Find:

**PAYXE**

Click:

**Activate / Edit**

Enter the credentials generated in Step 3:

```text
API Key
API Secret
```

Save the settings.

Make sure the PAYXE gateway is enabled.

---

# Step 6 – Test the Integration

Login to a DHRU Fusion customer account.

Go to:

**Add Funds**

Select:

**PAYXE**

Enter the amount you want to deposit.

Click:

**Pay**

Select the desired payment method and complete the payment.

---

# Step 7 – Payment Flow

After a successful payment, the complete process should work like this:

```text
Customer
    ↓
DHRU Fusion
    ↓
PAYXE Payment
    ↓
Customer Completes Payment
    ↓
PAYXE Confirms Payment
    ↓
PAYXE Webhook
    ↓
payxe_callback.php
    ↓
DHRU Fusion
    ↓
Invoice Marked as Paid
    ↓
Customer Balance Added
```

---

# Troubleshooting

## PAYXE Gateway Does Not Appear

Check that:

```text
public_html/modules/gateways/payxe.php
```

exists and was uploaded correctly.

Also make sure PAYXE is activated from:

**DHRU Fusion Admin → Settings → Payment Gateways**

---

## Webhook Is Not Working

Check that:

```text
public_html/payxe_callback.php
```

exists.

Then verify that your PAYXE webhook URL is exactly:

```text
https://YOUR-DOMAIN.COM/payxe_callback.php
```

The domain in the webhook URL must match the authorized DHRU Fusion domain.

---

## API Error

Verify that the following credentials are correct:

```text
API Key
API Secret
```

Also make sure the correct domain is selected under:

**Authorized Domains**

---

# Final Checklist

Before testing, confirm all of the following:

### DHRU Fusion Files

```text
✓ public_html/payxe_callback.php
✓ public_html/modules/gateways/payxe.php
```

### PAYXE.NET

```text
✓ DHRU Fusion domain added
✓ API key created
✓ Custom API Environment Name configured
✓ Correct webhook URL configured
✓ Correct authorized domain selected
✓ Required payment methods enabled
```

### Payment Configuration

```text
✓ Binance credentials configured (if using C2C)
✓ BEP20 wallet/network configured (if using BEP20)
✓ TRC20 wallet/network configured (if using TRC20)
```

### DHRU Fusion

```text
✓ PAYXE gateway activated
✓ API Key entered
✓ API Secret entered
✓ Test deposit completed
```

If all of the above are configured correctly, your **PAYXE.NET → DHRU Fusion payment gateway integration** is ready to use.
