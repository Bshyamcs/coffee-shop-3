'use strict';
/**
 * Razorpay Standard Checkout integration.
 *
 *   RAZORPAY_KEY_ID        - public key, safe to expose to the browser
 *   RAZORPAY_KEY_SECRET    - server-only, used to create orders and verify payment signatures
 *   RAZORPAY_WEBHOOK_SECRET- server-only, set the SAME value in Razorpay Dashboard -> Settings -> Webhooks
 *
 * Payment flow (all amounts in paise, the smallest INR unit):
 *   1. POST /api/checkout/razorpay/create  -> we create a Razorpay Order and a short-lived "pending" record
 *   2. Browser opens Razorpay Checkout with that order id
 *   3. POST /api/checkout/razorpay/verify  -> we verify razorpay_signature server-side before saving the order
 *   4. POST /api/webhooks/razorpay         -> a backup: Razorpay calls this directly in case step 3 never
 *      reaches us (tab closed, network drop). Its signature is over the RAW request body, so it only works
 *      once NODEJS_HELPERS=0 is set in the Vercel project (see README) - otherwise Vercel has already
 *      parsed the body and the exact original bytes are gone, and we correctly refuse to trust it unverified.
 */
const crypto = require('crypto');
const A = require('./auth');

// Overridable only for tests, so we can point at a local mock instead of the real Razorpay API.
const API_BASE = (process.env.RAZORPAY_API_BASE || 'https://api.razorpay.com').replace(/\/+$/, '');

function config() {
  const keyId = (process.env.RAZORPAY_KEY_ID || '').trim();
  const keySecret = (process.env.RAZORPAY_KEY_SECRET || '').trim();
  const webhookSecret = (process.env.RAZORPAY_WEBHOOK_SECRET || '').trim();
  return { keyId, keySecret, webhookSecret, enabled: !!(keyId && keySecret) };
}

/** Creates an Order via Razorpay's Orders API. `amount` must be an integer number of paise. */
async function createOrder({ amount, currency = 'INR', receipt, notes }) {
  const { keyId, keySecret, enabled } = config();
  if (!enabled) { const e = new Error('Online payment is not configured'); e.status = 503; throw e; }
  if (!Number.isInteger(amount) || amount < 100) { const e = new Error('Invalid payment amount'); e.status = 400; throw e; }
  const auth = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
  let resp;
  try {
    resp = await fetch(`${API_BASE}/v1/orders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Basic ${auth}` },
      body: JSON.stringify({ amount, currency, receipt, notes, payment_capture: 1 }),
    });
  } catch (e) {
    const err = new Error('Could not reach Razorpay. Please try again.'); err.status = 502; throw err;
  }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const msg = (data && data.error && data.error.description) || 'Could not start payment. Please try again.';
    const err = new Error(msg); err.status = 502; throw err;
  }
  return data; // { id, amount, currency, receipt, status, ... }
}

/** HMAC-SHA256(order_id + "|" + payment_id, key_secret) must equal the signature Checkout returns. */
function verifyPaymentSignature({ orderId, paymentId, signature }) {
  const { keySecret } = config();
  if (!keySecret || !orderId || !paymentId || !signature) return false;
  const expected = crypto.createHmac('sha256', keySecret).update(`${orderId}|${paymentId}`).digest('hex');
  return A.safeEqual(expected, signature);
}

/** Webhooks are signed over the RAW (unparsed) request body with a separate secret. */
function verifyWebhookSignature(rawBody, signature) {
  const { webhookSecret } = config();
  if (!webhookSecret || !signature || typeof rawBody !== 'string') return false;
  const expected = crypto.createHmac('sha256', webhookSecret).update(rawBody).digest('hex');
  return A.safeEqual(expected, signature);
}

module.exports = { config, createOrder, verifyPaymentSignature, verifyWebhookSignature };
