// index.js

import express from 'express';
import axios from 'axios';
import dotenv from 'dotenv';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import querystring from 'querystring';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const {
  SHOPIFY_API_KEY: API_KEY,
  SHOPIFY_API_SECRET: API_SECRET,
  SHOPIFY_SCOPES: SCOPES,
  SHOPIFY_API_VERSION: API_VERSION = '2025-04',
  HOST,
  PORT = 3000,
  APP_UI_PATH = '/app',
} = process.env;

if (!API_KEY || !API_SECRET || !SCOPES || !HOST) {
  console.error('❌ Missing environment variables');
  process.exit(1);
}

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-memory maps to store access tokens (by shop) and OAuth states (by state string)
const tokens = new Map();
const stateMap = new Map();

/**
 * STEP 1: WEBHOOK RAW‐BODY + HMAC VALIDATION MIDDLEWARE
 *
 *  • We mount bodyParser.raw(...) on "/webhooks". Any request whose path begins with "/webhooks"
 *    will have its entire request body available as a Buffer in req.body.
 *  • Immediately after, we check:
 *       – Method must be POST; otherwise respond 401
 *       – Compare X-Shopify-Hmac-Sha256 to HMAC(SHOPIFY_API_SECRET, rawBody). If mismatch, respond 401
 *    If either fails, we send 401 and stop. If valid, we call next() so the specific POST handler runs.
 */
app.use(
  '/webhooks',
  bodyParser.raw({
    type: '*/*',
  })
);

app.use('/webhooks', (req, res, next) => {
  // Only POST is valid for Shopify webhooks:
  if (req.method !== 'POST') {
    return res.status(401).send('Unauthorized');
  }

  // Compute our own HMAC on the raw request body
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256') || '';
  const generatedDigest = crypto
    .createHmac('sha256', API_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');

  try {
    if (
      !crypto.timingSafeEqual(
        Buffer.from(generatedDigest, 'base64'),
        Buffer.from(hmacHeader, 'base64')
      )
    ) {
      console.warn('❌ Invalid HMAC signature (webhook)');
      return res.status(401).send('Unauthorized');
    }
  } catch {
    // If lengths differ, timingSafeEqual throws
    return res.status(401).send('Unauthorized');
  }

  // HMAC is valid → proceed to the matching POST handler below
  next();
});

/**
 * STEP 2: JSON PARSER & STATIC FILES FOR THE REMAINDER OF THE APP
 *
 * Non-webhook routes will use JSON body parsing as usual.
 */
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * STEP 3: OAUTH CALLBACK HMAC VERIFICATION
 *
 * When Shopify redirects back to /auth/callback, it includes an HMAC in the query.
 * We must recreate that HMAC from all query params (except “hmac” itself) and compare.
 */
function verifyOAuthCallback(req) {
  const providedHmac = req.query.hmac;
  if (typeof providedHmac !== 'string') {
    return false;
  }

  const { hmac, signature, ...allParams } = req.query;
  const sortedMessage = Object.keys(allParams)
    .sort()
    .map((key) => `${key}=${allParams[key]}`)
    .join('&');

  const generatedHmac = crypto
    .createHmac('sha256', API_SECRET)
    .update(sortedMessage)
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(generatedHmac, 'hex'),
      Buffer.from(providedHmac, 'hex')
    );
  } catch {
    return false;
  }
}

/**
 * STEP 4: ROOT ROUTE “/” – HANDLES SHOPIFY INSTALL VS. MANUAL FORM
 *
 * Shopify’s automated check will call:
 *    GET /?shop=<my-shop>&timestamp=…&hmac=…
 * We must:
 *  1) Recreate HMAC over { shop, timestamp } (omit hmac)
 *  2) If valid, 302 → /connect?shop=<my-shop>
 *  3) If invalid, 400 error
 *
 * If no shop/hmac/timestamp present, we show a simple HTML form
 * for manual “kop” → “connect” flow.
 */
app.get('/', (req, res) => {
  const { shop, hmac, timestamp } = req.query;

  // Shopify “Install” flow
  if (shop && hmac && timestamp) {
    // Recreate query minus hmac
    const map = { ...req.query };
    delete map.hmac;
    const message = querystring.stringify(map);

    const generatedDigest = crypto
      .createHmac('sha256', API_SECRET)
      .update(message)
      .digest('hex');

    try {
      if (
        crypto.timingSafeEqual(
          Buffer.from(generatedDigest, 'hex'),
          Buffer.from(hmac, 'hex')
        )
      ) {
        // Valid HMAC → redirect into /connect
        return res.redirect(`/connect?shop=${encodeURIComponent(shop)}`);
      } else {
        return res.status(400).send('❌ Invalid HMAC on install request');
      }
    } catch {
      return res.status(400).send('❌ Invalid HMAC on install request');
    }
  }

  // Manual landing form
  res.send(`
    <html>
      <head><title>Connect Shopify</title></head>
      <body style="text-align: center; margin-top: 50px;">
        <h1>Welcome to My Shopify App</h1>
        <form action="/connect" method="GET">
          <input
            type="text"
            name="shop"
            placeholder="your-store.myshopify.com"
            required
            style="padding: 8px; width: 300px;"
          />
          <br/><br/>
          <button style="padding: 10px 20px; font-size: 16px;">Connect Shopify</button>
        </form>
      </body>
    </html>
  `);
});

/**
 * STEP 5: /connect → REDIRECT TO SHOPIFY’S OAUTH SCREEN
 *
 * Expects: GET /connect?shop=<store>.myshopify.com
 * We:
 *  1) Generate a random ‘state’ and store `stateMap.set(state, shop)`
 *  2) Redirect to Shopify’s /admin/oauth/authorize with client_id, scope, redirect_uri, state, grant_options[]=offline
 */
app.get('/connect', (req, res) => {
  const { shop } = req.query;
  if (!shop || typeof shop !== 'string') {
    return res.status(400).send('❌ Missing "shop" query parameter');
  }

  const state = uuidv4();
  stateMap.set(state, shop);

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${API_KEY}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(`${HOST}/auth/callback`)}` +
    `&state=${state}` +
    `&grant_options[]=offline`;

  return res.redirect(installUrl);
});

/**
 * STEP 6: OAUTH CALLBACK “/auth/callback”
 *
 * Shopify redirects here after merchant approval:
 *    GET /auth/callback?code=…&shop=…&state=…&hmac=…&host=…
 *
 * We:
 *  1) Verify that stateMap.get(state) === shop
 *  2) Verify the callback’s HMAC
 *  3) Exchange code for access_token via POST to https://<shop>/admin/oauth/access_token
 *  4) Save token in `tokens.set(shop, token)`
 *  5) Register GDPR webhooks for customers/data_request, customers/redact, shop/redact
 *  6) If `host` looks like “admin.shopify.com”, do a 302 → embedded‐app URL:
 *     `https://${host}/apps/${API_KEY}?shop=<…>&host=<…>`
 *  7) Otherwise (e.g. during automated check), 302 → `${HOST}${APP_UI_PATH}?shop=<…>`
 */
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, shop, state, host, hmac } = req.query;
    if (!code || !shop || !state || !hmac) {
      return res.status(400).send('❌ Missing required OAuth query parameters');
    }

    // Verify state
    const storedShop = stateMap.get(state);
    if (storedShop !== shop) {
      return res.status(400).send('❌ State mismatch');
    }
    stateMap.delete(state);

    // Verify HMAC on callback
    if (!verifyOAuthCallback(req)) {
      return res.status(400).send('❌ Invalid HMAC on OAuth callback');
    }

    // Exchange code for access token
    const tokenResponse = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code,
    });
    const token = tokenResponse.data.access_token;
    tokens.set(shop, token);
    console.log(`✅ Token stored for ${shop}`);

    // Register GDPR webhooks now that we have the token
    await registerPrivacyWebhooks(shop, token);

    // If host is valid, embed inside Shopify Admin
    if (typeof host === 'string' && host.includes('admin.shopify.com')) {
      const redirectUrl = `https://${host}/apps/${API_KEY}?shop=${encodeURIComponent(
        shop
      )}&host=${encodeURIComponent(host)}`;
      return res.redirect(redirectUrl);
    }

    // Otherwise, send merchant to our own UI
    return res.redirect(`${HOST}${APP_UI_PATH}?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.response?.data || err.message);
    return res.status(500).send('Authentication failed');
  }
});

/**
 * STEP 7: APP UI “/app”
 *
 * If merchant visits directly, they see a minimal dashboard.
 * (In a real embedded app you’d likely serve a React front-end instead.)
 */
app.get('/app', (req, res) => {
  const { shop } = req.query;
  res.send(`
    <h2>Shopify App Dashboard</h2>
    <p>Connected shop: <strong>${shop}</strong></p>
    <ul>
      <li><a href="/orders?shop=${shop}">View Orders</a></li>
      <li><a href="/products?shop=${shop}">View Products</a></li>
      <li><a href="/customers?shop=${shop}">View Customers</a></li>
    </ul>
  `);
});

/**
 * STEP 8: WEBHOOK HANDLERS
 *
 * By the time any request reaches these POST handlers, we have already
 * validated HMAC (or returned 401). So at this point we simply process.
 */

// Order creation webhook
app.post('/webhooks/orders/create', (req, res) => {
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('📦 Order Created:', payload);
  return res.status(200).send('OK');
});

// GDPR Customer data_request
app.post('/webhooks/customers/data_request', (req, res) => {
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🔐 customers/data_request:', payload);
  return res.status(200).send('OK');
});

// GDPR Customer redact
app.post('/webhooks/customers/redact', (req, res) => {
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🧹 customers/redact:', payload);
  return res.status(200).send('OK');
});

// GDPR Shop redact
app.post('/webhooks/shop/redact', (req, res) => {
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🏪 shop/redact:', payload);
  return res.status(200).send('OK');
});

/**
 * STEP 9: REGISTER GDPR WEBHOOKS VIA GRAPHQL
 */
async function registerPrivacyWebhooks(shop, accessToken) {
  const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

  const topics = [
    { topic: 'CUSTOMERS_DATA_REQUEST', path: '/webhooks/customers/data_request' },
    { topic: 'CUSTOMERS_REDACT',      path: '/webhooks/customers/redact' },
    { topic: 'SHOP_REDACT',           path: '/webhooks/shop/redact' },
  ];

  for (const { topic, path } of topics) {
    const mutation = `
      mutation {
        webhookSubscriptionCreate(
          topic: ${topic}
          webhookSubscription: {
            callbackUrl: "${HOST}${path}",
            format: JSON
          }
        ) {
          webhookSubscription {
            id
          }
          userErrors {
            field
            message
          }
        }
      }
    `;

    try {
      const response = await axios.post(
        url,
        { query: mutation },
        {
          headers: {
            'X-Shopify-Access-Token': accessToken,
            'Content-Type': 'application/json',
          },
        }
      );

      const errors = response.data?.data?.webhookSubscriptionCreate?.userErrors;
      if (errors && errors.length > 0) {
        console.error(`❌ Failed to register ${topic}:`, errors);
      } else {
        console.log(`✅ Registered webhook (GraphQL): ${topic}`);
      }
    } catch (err) {
      console.error(`❌ Webhook registration failed: ${topic}`, err.response?.data || err.message);
    }
  }
}

/**
 * STEP 10: HELPER TO RETRIEVE STORED ACCESS TOKEN FOR A SHOP
 */
function getToken(shop) {
  const token = tokens.get(shop);
  if (!token) throw new Error('Missing token for shop');
  return token;
}

// Orders query (GraphQL)
app.get('/orders', async (req, res) => {
  try {
    const { shop } = req.query;
    if (!shop) throw new Error('Missing shop');
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

    const query = `
      {
        orders(first: 10) {
          edges {
            node {
              id
              name
              createdAt
              totalPriceSet {
                shopMoney {
                  amount
                  currencyCode
                }
              }
              customer {
                firstName
                lastName
                email
              }
            }
          }
        }
      }
    `;

    const { data } = await axios.post(
      url,
      { query },
      {
        headers: {
          'X-Shopify-Access-Token': token,
          'Content-Type': 'application/json',
        },
      }
    );

    const orders = data.data.orders.edges.map((edge) => edge.node);
    return res.json(orders);
  } catch (err) {
    console.error('❌ GraphQL Orders error:', err.response?.data || err.message);
    return res.status(500).send('Error fetching orders');
  }
});

// Products query (GraphQL)
app.get('/products', async (req, res) => {
  try {
    const { shop } = req.query;
    if (!shop) throw new Error('Missing shop');
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

    const query = `
      {
        products(first: 10) {
          edges {
            node {
              id
              title
              status
              createdAt
              updatedAt
              totalInventory
              vendor
              handle
            }
          }
        }
      }
    `;

    const { data } = await axios.post(
      url,
      { query },
      {
        headers: {
          'X-Shopify-Access-Token': token,
          'Content-Type': 'application/json',
        },
      }
    );

    const products = data.data.products.edges.map((edge) => edge.node);
    return res.json(products);
  } catch (err) {
    console.error('❌ GraphQL Products error:', err.response?.data || err.message);
    return res.status(500).send('Error fetching products');
  }
});

// Customers query (GraphQL)
app.get('/customers', async (req, res) => {
  try {
    const { shop } = req.query;
    if (!shop) throw new Error('Missing shop');
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

    const query = `
      {
        customers(first: 10) {
          edges {
            node {
              id
              displayName
              email
              createdAt
              state
            }
          }
        }
      }
    `;

    const { data } = await axios.post(
      url,
      { query },
      {
        headers: {
          'X-Shopify-Access-Token': token,
          'Content-Type': 'application/json',
        },
      }
    );

    const customers = data.data.customers.edges.map((edge) => edge.node);
    return res.json(customers);
  } catch (err) {
    console.error('❌ GraphQL Customers error:', err.response?.data || err.message);
    return res.status(500).send('Error fetching customers');
  }
});

// START THE SERVER
app.listen(PORT, () => {
  console.log(`🚀 Shopify app running on ${HOST} (port ${PORT})`);
});
