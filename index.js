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

// In-memory map to store access tokens per shop
const tokens = new Map();

// In-memory map to store OAuth state per shop during installation
const stateMap = new Map();

/**
 * Verify the HMAC for incoming webhook payloads.
 * If invalid, send a 401 and return false. Otherwise return true.
 */
function verifyWebhook(req, res) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256') || '';
  const generatedDigest = crypto
    .createHmac('sha256', API_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');

  if (
    !crypto.timingSafeEqual(
      Buffer.from(generatedDigest, 'base64'),
      Buffer.from(hmacHeader, 'base64')
    )
  ) {
    console.warn('❌ Invalid HMAC signature (webhook)');
    res.status(401).send('Unauthorized');
    return false;
  }
  return true;
}

/**
 * Verify the HMAC for OAuth callback query parameters.
 * Shopify sends `hmac` in query; we recreate the message string
 * by sorting all params except `hmac` or `signature`.
 * This returns true if valid, false otherwise.
 */
function verifyOAuthCallback(req) {
  const providedHmac = req.query.hmac;
  if (typeof providedHmac !== 'string') {
    return false;
  }

  // Exclude 'hmac' and 'signature' from the message
  const { hmac, signature, ...allParams } = req.query;
  const sortedMessage = Object.keys(allParams)
    .sort()
    .map((key) => `${key}=${allParams[key]}`)
    .join('&');

  const generatedHmac = crypto
    .createHmac('sha256', API_SECRET)
    .update(sortedMessage)
    .digest('hex');

  // Compare the raw bytes of the two hex-encoded digests
  try {
    return crypto.timingSafeEqual(
      Buffer.from(generatedHmac, 'hex'),
      Buffer.from(providedHmac, 'hex')
    );
  } catch {
    // timingSafeEqual throws if buffer lengths differ
    return false;
  }
}

// Parse raw body for webhooks, and JSON for everything else
app.use('/webhooks', bodyParser.raw({ type: '*/*' }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Root route. Handles both:
 *  - Initial Shopify install redirect (when shop, hmac, timestamp are present)
 *  - Manual visits (renders a simple HTML form)
 */
app.get('/', (req, res) => {
  const { shop, hmac, timestamp } = req.query;

  // If Shopify is calling to install the app, it will include shop, hmac, timestamp
  if (shop && hmac && timestamp) {
    // Recreate the query string without 'hmac'
    const map = { ...req.query };
    delete map.hmac;
    const message = querystring.stringify(map);

    const generatedDigest = crypto
      .createHmac('sha256', API_SECRET)
      .update(message)
      .digest('hex');

    // Compare Shopify's hmac to our generated digest (hex)
    if (
      crypto.timingSafeEqual(
        Buffer.from(generatedDigest, 'hex'),
        Buffer.from(hmac, 'hex')
      )
    ) {
      // Valid HMAC: immediately redirect into /connect to start OAuth
      return res.redirect(`/connect?shop=${encodeURIComponent(shop)}`);
    } else {
      return res.status(400).send('❌ Invalid HMAC on install request');
    }
  }

  // Otherwise, render the landing page with manual shop input
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
 * /connect route: generates a random `state`, stores it,
 * and redirects merchant to Shopify's OAuth grant screen.
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
 * OAuth callback. Shopify redirects here after merchant approves.
 * We verify `state`, re-verify HMAC on the callback, exchange the code
 * for an access token, register webhooks, then redirect back into the Shopify Admin.
 */
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, shop, state, host, hmac } = req.query;
    if (!code || !shop || !state || !host || !hmac) {
      return res.status(400).send('❌ Missing required OAuth query parameters');
    }

    // 1) Verify `state` matches what we generated
    const storedShop = stateMap.get(state);
    if (storedShop !== shop) {
      return res.status(400).send('❌ State mismatch');
    }
    stateMap.delete(state);

    // 2) Verify HMAC on the callback query (Shopify sends `hmac` here)
    if (!verifyOAuthCallback(req)) {
      return res.status(400).send('❌ Invalid HMAC on OAuth callback');
    }

    // 3) Exchange `code` for an access token
    const tokenResponse = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code,
    });
    const token = tokenResponse.data.access_token;
    tokens.set(shop, token);
    console.log(`✅ Token stored for ${shop}`);

    // 4) Register required GDPR webhooks now that we have the token
    await registerPrivacyWebhooks(shop, token);

    // 5) Redirect back into Shopify Admin (embedded app launch)
    //    `host` is a Base64-encoded string provided by Shopify
    const redirectUrl = `https://${host}/apps/${API_KEY}?shop=${encodeURIComponent(
      shop
    )}&host=${encodeURIComponent(host)}`;

    return res.redirect(redirectUrl);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.response?.data || err.message);
    return res.status(500).send('Authentication failed');
  }
});

/**
 * App UI – if a merchant visits directly (not embedded),
 * they see a simple dashboard. In a real embedded app, you'd
 * likely serve a React/JS frontend here.
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
 * Webhook endpoints.
 * We place these routes before any potential redirect/HTTPS-forcing middleware
 * so that Shopify’s POST never sees a 307 redirect.
 */

// Order creation webhook
app.post('/webhooks/orders/create', (req, res) => {
  if (!verifyWebhook(req, res)) return; // sends 401 if HMAC invalid
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('📦 Order Created:', payload);
  res.status(200).send('OK');
});

// GDPR Customer data request
app.post('/webhooks/customers/data_request', (req, res) => {
  if (!verifyWebhook(req, res)) return;
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🔐 customers/data_request:', payload);
  res.status(200).send('OK');
});

// GDPR Customer redact
app.post('/webhooks/customers/redact', (req, res) => {
  if (!verifyWebhook(req, res)) return;
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🧹 customers/redact:', payload);
  res.status(200).send('OK');
});

// GDPR Shop redact
app.post('/webhooks/shop/redact', (req, res) => {
  if (!verifyWebhook(req, res)) return;
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🏪 shop/redact:', payload);
  res.status(200).send('OK');
});

/**
 * Helper to register required GDPR webhooks using GraphQL API.
 * We inject each `topic` directly into the GraphQL mutation.
 */
async function registerPrivacyWebhooks(shop, accessToken) {
  const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

  const topics = [
    { topic: 'CUSTOMERS_DATA_REQUEST', path: '/webhooks/customers/data_request' },
    { topic: 'CUSTOMERS_REDACT', path: '/webhooks/customers/redact' },
    { topic: 'SHOP_REDACT', path: '/webhooks/shop/redact' },
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
 * Helper to retrieve stored access token for a given shop.
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
    res.json(orders);
  } catch (err) {
    console.error('❌ GraphQL Orders error:', err.response?.data || err.message);
    res.status(500).send('Error fetching orders');
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
    res.json(products);
  } catch (err) {
    console.error('❌ GraphQL Products error:', err.response?.data || err.message);
    res.status(500).send('Error fetching products');
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
    res.json(customers);
  } catch (err) {
    console.error('❌ GraphQL Customers error:', err.response?.data || err.message);
    res.status(500).send('Error fetching customers');
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Shopify app running on ${HOST} (port ${PORT})`);
});
