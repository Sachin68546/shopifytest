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

// In‐memory storage for access tokens (by shop) and OAuth states (by random state)
const tokens = new Map();
const stateMap = new Map();

/**
 * STEP 1: WEBHOOK MIDDLEWARE
 *
 * We mount a raw‐body parser on "/webhooks". This catches ANY request whose path begins
 * with "/webhooks" (for example "/webhooks/shop/redact", "/webhooks/orders/create", etc.).
 *
 * Then we immediately verify:
 *  • METHOD must be POST, otherwise 401
 *  • HMAC header must match the raw body, otherwise 401
 *
 * If both pass, we call next() so the specific POST handler (below) can run.
 */
app.use(
  '/webhooks',
  bodyParser.raw({
    type: '*/*', // interpret entire payload as raw Buffer
  })
);

app.use('/webhooks', (req, res, next) => {
  // 1) Only POST is valid for Shopify webhooks
  if (req.method !== 'POST') {
    return res.status(401).send('Unauthorized');
  }

  // 2) Verify the HMAC from Shopify
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
    // timingSafeEqual can throw if lengths differ
    return res.status(401).send('Unauthorized');
  }

  // HMAC is valid → proceed to the matching POST handler
  next();
});

/**
 * STEP 2: PARSE JSON FOR THE REST OF THE APP
 */
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * STEP 3: OAUTH CALLBACK HMAC VERIFIER
 *
 * Shopify sends an HMAC in the query when redirecting back to /auth/callback.
 * We need to verify that HMAC using the same procedure:
 *  • Sort all query params except hmac & signature
 *  • Recreate the string "key1=value1&key2=value2…"
 *  • Compute our own HMAC via SHA256(API_SECRET, thatString)
 *  • Compare to the provided hmac (hex)
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
 * STEP 4: ROOT ROUTE – INSTALL INITIATION
 *
 * When Shopify’s review bot “clicks Install,” it will call:
 *   GET /?shop=<my-shop>&timestamp=…&hmac=…
 * 
 * We must:
 *  1) Reconstruct HMAC over { shop, timestamp } (excluding hmac itself).
 *  2) If valid, redirect (302) to /connect?shop=<my-shop>.
 *  3) If invalid, throw 400.
 *
 * If a developer (or merchant) simply browses to “/” without those query params,
 * we show a simple HTML form letting them type in a shop, then submit to /connect.
 */
app.get('/', (req, res) => {
  const { shop, hmac, timestamp } = req.query;

  // Shopify “install” call
  if (shop && hmac && timestamp) {
    // Recreate the message string from query minus “hmac”
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
        // Valid HMAC → immediately redirect into /connect
        return res.redirect(`/connect?shop=${encodeURIComponent(shop)}`);
      } else {
        return res.status(400).send('❌ Invalid HMAC on install request');
      }
    } catch {
      return res.status(400).send('❌ Invalid HMAC on install request');
    }
  }

  // No shop/hmac/timestamp → show a manual “Enter your-shop.myshopify.com” form
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
 * STEP 5: CONNECT ROUTE – REDIRECT TO SHOPIFY’S OAUTH SCREEN
 *
 * Expects: GET /connect?shop=<store>.myshopify.com
 * We:
 *  1) Generate a random state (UUID), store it in stateMap.set(state, shop)
 *  2) Build the authorize URL:
 *     https://<shop>/admin/oauth/authorize?client_id=...&scope=...&redirect_uri=...&state=...&grant_options[]=offline
 *  3) Redirect (302) to that URL
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
 * STEP 6: OAUTH CALLBACK
 *
 * Shopify will redirect here after the merchant approves:
 *   GET /auth/callback?code=...&shop=...&state=...&hmac=...&host=...
 *
 * We must:
 *  1) Verify that “state” matches what we stored for this shop
 *  2) Verify the HMAC on the callback query itself
 *  3) Exchange the “code” for an access token via POST to /admin/oauth/access_token
 *  4) Save token in memory (tokens.set(shop, token))
 *  5) Register GDPR webhooks (customers/data_request, customers/redact, shop/redact)
 *  6) Redirect merchant back into Shopify Admin’s embedded-app URL if “host” is valid
 *     OR, if “host” is missing/invalid (e.g. during automated check), send them to
 *     our own UI at `${HOST}${APP_UI_PATH}?shop=...`
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

    // Exchange `code` for access token
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

    // If host is valid, redirect into embedded-app Admin
    if (typeof host === 'string' && host.includes('admin.shopify.com')) {
      const redirectUrl = `https://${host}/apps/${API_KEY}?shop=${encodeURIComponent(
        shop
      )}&host=${encodeURIComponent(host)}`;
      return res.redirect(redirectUrl);
    }

    // Otherwise, send them to our own hosted UI
    return res.redirect(`${HOST}${APP_UI_PATH}?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.response?.data || err.message);
    return res.status(500).send('Authentication failed');
  }
});

/**
 * STEP 7: APP UI
 *
 * If a merchant arrives here (e.g. not embedded), they see a minimal dashboard.
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
 * Because we’ve already run the HMAC check (and method check) in the
 * `app.use('/webhooks', …)` middleware, these handlers only execute when HMAC is valid.
 */

// Order creation webhook
app.post('/webhooks/orders/create', (req, res) => {
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('📦 Order Created:', payload);
  return res.status(200).send('OK');
});

// GDPR Customer data request
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
 *
 * We subscribe to three topics: CUSTOMERS_DATA_REQUEST, CUSTOMERS_REDACT, SHOP_REDACT
 * by calling /admin/api/<API_VERSION>/graphql.json with a mutation.
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
 * STEP 10: RETRIEVE STORED ACCESS TOKEN FOR A SHOP
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

// Finally, start the server
app.listen(PORT, () => {
  console.log(`🚀 Shopify app running on ${HOST} (port ${PORT})`);
});
