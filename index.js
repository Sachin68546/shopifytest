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

// In-memory stores
const tokens = new Map();         // shop -> access token
const stateMap = new Map();       // state -> shop

// 1) Guard middleware: ensure OAuth completed before showing any UI or API routes
app.use((req, res, next) => {
  const publicPaths = ['/', '/connect', '/auth/callback', '/webhooks'];
  if (publicPaths.some(p => req.path.startsWith(p))) {
    return next();
  }
  const shop = req.query.shop;
  const token = shop && tokens.get(shop);
  if (!shop || !token) {
    return res.redirect(`/connect?shop=${encodeURIComponent(shop || '')}`);
  }
  next();
});

// 2) Raw body parser + HMAC check for webhooks
app.use('/webhooks', bodyParser.raw({ type: '*/*' }));
app.use('/webhooks', (req, res, next) => {
  if (req.method !== 'POST') return res.status(401).send('Unauthorized');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || '';
  const digest = crypto.createHmac('sha256', API_SECRET).update(req.body, 'utf8').digest('base64');
  if (!crypto.timingSafeEqual(Buffer.from(digest, 'base64'), Buffer.from(hmac, 'base64'))) {
    return res.status(401).send('Unauthorized');
  }
  next();
});

// 3) JSON parser
app.use(bodyParser.json());

// 4) Static assets & view engine (served only after OAuth guard)
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Helper: verify OAuth callback HMAC
function verifyOAuthCallback(req) {
  const providedHmac = req.query.hmac;
  if (typeof providedHmac !== 'string') return false;
  const { hmac, signature, ...rest } = req.query;
  const message = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('&');
  const generated = crypto.createHmac('sha256', API_SECRET).update(message).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(generated, 'hex'), Buffer.from(providedHmac, 'hex'));
}

// Root: install entrypoint
app.get('/', (req, res) => {
  const { shop, hmac, timestamp, host } = req.query;
  if (shop && hmac && timestamp) {
    // validate install HMAC
    const params = { shop, timestamp };
    const message = querystring.stringify(params);
    const digest = crypto.createHmac('sha256', API_SECRET).update(message).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(hmac, 'hex'))) {
      return res.status(400).send('❌ Invalid HMAC on install request');
    }
    // For embedded app installs, redirect into Shopify admin grant
    if (host && typeof host === 'string') {
      const decodedHost = Buffer.from(host, 'base64').toString('utf8');
      return res.redirect(`https://${decodedHost}/app/grant`);
    }
    // Otherwise start OAuth flow
    return res.redirect(`/connect?shop=${encodeURIComponent(shop)}`);
  }
  // fallback landing page
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// OAuth start
app.get('/connect', (req, res) => {
  const { shop } = req.query;
  if (!shop || typeof shop !== 'string') {
    return res.status(400).send('❌ Missing "shop" query parameter');
  }
  const state = uuidv4();
  stateMap.set(state, shop);

  const installUrl = `https://${shop}/admin/oauth/authorize` +
    `?client_id=${API_KEY}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(`${HOST}/auth/callback`)}` +
    `&state=${state}` +
    `&grant_options[]=offline`;

  res.redirect(installUrl);
});

// OAuth callback
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, shop, state, host, hmac } = req.query;
    if (!code || !shop || !state || !hmac) {
      return res.status(400).send('❌ Missing required OAuth query parameters');
    }
    if (stateMap.get(state) !== shop) {
      return res.status(400).send('❌ State mismatch');
    }
    stateMap.delete(state);
    if (!verifyOAuthCallback(req)) {
      return res.status(400).send('❌ Invalid HMAC on OAuth callback');
    }

    // Exchange code for token
    const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code,
    });
    const accessToken = tokenRes.data.access_token;
    tokens.set(shop, accessToken);

    // Register GDPR webhooks
    await registerPrivacyWebhooks(shop, accessToken);

    // Redirect into Admin if embedded
    if (host) {
      return res.redirect(
        `https://${shop}/admin/apps/${API_KEY}?host=${encodeURIComponent(host)}`
      );
    }

    // Otherwise to your own UI
    res.redirect(`${HOST}${APP_UI_PATH}?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.response?.data || err.message);
    res.status(500).send('Authentication failed');
  }
});

// Dashboard (only after OAuth guard)
app.get('/app', (req, res) => {
  const { shop } = req.query;
  res.render('app', { shop });
});

// Webhook handlers
app.post('/webhooks/orders/create', (req, res) => {
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('📦 Order Created:', payload);
  res.status(200).send('OK');
});
app.post('/webhooks/customers/data_request', (req, res) => {
  console.log('🔐 customers/data_request:', JSON.parse(req.body.toString()));
  res.status(200).send('OK');
});
app.post('/webhooks/customers/redact', (req, res) => {
  console.log('🧹 customers/redact:', JSON.parse(req.body.toString()));
  res.status(200).send('OK');
});
app.post('/webhooks/shop/redact', (req, res) => {
  console.log('🏪 shop/redact:', JSON.parse(req.body.toString()));
  res.status(200).send('OK');
});

// Register GDPR webhooks via GraphQL
async function registerPrivacyWebhooks(shop, accessToken) {
  const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
  const topics = [
    { topic: 'CUSTOMERS_DATA_REQUEST', path: '/webhooks/customers/data_request' },
    { topic: 'CUSTOMERS_REDACT',      path: '/webhooks/customers/redact' },
    { topic: 'SHOP_REDACT',           path: '/webhooks/shop/redact' },
  ];

  for (const { topic, path: cbPath } of topics) {
    const mutation = `
      mutation {
        webhookSubscriptionCreate(
          topic: ${topic}
          webhookSubscription: {
            callbackUrl: "${HOST}${cbPath}",
            format: JSON
          }
        ) {
          webhookSubscription { id }
          userErrors { field message }
        }
      }
    `;
    try {
      const resp = await axios.post(url, { query: mutation }, {
        headers: {
          'X-Shopify-Access-Token': accessToken,
          'Content-Type': 'application/json',
        },
      });
      const errs = resp.data?.data?.webhookSubscriptionCreate?.userErrors;
      if (errs?.length) console.error(`❌ ${topic} errors:`, errs);
      else console.log(`✅ Registered webhook: ${topic}`);
    } catch (e) {
      console.error(`❌ Webhook registration failed for ${topic}:`, e.response?.data || e.message);
    }
  }
}

// Helper to get token
function getToken(shop) {
  const token = tokens.get(shop);
  if (!token) throw new Error('Missing token for shop');
  return token;
}

// Example GraphQL endpoints (after OAuth guard)
app.get('/orders', async (req, res) => {
  try {
    const { shop } = req.query;
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const query = `...`;
    const { data } = await axios.post(url, { query }, {
      headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
    });
    res.json(data.data.orders.edges.map(e => e.node));
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching orders');
  }
});


app.get('/products', async (req, res) => {
  try {
    const { shop } = req.query;
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const query = `
      {
        products(first: 50) {
          edges {
            node {
              id
              title
              totalInventory
            }
          }
        }
      }
    `;
    const { data } = await axios.post(url, { query }, {
      headers: {
        'X-Shopify-Access-Token': token,
        'Content-Type': 'application/json',
      },
    });
    res.json(data.data.products.edges.map(e => e.node));
  } catch (err) {
    console.error('❌ /products error:', err.response?.data || err.message);
    res.status(500).send('Error fetching products');
  }
});

app.get('/customers', async (req, res) => {
  try {
    const { shop } = req.query;
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const query = `
      {
        customers(first: 50) {
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
    const { data } = await axios.post(url, { query }, {
      headers: {
        'X-Shopify-Access-Token': token,
        'Content-Type': 'application/json',
      },
    });
    res.json(data.data.customers.edges.map(e => e.node));
  } catch (err) {
    console.error('❌ /customers error:', err.response?.data || err.message);
    res.status(500).send('Error fetching customers');
  }
});
// Catch-all redirect to root
app.use((req, res) => res.redirect('/'));

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Shopify app running on ${HOST}:${PORT}`);
});
