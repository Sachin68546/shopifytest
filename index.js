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

// In-memory token storage
const tokens = new Map();
const stateMap = new Map();

// Middleware
app.use((req, res, next) => {
  const publicPaths = ['/', '/connect', '/auth/callback', '/webhooks'];
  if (publicPaths.some(p => req.path.startsWith(p))) return next();

  const shop = req.query.shop;
  const token = shop && tokens.get(shop);
  if (!shop || !token) {
    return res.redirect(`/connect?shop=${encodeURIComponent(shop || '')}`);
  }
  next();
});

app.use('/webhooks', bodyParser.raw({ type: '*/*' }));
app.use('/webhooks', (req, res, next) => {
  const hmac = req.get('X-Shopify-Hmac-Sha256') || '';
  const digest = crypto.createHmac('sha256', API_SECRET).update(req.body, 'utf8').digest('base64');
  if (!crypto.timingSafeEqual(Buffer.from(digest, 'base64'), Buffer.from(hmac, 'base64'))) {
    return res.status(401).send('Unauthorized');
  }
  next();
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// HMAC verifier
function verifyOAuthCallback(req) {
  const providedHmac = req.query.hmac;
  if (typeof providedHmac !== 'string') return false;
  const { hmac, signature, ...rest } = req.query;
  const message = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('&');
  const generated = crypto.createHmac('sha256', API_SECRET).update(message).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(generated, 'hex'), Buffer.from(providedHmac, 'hex'));
}

// Root route for installation
app.get('/', (req, res) => {
  const { shop, hmac, timestamp } = req.query;

  if (shop && hmac && timestamp) {
    const params = { shop, timestamp };
    const message = querystring.stringify(params);
    const digest = crypto.createHmac('sha256', API_SECRET).update(message).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(hmac, 'hex'))) {
      return res.status(400).send('❌ Invalid HMAC on install request');
    }

    // Redirect to embedded app admin
    return res.redirect(`https://admin.shopify.com/store/${shop.replace('.myshopify.com', '')}/app/grant`);
  }

  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start OAuth flow
app.get('/connect', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('❌ Missing shop');

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
    if (!code || !shop || !state || !hmac) return res.status(400).send('❌ Missing OAuth parameters');
    if (stateMap.get(state) !== shop) return res.status(400).send('❌ State mismatch');
    stateMap.delete(state);

    if (!verifyOAuthCallback(req)) return res.status(400).send('❌ Invalid HMAC');

    const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code,
    });
    const accessToken = tokenRes.data.access_token;
    tokens.set(shop, accessToken);

    await registerPrivacyWebhooks(shop, accessToken);

    if (host) {
      return res.redirect(`https://${shop}/admin/apps/${API_KEY}?host=${encodeURIComponent(host)}`);
    }

    res.redirect(`${HOST}${APP_UI_PATH}?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.response?.data || err.message);
    res.status(500).send('Authentication failed');
  }
});

// Dashboard route
app.get('/app', (req, res) => {
  const { shop } = req.query;
  res.render('app', { shop });
});

// GDPR Webhook registration
async function registerPrivacyWebhooks(shop, accessToken) {
  const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
  const topics = [
    { topic: 'CUSTOMERS_DATA_REQUEST', path: '/webhooks/customers/data_request' },
    { topic: 'CUSTOMERS_REDACT', path: '/webhooks/customers/redact' },
    { topic: 'SHOP_REDACT', path: '/webhooks/shop/redact' },
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
      console.error(`❌ Failed to register ${topic}:`, e.response?.data || e.message);
    }
  }
}

// Helper
function getToken(shop) {
  const token = tokens.get(shop);
  if (!token) throw new Error('Missing token for shop');
  return token;
}

app.get('/orders', async (req, res) => {
  try {
    const { shop } = req.query;
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const query = `
      {
        orders(first: 50) {
          edges {
            node {
              id
              name
              createdAt
              totalPriceSet { shopMoney { amount currencyCode } }
              customer { firstName lastName email }
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
    res.json(data.data.orders.edges.map(e => e.node));
  } catch (err) {
    console.error('❌ /orders error:', err.response?.data || err.message);
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
