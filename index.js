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


// EJS setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const tokens = new Map();
const stateMap = new Map();

// Raw body parser for webhooks
app.use('/webhooks', bodyParser.raw({ type: '*/*' }));

// HMAC verification for webhooks
app.use('/webhooks', (req, res, next) => {
  if (req.method !== 'POST') return res.status(401).send('Unauthorized');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || '';
  const digest = crypto.createHmac('sha256', API_SECRET).update(req.body, 'utf8').digest('base64');
  if (!crypto.timingSafeEqual(Buffer.from(digest, 'base64'), Buffer.from(hmac, 'base64'))) {
    console.warn('❌ Invalid HMAC signature (webhook)');
    return res.status(401).send('Unauthorized');
  }
  next();
});

app.use(bodyParser.json());

function verifyOAuthCallback(req) {
  const providedHmac = req.query.hmac;
  if (typeof providedHmac !== 'string') return false;
  const { hmac, signature, ...rest } = req.query;
  const sorted = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('&');
  const generated = crypto.createHmac('sha256', API_SECRET).update(sorted).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(generated, 'hex'), Buffer.from(providedHmac, 'hex'));
}

app.get('/', (req, res) => {
  const { shop } = req.query;

  if (!shop) {
    return res.send(`
      <html>
        <head><title>profit first</title></head>
        <body>
          <h2>Welcome to Profit First App</h2>
        </body>
      </html>
    `);
  }
  // Redirect if shop is present (from App Store installation link)
  return res.redirect(`/connect?shop=${encodeURIComponent(shop)}`);
});


// OAuth start
app.get('/connect', (req, res) => {
  const { shop } = req.query;
  if (!shop || typeof shop !== 'string') return res.status(400).send('❌ Missing "shop" query parameter');
  const state = uuidv4();
  stateMap.set(state, shop);

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
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

    const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code,
    });
    tokens.set(shop, tokenRes.data.access_token);
    console.log(`✅ Token stored for ${shop}`);

    // Register privacy webhooks
    await registerPrivacyWebhooks(shop, tokenRes.data.access_token);

    // Redirect back into Shopify admin if embedded
    if (host && host.includes('admin.shopify.com')) {
      const redirectUrl = `https://${host}/apps/${API_KEY}?shop=${encodeURIComponent(shop)}&host=${encodeURIComponent(host)}`;
      return res.redirect(redirectUrl);
    }
    // Otherwise to your own UI
    res.redirect(`${HOST}${APP_UI_PATH}?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.response?.data || err.message);
    res.status(500).send('Authentication failed');
  }
});

// Dashboard
app.get('/app', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('❌ Missing "shop" parameter');
  res.render('app', { shop });
});

// Webhook handlers (examples)
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

// Register GDPR webhooks
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
          webhookSubscription { id }
          userErrors { field message }
        }
      }
    `;
    try {
      const response = await axios.post(url, { query: mutation }, {
        headers: {
          'X-Shopify-Access-Token': accessToken,
          'Content-Type': 'application/json',
        },
      });
      const errors = response.data?.data?.webhookSubscriptionCreate?.userErrors;
      if (errors?.length) console.error(`❌ ${topic} errors:`, errors);
      else console.log(`✅ Registered webhook: ${topic}`);
    } catch (err) {
      console.error(`❌ Webhook registration failed for ${topic}:`, err.response?.data || err.message);
    }
  }
}

function getToken(shop) {
  const token = tokens.get(shop);
  if (!token) {
    console.warn(`⚠️ No token found for ${shop}`);
    throw new Error('Missing token for shop');
  }
  return token;
}


// GraphQL endpoints
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

    const { data } = await axios.post(url, { query }, {
      headers: {
        'X-Shopify-Access-Token': token,
        'Content-Type': 'application/json',
      },
    });

    // Shopify might return errors in the response body
    if (data.errors) {
      console.error('GraphQL Errors:', data.errors);
      return res.status(500).send('GraphQL query error');
    }

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
app.use((req, res) => {
  res.redirect('/');
});


// Serve static files from `public/`
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`🚀 Shopify app running on ${HOST}:${PORT}`);
});
