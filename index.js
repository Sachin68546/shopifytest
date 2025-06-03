import express from 'express';
import axios from 'axios';
import dotenv from 'dotenv';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const {
  SHOPIFY_API_KEY: API_KEY,
  SHOPIFY_API_SECRET: API_SECRET,
  SHOPIFY_STORE: STORE,
  SHOPIFY_SCOPES: SCOPES,
  SHOPIFY_API_VERSION: API_VERSION = '2025-04',
  HOST,
  PORT = 3000,
  APP_UI_PATH = '/app',
} = process.env;

if (!API_KEY || !API_SECRET || !STORE || !SCOPES || !HOST) {
  console.error('❌ Missing environment variables');
  process.exit(1);
}

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const tokens = new Map();

app.use('/webhooks', bodyParser.raw({ type: '*/*' }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Install Route
app.get('/', (req, res) => {
  const installUrl = `https://${STORE}/admin/oauth/authorize` +
    `?client_id=${API_KEY}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(`${HOST}/auth/callback`)}` +
    `&grant_options[]=offline`;

  res.redirect(installUrl);
});

// OAuth Callback
app.get('/auth/callback', async (req, res) => {
  const { code, shop } = req.query;
  if (!code || !shop) return res.status(400).send('Missing code or shop');

  try {
    const resp = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code,
    });

    const token = resp.data.access_token;
    tokens.set(shop, token);
    console.log(`✅ Token stored for ${shop}`);

    // Register mandatory privacy webhooks
    await registerPrivacyWebhooks(shop, token);

    res.redirect(`${APP_UI_PATH}?shop=${shop}`);
  } catch (err) {
    console.error('❌ OAuth error:', err.response?.data || err.message);
    res.status(500).send('Authentication failed');
  }
});

// App UI
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

// Webhook Verification Helper
function verifyWebhook(req, res) {
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const digest = crypto
    .createHmac('sha256', API_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');

  if (hmac !== digest) {
    console.warn('❌ Invalid HMAC signature');
    res.status(401).send('Unauthorized');
    return false;
  }
  return true;
}

// Orders Create Webhook
app.post('/webhooks/orders/create', (req, res) => {
  if (!verifyWebhook(req, res)) return;
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('📦 Order Created:', payload);
  res.status(200).send('OK');
});

// Privacy Webhooks
app.post('/webhooks/customers/data_request', (req, res) => {
  if (!verifyWebhook(req, res)) return;
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🔐 customers/data_request:', payload);
  res.status(200).send('OK');
});

app.post('/webhooks/customers/redact', (req, res) => {
  if (!verifyWebhook(req, res)) return;
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🧹 customers/redact:', payload);
  res.status(200).send('OK');
});

app.post('/webhooks/shop/redact', (req, res) => {
  if (!verifyWebhook(req, res)) return;
  const payload = JSON.parse(req.body.toString('utf8'));
  console.log('🏪 shop/redact:', payload);
  res.status(200).send('OK');
});

// Register Webhooks
async function registerPrivacyWebhooks(shop, accessToken) {
  const baseUrl = `https://${shop}/admin/api/${API_VERSION}/webhooks.json`;
  const topics = [
    { topic: 'customers/data_request', path: '/webhooks/customers/data_request' },
    { topic: 'customers/redact', path: '/webhooks/customers/redact' },
    { topic: 'shop/redact', path: '/webhooks/shop/redact' },
  ];

  for (const { topic, path } of topics) {
    try {
      await axios.post(baseUrl, {
        webhook: {
          topic,
          address: `${HOST}${path}`,
          format: 'json',
        },
      }, {
        headers: { 'X-Shopify-Access-Token': accessToken },
      });
      console.log(`✅ Registered webhook: ${topic}`);
    } catch (err) {
      console.error(`❌ Failed to register ${topic}:`, err.response?.data || err.message);
    }
  }
}

// Helper to get access token
function getToken(shop) {
  const token = tokens.get(shop);
  if (!token) throw new Error('Missing token for shop');
  return token;
}

// Orders Endpoint
app.get('/orders', async (req, res) => {
  try {
    const { shop } = req.query;
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/orders.json?limit=10`;
    const { data } = await axios.get(url, {
      headers: { 'X-Shopify-Access-Token': token },
    });
    res.json(data.orders);
  } catch (err) {
    console.error('❌ Orders error:', err.response?.data || err.message);
    res.status(500).send('Error fetching orders');
  }
});

// Products Endpoint
app.get('/products', async (req, res) => {
  try {
    const { shop } = req.query;
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

    const { data } = await axios.post(url, { query }, {
      headers: {
        'X-Shopify-Access-Token': token,
        'Content-Type': 'application/json'
      }
    });

    const products = data.data.products.edges.map(edge => edge.node);
    res.json(products);
  } catch (err) {
    console.error('❌ GraphQL Products error:', err.response?.data || err.message);
    res.status(500).send('Error fetching products (GraphQL)');
  }
});


// Customers Endpoint
app.get('/customers', async (req, res) => {
  try {
    const { shop } = req.query;
    const token = getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/customers.json?limit=10`;
    const { data } = await axios.get(url, {
      headers: { 'X-Shopify-Access-Token': token },
    });
    res.json(data.customers);
  } catch (err) {
    console.error('❌ Customers error:', err.response?.data || err.message);
    res.status(500).send('Error fetching customers');
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Shopify app running on ${HOST} (port ${PORT})`);
});
