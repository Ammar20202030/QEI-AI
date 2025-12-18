# QEI Public Assistant Gateway — Production-Min (Cloudflare)

## 0) Requirements
- Node.js
- Wrangler installed (`npm i -g wrangler`)
- Cloudflare account

## 1) Create Vectorize index (768 dims for bge-base)
npx wrangler vectorize create qei-public-kb --dimensions=768 --metric=cosine

## 2) Create R2 bucket
npx wrangler r2 bucket create qei-public-docs

## 3) Login
wrangler login

## 4) Set secrets (DO NOT put in files)
wrangler secret put ADMIN_INGEST_TOKEN

## 5) Deploy
wrangler deploy

## 6) Ingest public docs (protected)
curl -X POST "https://YOUR-WORKER.workers.dev/admin/ingest" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_INGEST_TOKEN" \
  -d '{
    "docs": [
      { "id": "faq", "title": "QEI FAQ", "text": "PASTE FAQ HERE" },
      { "id": "kb",  "title": "QEI Public KB", "text": "PASTE KB HERE" }
    ]
  }'

## 7) Frontend
In app.js set:
GATEWAY_URL = "https://YOUR-WORKER.workers.dev/chat"
