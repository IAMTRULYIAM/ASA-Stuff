# RP Calendar - Cloudflare Pages Deployment

## Repository Structure

```
your-repo/
├── index.html          ← the calendar widget
├── functions/
│   └── state.js        ← serverless endpoint for GM state persistence
└── README.md
```

---

## One-Time Setup (approx. 10 minutes)

### 1. Push to GitHub
Create a new GitHub repository and push these files to it.

### 2. Create a Cloudflare Pages project
1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Go to **Workers & Pages** → **Pages** → **Create a project**
3. Click **Connect to Git** and authorise Cloudflare to access your GitHub account
4. Select your repository
5. Under **Build settings**:
   - Framework preset: **None**
   - Build command: *(leave blank)*
   - Build output directory: `/` or leave blank
6. Click **Save and Deploy**

Your site will be live at `https://your-project.pages.dev` within a minute.

### 3. Create a KV namespace
The calendar stores the current RP date in Cloudflare KV (key-value storage).

1. In Cloudflare Dashboard, go to **Workers & Pages** → **KV**
2. Click **Create a namespace**
3. Name it anything, e.g. `rp-calendar-state`
4. Click **Add**

### 4. Bind KV to your Pages project
1. Go to **Workers & Pages** → your Pages project → **Settings** → **Functions**
2. Scroll to **KV namespace bindings**
3. Click **Add binding**
   - Variable name: `RP_STATE` *(must match exactly)*
   - KV namespace: select `rp-calendar-state`
4. Click **Save**
5. Trigger a new deployment: **Deployments** → **Retry deployment** (or push any commit)

---

## How it works after setup

| Who | Action | Result |
|-----|--------|--------|
| GM | Opens site, enters access code, sets date, clicks **Publish and Save** | Date written to KV via `/state` |
| Players | Open the site URL | Widget fetches `/state` from KV, auto-advances to correct live date |
| Players (offline) | If KV unreachable | Falls back to URL hash in the shared link |

The RP date auto-advances in real time based on the speed setting chosen when the GM last published. No one needs to manually update it day-to-day.

---

## Custom Domain (optional)
In your Pages project → **Custom domains** → add your domain and follow the DNS instructions.

---

## Updating the widget
Push any change to your GitHub repository. Cloudflare Pages redeploys automatically within ~30 seconds.
