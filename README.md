# haoching's site

Hugo + Blowfish blog, deployed as Cloudflare Workers Static Assets.

## Local build

This project pins Hugo Extended `0.164.0` and Blowfish `v2.105.0`.

```bash
npm ci
hugo mod get
bash ./build.sh
```

The generated `public/` and `resources/_gen/` directories are intentionally ignored.

## Publishing workflow

Drafts are written collaboratively in the self-hosted HedgeDoc instance. The HedgeDoc
Publish action is routed to the publisher service, which validates the YAML frontmatter,
copies referenced draft images to R2, rewrites media URLs, and commits the published
Markdown to this repository. It also rejects HedgeDoc-only constructs (for example
`[toc]` and slide directives) with a line number so the GitHub article remains portable.

### About Me page

The fixed `/about/` page uses the same HedgeDoc Publish action. Its note starts with:

```yaml
---
page: about
title: "關於我"
description: "關於 haoching"
---
```

Unlike a post, it does not require a `slug`. Publishing updates only
`content/about/index.md`; pasted images are copied to R2 under `pages/about/`.
The `about` post slug is reserved so it cannot conflict with the fixed page.

## Deployment secrets

The production GitHub Actions environment requires `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID`. The token must be limited to Workers deployment for this
account. The preview environment uses the same account with a separate Worker name.

## Operations

- `ops/hedgedoc/` contains the pinned HedgeDoc/PostgreSQL/publisher/Caddy/Tunnel stack.
- `ops/cloudflare/README.md` covers Worker custom domains, R2 `media.chang929.site`, Tunnel, Access and Rocket Loader settings.
- `ops/proxmox/README.md` covers the VLAN 10 LXC, Docker nesting and backup/restore schedule.
- `ops/github/README.md` covers the least-privilege publisher GitHub App and `v2` → `master` flow.

## Deployed inventory

The v2 implementation was deployed on 2026-08-12:

- Production blog: `https://chang929.site/` (`blog` Worker, `master` branch)
- Preview blog: `https://blog-preview.haoching929.workers.dev/` (`v2` branch)
- Editor: `https://edit.chang929.site/` (Cloudflare Access + HedgeDoc GitHub OAuth)
- Published media: `https://media.chang929.site/` (private-write R2 bucket with a public custom domain)
- Editor host: Proxmox CT `113`, `192.168.10.22/24`, repository at `/opt/blog-v2`
- Clean Windows clone: `C:\Users\user\Projects\blog-v2`

The legacy source is preserved as tag `legacy-2025`. GitHub Actions is the only
Cloudflare Worker deployment path; the redundant Cloudflare Git build integration is
intentionally disconnected.
