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

## Deployment secrets

The production GitHub Actions environment requires `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID`. The token must be limited to Workers deployment for this
account. The preview environment uses the same account with a separate Worker name.
