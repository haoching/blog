# HedgeDoc editor stack

This stack is intended for the dedicated Ubuntu LXC on VLAN 10. It exposes only
the local Caddy port; public access is provided by a Cloudflare Tunnel whose
public hostname is `edit.chang929.site`.

1. Copy `.env.example` to `.env` and fill secrets. Never commit `.env`.
2. Create the GitHub OAuth application with callback
   `https://edit.chang929.site/auth/github/callback`.
3. Create the Cloudflare Tunnel route to `http://reverse_proxy:8080`.
4. Configure Cloudflare Access to allow only the collaborators.
5. Start with `docker compose up -d --build`.

The publisher intercepts HedgeDoc's `/<note>/publish` request, shows the
frontmatter and Markdown for confirmation, then commits the normalized article.
The filesystem upload path remains HedgeDoc's default `/hedgedoc/public/uploads`
and is backed by the `hedgedoc_uploads` volume; `CMD_UPLOADS_PATH` is not a
documented HedgeDoc 1.x environment variable.
