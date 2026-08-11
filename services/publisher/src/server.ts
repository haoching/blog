import crypto from "node:crypto";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import matter from "gray-matter";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { Octokit } from "octokit";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { Pool } from "pg";
import YAML from "yaml";
import { stringArray, validateFrontmatter } from "./validation.js";

const env = (name: string, fallback?: string): string => {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
};

const PORT = Number(process.env.PORT ?? "3000");
const HEDGE_DOC_URL = env("HEDGE_DOC_URL").replace(/\/$/, "");
const HEDGE_DOC_DOMAIN = env("HEDGE_DOC_DOMAIN");
const DATABASE_URL = env("DATABASE_URL");
const GITHUB_OWNER = env("GITHUB_OWNER");
const GITHUB_REPO = env("GITHUB_REPO");
const GITHUB_BRANCH = env("GITHUB_BRANCH", "master");
const R2_BUCKET = env("R2_BUCKET");
const R2_PUBLIC_BASE_URL = env("R2_PUBLIC_BASE_URL").replace(/\/$/, "");
const REQUIRE_ACCESS = (process.env.REQUIRE_ACCESS ?? "true") === "true";

const pool = new Pool({ connectionString: DATABASE_URL });
const octokit = new Octokit({ auth: env("GITHUB_TOKEN") });
const r2 = new S3Client({
  region: process.env.R2_REGION ?? "auto",
  endpoint: env("R2_ENDPOINT"),
  forcePathStyle: true,
  credentials: {
    accessKeyId: env("R2_ACCESS_KEY_ID"),
    secretAccessKey: env("R2_SECRET_ACCESS_KEY"),
  },
});

const app = Fastify({ logger: true, bodyLimit: 1024 * 1024 });
let accessJwks: ReturnType<typeof createRemoteJWKSet> | undefined;

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function requestCookie(request: FastifyRequest): string {
  const cookie = request.headers.cookie;
  return typeof cookie === "string" ? cookie : "";
}

async function requireAccess(request: FastifyRequest, reply: FastifyReply): Promise<boolean> {
  if (!REQUIRE_ACCESS) return true;
  const token = request.headers["cf-access-jwt-assertion"];
  if (typeof token !== "string") {
    await reply.code(401).send({ error: "Cloudflare Access authentication required" });
    return false;
  }
  try {
    const teamDomain = env("CF_ACCESS_TEAM_DOMAIN").replace(/\/$/, "");
    const audience = env("CF_ACCESS_AUDIENCE");
    accessJwks ??= createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`));
    await jwtVerify(token, accessJwks, { audience, issuer: teamDomain });
    return true;
  } catch (error) {
    request.log.warn({ error }, "Cloudflare Access JWT rejected");
    await reply.code(403).send({ error: "Invalid Cloudflare Access identity" });
    return false;
  }
}

async function fetchNote(request: FastifyRequest, noteId: string): Promise<string> {
  if (!requestCookie(request)) throw new Error("HedgeDoc login session is required");
  const response = await fetch(`${HEDGE_DOC_URL}/${encodeURIComponent(noteId)}/download`, {
    headers: { cookie: requestCookie(request) },
  });
  if (!response.ok) throw new Error(`HedgeDoc returned ${response.status} while reading note`);
  return response.text();
}

function isDraftUpload(value: string): boolean {
  try {
    const url = new URL(value, `https://${HEDGE_DOC_DOMAIN}`);
    return url.hostname === HEDGE_DOC_DOMAIN && url.pathname.startsWith("/uploads/");
  } catch {
    return false;
  }
}

function detectImageType(bytes: Buffer, contentType: string | null, source: string): { extension: string; mime: string } {
  const signatures: Array<{ extension: string; mime: string; matches: (data: Buffer) => boolean }> = [
    { extension: "png", mime: "image/png", matches: (data) => data.length >= 8 && data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
    { extension: "jpg", mime: "image/jpeg", matches: (data) => data.length >= 3 && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff },
    { extension: "webp", mime: "image/webp", matches: (data) => data.length >= 12 && data.toString("ascii", 0, 4) === "RIFF" && data.toString("ascii", 8, 12) === "WEBP" },
    { extension: "gif", mime: "image/gif", matches: (data) => data.length >= 6 && (data.toString("ascii", 0, 6) === "GIF87a" || data.toString("ascii", 0, 6) === "GIF89a") },
  ];
  const detected = signatures.find(({ matches }) => matches(bytes));
  if (!detected || (contentType && contentType !== detected.mime)) throw new Error(`Unsupported or mismatched image type for ${source}`);
  return { extension: detected.extension, mime: detected.mime };
}

async function uploadDraftImage(request: FastifyRequest, source: string, slug: string): Promise<string> {
  const url = new URL(source, `https://${HEDGE_DOC_DOMAIN}`);
  const response = await fetch(`${HEDGE_DOC_URL}${url.pathname}`, { headers: { cookie: requestCookie(request) } });
  if (!response.ok) throw new Error(`Unable to read draft image (${response.status})`);
  const contentType = response.headers.get("content-type")?.split(";", 1)[0] ?? null;
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.byteLength > 10 * 1024 * 1024) throw new Error("Image exceeds the 10 MB limit");
  const detected = detectImageType(bytes, contentType, source);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  const key = `posts/${slug}/${digest}.${detected.extension}`;
  await r2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: key, Body: bytes, ContentType: detected.mime, CacheControl: "public, max-age=31536000, immutable" }));
  return `${R2_PUBLIC_BASE_URL}/${key}`;
}

async function rewriteDraftImages(request: FastifyRequest, raw: string, slug: string): Promise<string> {
  const parsed = matter(raw);
  const sourceUrls = new Set<string>();
  const markdownImage = /!\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)/g;
  for (const match of parsed.content.matchAll(markdownImage)) if (isDraftUpload(match[1])) sourceUrls.add(match[1]);
  if (typeof parsed.data.featureimage === "string" && isDraftUpload(parsed.data.featureimage)) sourceUrls.add(parsed.data.featureimage);
  const replacements = new Map<string, string>();
  for (const source of sourceUrls) replacements.set(source, await uploadDraftImage(request, source, slug));
  let content = parsed.content;
  for (const [source, target] of replacements) content = content.replaceAll(source, target);
  if (typeof parsed.data.featureimage === "string" && replacements.has(parsed.data.featureimage)) parsed.data.featureimage = replacements.get(parsed.data.featureimage);
  return matter.stringify(content, parsed.data);
}

async function getGithubFile(path: string): Promise<{ sha: string; content: string } | undefined> {
  try {
    const result = await octokit.rest.repos.getContent({ owner: GITHUB_OWNER, repo: GITHUB_REPO, path, ref: GITHUB_BRANCH });
    if (Array.isArray(result.data) || result.data.type !== "file") return undefined;
    return { sha: result.data.sha, content: Buffer.from(result.data.content ?? "", "base64").toString("utf8") };
  } catch (error: any) {
    if (error.status === 404) return undefined;
    throw error;
  }
}

async function ensureSchema(): Promise<void> {
  await pool.query(`CREATE TABLE IF NOT EXISTS publications (
    note_id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, repo_path TEXT NOT NULL UNIQUE,
    first_published_at TIMESTAMPTZ NOT NULL, last_published_at TIMESTAMPTZ NOT NULL,
    source_hash TEXT NOT NULL, last_commit_sha TEXT NOT NULL)`);
}

const actionsUrl = `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/actions`;

async function publishNote(request: FastifyRequest, noteId: string, expectedHash: string): Promise<{ slug: string; commit: string; url: string; actionsUrl: string }> {
  const raw = await fetchNote(request, noteId);
  const sourceHash = crypto.createHash("sha256").update(raw).digest("hex");
  if (sourceHash !== expectedHash) throw new Error("The note changed while you were reviewing it; reload and confirm again");
  const parsed = validateFrontmatter(raw);
  const existing = await pool.query("SELECT * FROM publications WHERE note_id = $1", [noteId]);
  const publication = existing.rows[0] as { slug?: string; first_published_at?: Date; source_hash?: string; last_commit_sha?: string } | undefined;
  const slugConflict = await pool.query("SELECT note_id FROM publications WHERE slug = $1 AND note_id <> $2 LIMIT 1", [parsed.slug, noteId]);
  if (slugConflict.rowCount) throw new Error(`Slug already belongs to another published note: ${parsed.slug}`);
  if (publication?.source_hash === sourceHash && publication.slug && publication.last_commit_sha) {
    return { slug: publication.slug, commit: publication.last_commit_sha, url: `https://chang929.site/posts/${publication.slug}/`, actionsUrl };
  }
  const now = new Date();
  const firstPublishedAt = publication?.first_published_at ?? now;
  const data = { ...parsed.data };
  data.title = parsed.title;
  data.slug = parsed.slug;
  data.tags = stringArray(data.tags);
  data.categories = stringArray(data.categories);
  data.authors = stringArray(data.authors).length ? stringArray(data.authors) : ["haoching"];
  data.date = publication?.first_published_at ? publication.first_published_at.toISOString() : (data.date ?? firstPublishedAt.toISOString());
  data.lastmod = now.toISOString();
  data.draft = false;
  if (publication?.slug && publication.slug !== parsed.slug) {
    const aliases = stringArray(data.aliases);
    const oldAlias = `/posts/${publication.slug}/`;
    if (!aliases.includes(oldAlias)) aliases.push(oldAlias);
    data.aliases = aliases;
  }
  const normalized = await rewriteDraftImages(request, matter.stringify(parsed.content, data), parsed.slug);
  const repoPath = `content/posts/${parsed.slug}/index.md`;
  const current = await getGithubFile(repoPath);
  if (current?.content === normalized && publication?.last_commit_sha) {
    return { slug: parsed.slug, commit: publication.last_commit_sha, url: `https://chang929.site/posts/${parsed.slug}/`, actionsUrl };
  }
  const response = await octokit.rest.repos.createOrUpdateFileContents({ owner: GITHUB_OWNER, repo: GITHUB_REPO, path: repoPath, branch: GITHUB_BRANCH, message: `publish: ${parsed.title}`, content: Buffer.from(normalized, "utf8").toString("base64"), sha: current?.sha });
  const commitSha = response.data.commit.sha ?? response.data.content?.sha ?? "unknown";
  await pool.query(`INSERT INTO publications (note_id, slug, repo_path, first_published_at, last_published_at, source_hash, last_commit_sha)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (note_id) DO UPDATE SET slug = EXCLUDED.slug, repo_path = EXCLUDED.repo_path,
      last_published_at = EXCLUDED.last_published_at, source_hash = EXCLUDED.source_hash,
      last_commit_sha = EXCLUDED.last_commit_sha`, [noteId, parsed.slug, repoPath, firstPublishedAt, now, sourceHash, commitSha]);
  return { slug: parsed.slug, commit: commitSha, url: `https://chang929.site/posts/${parsed.slug}/`, actionsUrl };
}

function renderDiff(before: string | undefined, after: string): string {
  if (before === undefined) return `--- /dev/null\n+++ proposed\n${after.split("\n").map((line) => `+ ${line}`).join("\n")}`;
  if (before === after) return "No changes: this publication would not create a new commit.";
  return [
    "--- current GitHub file",
    "+++ proposed file",
    ...before.split("\n").map((line) => `- ${line}`),
    ...after.split("\n").map((line) => `+ ${line}`),
  ].join("\n");
}

function renderPreview(noteId: string, raw: string, sourceHash: string, current: string | undefined): string {
  const parsed = validateFrontmatter(raw);
  const diff = renderDiff(current, raw);
  return `<!doctype html><meta charset="utf-8"><title>發布 ${escapeHtml(parsed.title)}</title>
  <style>body{font-family:system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}main{display:grid;grid-template-columns:1fr 1fr;gap:1rem}section{border:1px solid #374151;border-radius:8px;padding:1rem}pre{white-space:pre-wrap;max-height:70vh;overflow:auto}button{background:#38bdf8;border:0;border-radius:6px;padding:.7rem 1rem;cursor:pointer}</style>
  <h1>發布：${escapeHtml(parsed.title)}</h1><p>網址：/posts/${escapeHtml(parsed.slug)}/</p><main><section><h2>Frontmatter</h2><pre>${escapeHtml(YAML.stringify(parsed.data))}</pre></section><section><h2>Markdown</h2><pre>${escapeHtml(parsed.content)}</pre></section><section><h2>Git diff</h2><pre>${escapeHtml(diff)}</pre></section></main>
  <button id="publish">確認發布</button><p id="status"></p><script>
  document.querySelector('#publish').onclick=async()=>{const b=document.querySelector('#publish');b.disabled=true;const s=document.querySelector('#status');s.textContent='發布中…';const r=await fetch('/${encodeURIComponent(noteId)}/publish/confirm',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sourceHash:'${sourceHash}'})});const j=await r.json();s.textContent=j.error||('完成：'+j.url+' commit '+j.commit);b.disabled=false};</script>`;
}

async function handlePreview(request: FastifyRequest<{ Params: { noteId: string } }>, reply: FastifyReply): Promise<void> {
  if (!(await requireAccess(request, reply))) return;
  try {
    const raw = await fetchNote(request, request.params.noteId);
    const sourceHash = crypto.createHash("sha256").update(raw).digest("hex");
    const parsed = validateFrontmatter(raw);
    const current = await getGithubFile(`content/posts/${parsed.slug}/index.md`);
    reply.type("text/html").send(renderPreview(request.params.noteId, raw, sourceHash, current?.content));
  } catch (error: any) {
    reply.code(400).send({ error: error.message });
  }
}

async function handleConfirm(request: FastifyRequest<{ Params: { noteId: string }; Body: { sourceHash?: string } }>, reply: FastifyReply): Promise<void> {
  if (!(await requireAccess(request, reply))) return;
  try {
    const origin = request.headers.origin;
    if (origin && origin !== `https://${HEDGE_DOC_DOMAIN}`) throw new Error("Publish confirmation must come from the editor origin");
    const sourceHash = request.body?.sourceHash;
    if (!sourceHash || !/^[a-f0-9]{64}$/.test(sourceHash)) throw new Error("Invalid source hash");
    reply.send(await publishNote(request, request.params.noteId, sourceHash));
  } catch (error: any) {
    request.log.error({ error }, "Publish failed");
    reply.code(400).send({ error: error.message });
  }
}

app.get("/:noteId/publish", handlePreview);
app.post("/:noteId/publish/confirm", handleConfirm);
app.get("/health", async () => ({ ok: true }));

await ensureSchema();
await app.listen({ host: "0.0.0.0", port: PORT });
