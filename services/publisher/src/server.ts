import crypto from "node:crypto";
import fs from "node:fs";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { App, Octokit } from "octokit";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { Pool } from "pg";
import YAML from "yaml";
import {
  assertImageSize,
  collectReferencedImages,
  detectImageType,
  replaceImageSources,
  type ReferencedImage,
} from "./images.js";
import { buildPublicationArticle, githubPathConflicts, type ExistingPublication } from "./publication.js";
import { validateFrontmatter } from "./validation.js";

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
const staticGithubToken = process.env.GITHUB_TOKEN?.trim();
const staticOctokit = staticGithubToken ? new Octokit({ auth: staticGithubToken }) : undefined;
const githubApp = staticGithubToken
  ? undefined
  : new App({
      appId: env("GITHUB_APP_ID"),
      privateKey: fs.readFileSync(env("GITHUB_APP_PRIVATE_KEY_PATH"), "utf8"),
    });
const githubInstallationId = staticGithubToken ? undefined : Number(env("GITHUB_APP_INSTALLATION_ID"));

async function githubClient(): Promise<Octokit> {
  if (staticOctokit) return staticOctokit;
  if (!githubApp || !Number.isSafeInteger(githubInstallationId) || githubInstallationId! <= 0) {
    throw new Error("Invalid GitHub App installation configuration");
  }
  return githubApp.getInstallationOctokit(githubInstallationId!);
}
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

type ImageReview = ReferencedImage & {
  target: string;
  status: string;
};

type PreparedDraftImage = {
  key: string;
  bytes: Buffer;
  mime: string;
  target: string;
};

async function inspectDraftImage(request: FastifyRequest, source: string, mediaPath: string): Promise<PreparedDraftImage> {
  const url = new URL(source, `https://${HEDGE_DOC_DOMAIN}`);
  const response = await fetch(`${HEDGE_DOC_URL}${url.pathname}`, { headers: { cookie: requestCookie(request) } });
  if (!response.ok) throw new Error(`Unable to read draft image (${response.status})`);
  const advertisedLength = response.headers.get("content-length");
  if (advertisedLength) assertImageSize(Number(advertisedLength));
  const contentType = response.headers.get("content-type")?.split(";", 1)[0] ?? null;
  const bytes = Buffer.from(await response.arrayBuffer());
  assertImageSize(bytes.byteLength);
  const detected = detectImageType(bytes, contentType, source);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  const key = `${mediaPath}/${digest}.${detected.extension}`;
  return { key, bytes, mime: detected.mime, target: `${R2_PUBLIC_BASE_URL}/${key}` };
}

async function prepareImages(
  request: FastifyRequest,
  raw: string,
  mediaPath: string,
  upload: boolean,
): Promise<{ raw: string; images: ImageReview[] }> {
  const references = collectReferencedImages(raw, HEDGE_DOC_DOMAIN, R2_PUBLIC_BASE_URL);
  const replacements = new Map<string, string>();
  const images: ImageReview[] = [];
  for (const reference of references) {
    if (reference.kind === "draft") {
      const prepared = await inspectDraftImage(request, reference.source, mediaPath);
      if (upload) {
        await r2.send(new PutObjectCommand({
          Bucket: R2_BUCKET,
          Key: prepared.key,
          Body: prepared.bytes,
          ContentType: prepared.mime,
          CacheControl: "public, max-age=31536000, immutable",
        }));
      }
      replacements.set(reference.source, prepared.target);
      images.push({ ...reference, target: prepared.target, status: upload ? "validated and copied to R2" : "validated; will be copied to R2" });
    } else {
      images.push({
        ...reference,
        target: reference.source,
        status: reference.kind === "published" ? "already stored in R2" : "supported external URL",
      });
    }
  }
  return { raw: replaceImageSources(raw, replacements), images };
}

async function getGithubFile(path: string): Promise<{ sha: string; content: string } | undefined> {
  try {
    const octokit = await githubClient();
    const result = await octokit.rest.repos.getContent({ owner: GITHUB_OWNER, repo: GITHUB_REPO, path, ref: GITHUB_BRANCH });
    if (Array.isArray(result.data) || result.data.type !== "file") return undefined;
    return { sha: result.data.sha, content: Buffer.from(result.data.content ?? "", "base64").toString("utf8") };
  } catch (error: any) {
    if (error.status === 404) return undefined;
    throw error;
  }
}

async function getLatestCommitForPath(path: string): Promise<string | undefined> {
  const octokit = await githubClient();
  const result = await octokit.rest.repos.listCommits({
    owner: GITHUB_OWNER,
    repo: GITHUB_REPO,
    sha: GITHUB_BRANCH,
    path,
    per_page: 1,
  });
  return result.data[0]?.sha;
}

async function ensureSchema(): Promise<void> {
  await pool.query(`CREATE TABLE IF NOT EXISTS publications (
    note_id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, repo_path TEXT NOT NULL UNIQUE,
    first_published_at TIMESTAMPTZ NOT NULL, last_published_at TIMESTAMPTZ NOT NULL,
    source_hash TEXT NOT NULL, last_commit_sha TEXT NOT NULL)`);
}

const actionsUrl = `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/actions`;

type PublishResult = {
  slug: string;
  commit: string;
  url: string;
  commitUrl: string;
  actionsUrl: string;
  statusUrl: string;
};

function publishedUrlPath(slug: string, repoPath?: string): string {
  return repoPath === "content/about/index.md" ? "/about/" : `/posts/${slug}/`;
}

function publishResult(noteId: string, slug: string, commit: string, repoPath?: string): PublishResult {
  return {
    slug,
    commit,
    url: `https://chang929.site${publishedUrlPath(slug, repoPath)}`,
    commitUrl: `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/commit/${commit}`,
    actionsUrl,
    statusUrl: `/${encodeURIComponent(noteId)}/publish/status?commit=${encodeURIComponent(commit)}`,
  };
}

async function publishNote(request: FastifyRequest, noteId: string, expectedHash: string): Promise<PublishResult> {
  const raw = await fetchNote(request, noteId);
  const sourceHash = crypto.createHash("sha256").update(raw).digest("hex");
  if (sourceHash !== expectedHash) throw new Error("The note changed while you were reviewing it; reload and confirm again");
  const parsed = validateFrontmatter(raw);
  const existing = await pool.query("SELECT * FROM publications WHERE note_id = $1", [noteId]);
  const publication = existing.rows[0] as ExistingPublication | undefined;
  const slugConflict = await pool.query("SELECT note_id FROM publications WHERE slug = $1 AND note_id <> $2 LIMIT 1", [parsed.slug, noteId]);
  if (slugConflict.rowCount) throw new Error(`Slug already belongs to another published note: ${parsed.slug}`);
  if (publication?.source_hash === sourceHash && publication.slug && publication.last_commit_sha) {
    return publishResult(noteId, publication.slug, publication.last_commit_sha, publication.repo_path);
  }
  const now = new Date();
  const article = buildPublicationArticle(raw, publication, now);
  const wasAbout = publication?.repo_path === "content/about/index.md";
  if (publication?.repo_path && wasAbout !== (article.kind === "about")) {
    throw new Error("A published note cannot change between a blog post and the About Me page");
  }
  const prepared = await prepareImages(request, article.raw, article.mediaPath, true);
  const repoPath = article.repoPath;
  const oldRepoPath = publication?.repo_path ?? (publication?.slug ? `content/posts/${publication.slug}/index.md` : undefined);
  const slugChanged = article.kind === "post" && Boolean(publication?.slug && publication.slug !== article.slug);
  const current = await getGithubFile(repoPath);
  if (article.kind === "post" && githubPathConflicts(publication, article.slug, current?.content, prepared.raw)) {
    throw new Error(`Slug already exists in GitHub: ${article.slug}`);
  }
  if (current?.content === prepared.raw && !slugChanged && publication?.last_commit_sha) {
    return publishResult(noteId, article.slug, publication.last_commit_sha, repoPath);
  }
  const octokit = await githubClient();
  let commitSha = publication?.last_commit_sha ?? "unknown";
  if (current?.content !== prepared.raw) {
    const response = await octokit.rest.repos.createOrUpdateFileContents({
      owner: GITHUB_OWNER,
      repo: GITHUB_REPO,
      path: repoPath,
      branch: GITHUB_BRANCH,
      message: `publish: ${article.title}`,
      content: Buffer.from(prepared.raw, "utf8").toString("base64"),
      sha: current?.sha,
    });
    commitSha = response.data.commit.sha ?? response.data.content?.sha ?? commitSha;
  } else {
    commitSha = (await getLatestCommitForPath(repoPath)) ?? commitSha;
  }
  if (slugChanged && oldRepoPath && oldRepoPath !== repoPath) {
    const oldFile = await getGithubFile(oldRepoPath);
    if (oldFile) {
      const deleted = await octokit.rest.repos.deleteFile({
        owner: GITHUB_OWNER,
        repo: GITHUB_REPO,
        path: oldRepoPath,
        branch: GITHUB_BRANCH,
        message: `publish: redirect ${publication?.slug} to ${article.slug}`,
        sha: oldFile.sha,
      });
      commitSha = deleted.data.commit.sha ?? commitSha;
    }
  }
  if (!/^[a-f0-9]{40}$/.test(commitSha)) throw new Error("GitHub did not return a valid commit SHA");
  await pool.query(`INSERT INTO publications (note_id, slug, repo_path, first_published_at, last_published_at, source_hash, last_commit_sha)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (note_id) DO UPDATE SET slug = EXCLUDED.slug, repo_path = EXCLUDED.repo_path,
      last_published_at = EXCLUDED.last_published_at, source_hash = EXCLUDED.source_hash,
      last_commit_sha = EXCLUDED.last_commit_sha`, [noteId, article.slug, repoPath, article.firstPublishedAt, now, sourceHash, commitSha]);
  return publishResult(noteId, article.slug, commitSha, repoPath);
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

function renderPreview(
  noteId: string,
  proposed: string,
  sourceHash: string,
  current: string | undefined,
  images: ImageReview[],
): string {
  const parsed = validateFrontmatter(proposed);
  const diff = renderDiff(current, proposed);
  const urlPath = parsed.kind === "about" ? "/about/" : `/posts/${parsed.slug}/`;
  const imageRows = images.length
    ? `<ul>${images.map((image) => `<li><code>${escapeHtml(image.source)}</code><br>→ <code>${escapeHtml(image.target)}</code><br>${escapeHtml(image.status)}</li>`).join("")}</ul>`
    : "<p>本文沒有引用圖片。</p>";
  return `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>發布 ${escapeHtml(parsed.title)}</title>
  <style>body{font-family:system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1rem}section{border:1px solid #374151;border-radius:8px;padding:1rem}pre{white-space:pre-wrap;max-height:70vh;overflow:auto}li{margin:.75rem 0;overflow-wrap:anywhere}button{background:#38bdf8;border:0;border-radius:6px;padding:.7rem 1rem;cursor:pointer}button:disabled{opacity:.55}a{color:#7dd3fc}</style></head><body>
  <h1>發布：${escapeHtml(parsed.title)}</h1><p>網址：<code>${escapeHtml(urlPath)}</code></p><p>驗證通過：frontmatter、路徑、Markdown 語法與草稿圖片皆符合發布規則。</p><main><section><h2>Frontmatter</h2><pre>${escapeHtml(YAML.stringify(parsed.data))}</pre></section><section><h2>Markdown</h2><pre>${escapeHtml(parsed.content)}</pre></section><section><h2>圖片</h2>${imageRows}</section><section><h2>Git diff</h2><pre>${escapeHtml(diff)}</pre></section></main>
  <p><button id="publish">確認發布</button></p><p id="status"></p><p id="deployment"></p><script>
  const button=document.querySelector('#publish');const status=document.querySelector('#status');const deployment=document.querySelector('#deployment');
  async function poll(url){const response=await fetch(url);const result=await response.json();if(result.error){deployment.textContent=result.error;return}deployment.innerHTML='部署：<a target="_blank" rel="noreferrer" href="'+result.actionsUrl+'">'+result.status+(result.conclusion?' / '+result.conclusion:'')+'</a>';if(result.status!=='completed')setTimeout(()=>poll(url),3000)}
  button.onclick=async()=>{button.disabled=true;status.textContent='發布中…';const response=await fetch('/${encodeURIComponent(noteId)}/publish/confirm',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sourceHash:'${sourceHash}'})});const result=await response.json();if(result.error){status.textContent=result.error;button.disabled=false;return}status.innerHTML='完成：<a href="'+result.url+'">文章</a> · <a target="_blank" rel="noreferrer" href="'+result.commitUrl+'">commit '+result.commit.slice(0,7)+'</a>';poll(result.statusUrl)};</script></body></html>`;
}

async function handlePreview(request: FastifyRequest<{ Params: { noteId: string } }>, reply: FastifyReply): Promise<void> {
  if (!(await requireAccess(request, reply))) return;
  try {
    const raw = await fetchNote(request, request.params.noteId);
    const sourceHash = crypto.createHash("sha256").update(raw).digest("hex");
    const parsed = validateFrontmatter(raw);
    const existing = await pool.query("SELECT * FROM publications WHERE note_id = $1", [request.params.noteId]);
    const publication = existing.rows[0] as ExistingPublication | undefined;
    const slugConflict = await pool.query("SELECT note_id FROM publications WHERE slug = $1 AND note_id <> $2 LIMIT 1", [parsed.slug, request.params.noteId]);
    if (slugConflict.rowCount) throw new Error(`Slug already belongs to another published note: ${parsed.slug}`);
    const article = buildPublicationArticle(raw, publication, new Date());
    const wasAbout = publication?.repo_path === "content/about/index.md";
    if (publication?.repo_path && wasAbout !== (article.kind === "about")) {
      throw new Error("A published note cannot change between a blog post and the About Me page");
    }
    const prepared = await prepareImages(request, article.raw, article.mediaPath, false);
    const current = await getGithubFile(article.repoPath);
    if (article.kind === "post" && githubPathConflicts(publication, article.slug, current?.content, prepared.raw)) {
      throw new Error(`Slug already exists in GitHub: ${article.slug}`);
    }
    reply.type("text/html").send(renderPreview(request.params.noteId, prepared.raw, sourceHash, current?.content, prepared.images));
  } catch (error: any) {
    reply.code(400).send({ error: error.message });
  }
}

async function handleStatus(
  request: FastifyRequest<{ Params: { noteId: string }; Querystring: { commit?: string } }>,
  reply: FastifyReply,
): Promise<void> {
  if (!(await requireAccess(request, reply))) return;
  try {
    const commit = request.query.commit;
    if (!commit || !/^[a-f0-9]{40}$/.test(commit)) throw new Error("Invalid commit SHA");
    const octokit = await githubClient();
    const runs = await octokit.rest.actions.listWorkflowRunsForRepo({
      owner: GITHUB_OWNER,
      repo: GITHUB_REPO,
      head_sha: commit,
      per_page: 1,
    });
    const run = runs.data.workflow_runs[0];
    reply.send(run
      ? { status: run.status, conclusion: run.conclusion, actionsUrl: run.html_url }
      : { status: "waiting", conclusion: null, actionsUrl });
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
app.get("/:noteId/publish/status", handleStatus);
app.get("/health", async () => ({ ok: true }));

await ensureSchema();
await app.listen({ host: "0.0.0.0", port: PORT });
