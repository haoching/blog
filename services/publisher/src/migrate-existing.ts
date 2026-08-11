import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import matter from "gray-matter";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { validateFrontmatter } from "./validation.js";

const env = (name: string): string => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
};

const inputRoot = path.resolve(process.argv[2] ?? "");
const outputRoot = path.resolve(process.argv[3] ?? "");
if (!process.argv[2] || !process.argv[3]) {
  throw new Error("Usage: node dist/migrate-existing.js <posts-root> <output-root>");
}

const bucket = env("R2_BUCKET");
const publicBaseUrl = env("R2_PUBLIC_BASE_URL").replace(/\/$/, "");
const r2 = new S3Client({
  region: process.env.R2_REGION ?? "auto",
  endpoint: env("R2_ENDPOINT"),
  forcePathStyle: true,
  credentials: {
    accessKeyId: env("R2_ACCESS_KEY_ID"),
    secretAccessKey: env("R2_SECRET_ACCESS_KEY"),
  },
});

function detectImage(bytes: Buffer, source: string): { extension: string; mime: string } {
  const types = [
    { extension: "png", mime: "image/png", matches: () => bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
    { extension: "jpg", mime: "image/jpeg", matches: () => bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff },
    { extension: "webp", mime: "image/webp", matches: () => bytes.length >= 12 && bytes.toString("ascii", 0, 4) === "RIFF" && bytes.toString("ascii", 8, 12) === "WEBP" },
    { extension: "gif", mime: "image/gif", matches: () => bytes.length >= 6 && ["GIF87a", "GIF89a"].includes(bytes.toString("ascii", 0, 6)) },
  ];
  const detected = types.find(({ matches }) => matches());
  if (!detected) throw new Error(`Unsupported image type: ${source}`);
  return { extension: detected.extension, mime: detected.mime };
}

function isLocalImage(value: string): boolean {
  return !/^(?:https?:|data:|#)/i.test(value);
}

async function uploadImage(postDirectory: string, source: string, slug: string): Promise<string> {
  const relativePath = decodeURIComponent(source.split(/[?#]/, 1)[0]);
  const candidate = path.resolve(postDirectory, relativePath);
  const realPostDirectory = await fs.realpath(postDirectory);
  const realCandidate = await fs.realpath(candidate);
  if (realCandidate !== realPostDirectory && !realCandidate.startsWith(`${realPostDirectory}${path.sep}`)) {
    throw new Error(`Image path escapes its post directory: ${source}`);
  }
  const bytes = await fs.readFile(realCandidate);
  if (bytes.byteLength > 10 * 1024 * 1024) throw new Error(`Image exceeds 10 MB: ${source}`);
  const detected = detectImage(bytes, source);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  const key = `posts/${slug}/${digest}.${detected.extension}`;
  await r2.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: bytes,
    ContentType: detected.mime,
    CacheControl: "public, max-age=31536000, immutable",
  }));
  return `${publicBaseUrl}/${key}`;
}

await fs.mkdir(outputRoot, { recursive: true });
const results: Array<{ slug: string; output: string; images: number }> = [];
for (const entry of await fs.readdir(inputRoot, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const postDirectory = path.join(inputRoot, entry.name);
  const sourcePath = path.join(postDirectory, "index.md");
  try {
    await fs.access(sourcePath);
  } catch {
    continue;
  }

  const raw = await fs.readFile(sourcePath, "utf8");
  const validated = validateFrontmatter(raw);
  const parsed = matter(raw);
  const replacements = new Map<string, string>();
  const markdownImage = /!\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)/g;
  for (const match of parsed.content.matchAll(markdownImage)) {
    const source = match[1];
    if (isLocalImage(source) && !replacements.has(source)) {
      replacements.set(source, await uploadImage(postDirectory, source, validated.slug));
    }
  }

  let content = parsed.content;
  for (const [source, target] of replacements) content = content.replaceAll(source, target);

  if (typeof parsed.data.featureimage === "string" && parsed.data.featureimage && isLocalImage(parsed.data.featureimage)) {
    parsed.data.featureimage = await uploadImage(postDirectory, parsed.data.featureimage, validated.slug);
  } else if (!parsed.data.featureimage) {
    const conventionalFeature = path.join(postDirectory, "featured.png");
    try {
      await fs.access(conventionalFeature);
      parsed.data.featureimage = await uploadImage(postDirectory, "featured.png", validated.slug);
    } catch (error: any) {
      if (error?.code !== "ENOENT") throw error;
    }
  }

  const output = path.join(outputRoot, `${validated.slug}.md`);
  await fs.writeFile(output, matter.stringify(content, parsed.data), { encoding: "utf8", mode: 0o600 });
  results.push({ slug: validated.slug, output, images: replacements.size + (parsed.data.featureimage ? 1 : 0) });
}

process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
