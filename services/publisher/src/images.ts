import matter from "gray-matter";

export const MAX_IMAGE_BYTES = 10 * 1024 * 1024;

export type ReferencedImage = {
  source: string;
  kind: "draft" | "published" | "external";
};

export function imageIsDraftUpload(value: string, hedgeDocDomain: string): boolean {
  try {
    const url = new URL(value, `https://${hedgeDocDomain}`);
    return url.hostname === hedgeDocDomain && url.pathname.startsWith("/uploads/");
  } catch {
    return false;
  }
}

export function collectReferencedImages(
  raw: string,
  hedgeDocDomain: string,
  publicBaseUrl: string,
): ReferencedImage[] {
  const parsed = matter(raw);
  const sources = new Set<string>();
  const markdownImage = /!\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)/g;
  for (const match of parsed.content.matchAll(markdownImage)) sources.add(match[1]);
  if (typeof parsed.data.featureimage === "string" && parsed.data.featureimage.trim()) {
    sources.add(parsed.data.featureimage.trim());
  }
  return [...sources].map((source) => ({
    source,
    kind: imageIsDraftUpload(source, hedgeDocDomain)
      ? "draft"
      : source.startsWith(`${publicBaseUrl}/`)
        ? "published"
        : "external",
  }));
}

export function assertImageSize(size: number): void {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_IMAGE_BYTES) {
    throw new Error("Image exceeds the 10 MB limit");
  }
}

export function detectImageType(bytes: Buffer, contentType: string | null, source: string): { extension: string; mime: string } {
  const signatures: Array<{ extension: string; mime: string; matches: (data: Buffer) => boolean }> = [
    { extension: "png", mime: "image/png", matches: (data) => data.length >= 8 && data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
    { extension: "jpg", mime: "image/jpeg", matches: (data) => data.length >= 3 && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff },
    { extension: "webp", mime: "image/webp", matches: (data) => data.length >= 12 && data.toString("ascii", 0, 4) === "RIFF" && data.toString("ascii", 8, 12) === "WEBP" },
    { extension: "gif", mime: "image/gif", matches: (data) => data.length >= 6 && (data.toString("ascii", 0, 6) === "GIF87a" || data.toString("ascii", 0, 6) === "GIF89a") },
  ];
  const detected = signatures.find(({ matches }) => matches(bytes));
  if (!detected || (contentType && contentType !== detected.mime)) {
    throw new Error(`Unsupported or mismatched image type for ${source}`);
  }
  return { extension: detected.extension, mime: detected.mime };
}

export function replaceImageSources(raw: string, replacements: ReadonlyMap<string, string>): string {
  const parsed = matter(raw);
  let content = parsed.content;
  for (const [source, target] of replacements) content = content.replaceAll(source, target);
  if (typeof parsed.data.featureimage === "string" && replacements.has(parsed.data.featureimage)) {
    parsed.data.featureimage = replacements.get(parsed.data.featureimage);
  }
  return matter.stringify(content, parsed.data);
}
