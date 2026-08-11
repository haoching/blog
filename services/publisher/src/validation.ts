import matter from "gray-matter";

export type PublicationKind = "post" | "about";

export type ValidatedFrontmatter = {
  data: Record<string, unknown>;
  content: string;
  kind: PublicationKind;
  slug: string;
  title: string;
};

export function slugIsValid(slug: unknown): slug is string {
  return typeof slug === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) && slug.length <= 96;
}

export function stringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}

export function validateFrontmatter(raw: string): ValidatedFrontmatter {
  const parsed = matter(raw);
  const data = parsed.data as Record<string, unknown>;
  const title = typeof data.title === "string" ? data.title.trim() : "";
  const page = data.page;
  const kind: PublicationKind = page === "about" ? "about" : "post";
  const slug = kind === "about" ? "about" : data.slug;
  const errors: string[] = [];
  if (!title) errors.push("title is required");
  if (page !== undefined && page !== "about") errors.push('page must be "about" when publishing a fixed page');
  if (!slugIsValid(slug)) errors.push("slug must use lowercase English letters, numbers, and hyphens");
  if (kind === "post" && slug === "about") errors.push('slug "about" is reserved for the About Me page');
  if (data.tags !== undefined && !Array.isArray(data.tags) && typeof data.tags !== "string") errors.push("tags must be an array");
  if (data.categories !== undefined && !Array.isArray(data.categories) && typeof data.categories !== "string") errors.push("categories must be an array");
  const hedgeDocOnly = [
    /^\s*\[toc\]\s*$/i,
    /^\s*<!--\s*(?:slide|\.element:)/i,
    /^\s*@import\s+/i,
    /^\s*```[a-z0-9_-]*!\s*$/i,
  ];
  for (const [index, line] of parsed.content.split(/\r?\n/).entries()) {
    if (hedgeDocOnly.some((pattern) => pattern.test(line))) errors.push(`HedgeDoc-only syntax at line ${index + 1}; use a Hugo/Blowfish equivalent`);
  }
  if (errors.length) throw new Error(errors.join("; "));
  return { data, content: parsed.content, kind, slug: slug as string, title };
}
