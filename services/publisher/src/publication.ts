import matter from "gray-matter";
import { stringArray, validateFrontmatter } from "./validation.js";

export type ExistingPublication = {
  slug?: string;
  repo_path?: string;
  first_published_at?: Date;
  source_hash?: string;
  last_commit_sha?: string;
};

export function githubPathConflicts(
  publication: ExistingPublication | undefined,
  targetSlug: string,
  currentContent: string | undefined,
  proposedContent: string,
): boolean {
  if (currentContent === undefined) return false;
  if (!publication) return true;
  if (publication.slug === targetSlug) return false;
  return currentContent !== proposedContent;
}

export function buildPublicationArticle(
  raw: string,
  publication: ExistingPublication | undefined,
  now: Date,
): { raw: string; slug: string; title: string; firstPublishedAt: Date } {
  const parsed = validateFrontmatter(raw);
  const data = { ...parsed.data };
  const sourceDate = data.date instanceof Date
    ? data.date
    : typeof data.date === "string" || typeof data.date === "number"
      ? new Date(data.date)
      : undefined;
  const validSourceDate = sourceDate && !Number.isNaN(sourceDate.getTime()) ? sourceDate : undefined;
  const firstPublishedAt = publication?.first_published_at ?? validSourceDate ?? now;
  data.title = parsed.title;
  data.slug = parsed.slug;
  data.tags = stringArray(data.tags);
  data.categories = stringArray(data.categories);
  data.authors = stringArray(data.authors).length ? stringArray(data.authors) : ["haoching"];
  data.date = firstPublishedAt.toISOString();
  data.lastmod = now.toISOString();
  data.draft = false;
  if (publication?.slug && publication.slug !== parsed.slug) {
    const aliases = stringArray(data.aliases);
    const oldAlias = `/posts/${publication.slug}/`;
    if (!aliases.includes(oldAlias)) aliases.push(oldAlias);
    data.aliases = aliases;
  }
  return { raw: matter.stringify(parsed.content, data), slug: parsed.slug, title: parsed.title, firstPublishedAt };
}
