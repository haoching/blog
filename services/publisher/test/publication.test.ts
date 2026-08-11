import assert from "node:assert/strict";
import test from "node:test";
import matter from "gray-matter";
import { buildPublicationArticle, githubPathConflicts } from "../src/publication.js";

test("adds the old URL as an alias when a note slug changes", () => {
  const firstPublished = new Date("2025-07-25T00:00:00.000Z");
  const now = new Date("2026-08-11T12:00:00.000Z");
  const result = buildPublicationArticle(
    "---\ntitle: Renamed\nslug: new-slug\naliases: [/older/]\n---\nBody",
    { slug: "old-slug", first_published_at: firstPublished },
    now,
  );
  const parsed = matter(result.raw);
  assert.deepEqual(parsed.data.aliases, ["/older/", "/posts/old-slug/"]);
  assert.equal(String(parsed.data.date), firstPublished.toISOString());
  assert.equal(String(parsed.data.lastmod), now.toISOString());
  assert.equal(parsed.data.draft, false);
});

test("does not duplicate an existing old-slug alias", () => {
  const result = buildPublicationArticle(
    "---\ntitle: Renamed\nslug: new-slug\naliases: [/posts/old-slug/]\n---\nBody",
    { slug: "old-slug", first_published_at: new Date("2025-07-25T00:00:00.000Z") },
    new Date("2026-08-11T12:00:00.000Z"),
  );
  assert.deepEqual(matter(result.raw).data.aliases, ["/posts/old-slug/"]);
});

test("blocks slugs that already exist outside this publication", () => {
  assert.equal(githubPathConflicts(undefined, "taken", "existing", "proposed"), true);
  assert.equal(githubPathConflicts({ slug: "same" }, "same", "existing", "proposed"), false);
  assert.equal(githubPathConflicts({ slug: "old" }, "new", "existing", "proposed"), true);
  assert.equal(githubPathConflicts({ slug: "old" }, "new", "proposed", "proposed"), false);
});

test("uses a migrated source date on first publish", () => {
  const result = buildPublicationArticle(
    "---\ntitle: Migrated\nslug: migrated\ndate: 2025-07-25T00:00:00.000Z\n---\nBody",
    undefined,
    new Date("2026-08-11T12:00:00.000Z"),
  );
  assert.equal(result.firstPublishedAt.toISOString(), "2025-07-25T00:00:00.000Z");
  assert.equal(String(matter(result.raw).data.date), "2025-07-25T00:00:00.000Z");
});

test("keeps the stored first-publish date on updates", () => {
  const result = buildPublicationArticle(
    "---\ntitle: Stable\nslug: stable\ndate: 2030-01-01T00:00:00.000Z\n---\nBody",
    { first_published_at: new Date("2025-07-25T00:00:00.000Z") },
    new Date("2026-08-11T12:00:00.000Z"),
  );
  assert.equal(result.firstPublishedAt.toISOString(), "2025-07-25T00:00:00.000Z");
  assert.equal(String(matter(result.raw).data.date), "2025-07-25T00:00:00.000Z");
});
