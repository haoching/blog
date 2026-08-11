import assert from "node:assert/strict";
import test from "node:test";
import { slugIsValid, validateFrontmatter } from "../src/validation.js";

test("accepts the documented frontmatter contract", () => {
  const article = validateFrontmatter(`---\ntitle: Test\nslug: valid-slug\ntags: [ctf]\ncategories: [Security]\n---\n\n本文`);
  assert.equal(article.slug, "valid-slug");
  assert.equal(article.title, "Test");
  assert.equal(article.content.trim(), "本文");
});

test("rejects invalid or non-English slugs", () => {
  for (const slug of ["", "大寫", "has--two", "has space", "UPPER"]) {
    assert.equal(slugIsValid(slug), false, slug);
  }
  assert.throws(() => validateFrontmatter("---\ntitle: Missing slug\n---\n本文"), /slug/);
});

test("rejects object-valued tag fields", () => {
  assert.throws(() => validateFrontmatter("---\ntitle: Bad\nslug: bad\ntags: {foo: bar}\n---\n本文"), /tags must be an array/);
});

test("reports HedgeDoc-only syntax with a line number", () => {
  assert.throws(() => validateFrontmatter("---\ntitle: Syntax\nslug: syntax\n---\n本文\n[toc]"), /HedgeDoc-only syntax at line 2/);
});
