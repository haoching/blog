import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_IMAGE_BYTES,
  assertImageSize,
  collectReferencedImages,
  detectImageType,
  replaceImageSources,
} from "../src/images.js";

test("collects draft, published, external, and feature images once", () => {
  const raw = `---
title: Images
slug: images
featureimage: https://edit.chang929.site/uploads/feature
---
![draft](https://edit.chang929.site/uploads/draft)
![published](https://media.chang929.site/posts/images/a.png)
![external](https://example.com/a.jpg)
![duplicate](https://edit.chang929.site/uploads/draft)`;
  assert.deepEqual(collectReferencedImages(raw, "edit.chang929.site", "https://media.chang929.site"), [
    { source: "https://edit.chang929.site/uploads/draft", kind: "draft" },
    { source: "https://media.chang929.site/posts/images/a.png", kind: "published" },
    { source: "https://example.com/a.jpg", kind: "external" },
    { source: "https://edit.chang929.site/uploads/feature", kind: "draft" },
  ]);
});

test("validates image signatures and content types", () => {
  const png = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const jpg = Buffer.from([0xff, 0xd8, 0xff]);
  const webp = Buffer.from("RIFF0000WEBP", "ascii");
  const gif = Buffer.from("GIF89a", "ascii");
  assert.deepEqual(detectImageType(png, "image/png", "draft"), { extension: "png", mime: "image/png" });
  assert.deepEqual(detectImageType(jpg, "image/jpeg", "draft"), { extension: "jpg", mime: "image/jpeg" });
  assert.deepEqual(detectImageType(webp, "image/webp", "draft"), { extension: "webp", mime: "image/webp" });
  assert.deepEqual(detectImageType(gif, "image/gif", "draft"), { extension: "gif", mime: "image/gif" });
  assert.throws(() => detectImageType(png, "image/svg+xml", "draft"), /Unsupported or mismatched/);
  assert.throws(() => detectImageType(Buffer.from("<svg></svg>"), "image/svg+xml", "draft"), /Unsupported or mismatched/);
});

test("rejects images over 10 MB", () => {
  assert.doesNotThrow(() => assertImageSize(MAX_IMAGE_BYTES));
  assert.throws(() => assertImageSize(MAX_IMAGE_BYTES + 1), /10 MB/);
});

test("rewrites Markdown and feature images", () => {
  const source = "https://edit.chang929.site/uploads/a";
  const target = "https://media.chang929.site/posts/images/hash.png";
  const raw = `---\ntitle: Images\nslug: images\nfeatureimage: ${source}\n---\n![a](${source})`;
  const rewritten = replaceImageSources(raw, new Map([[source, target]]));
  assert.equal(rewritten.includes(source), false);
  assert.equal(rewritten.match(new RegExp(target.replaceAll(".", "\\."), "g"))?.length, 2);
});
