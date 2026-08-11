import assert from "node:assert/strict";
import test from "node:test";
import { normalizeLegacyMarkdown } from "../src/markdown.js";
import { validateFrontmatter } from "../src/validation.js";

test("rejects HedgeDoc code-fence modifiers with a line number", () => {
  const article = "---\ntitle: Syntax\nslug: syntax\n---\ntext\n```python!\npass\n```";
  assert.throws(() => validateFrontmatter(article), /HedgeDoc-only syntax at line 2/);
});

test("normalizes legacy HedgeDoc code-fence modifiers before migration", () => {
  assert.equal(normalizeLegacyMarkdown("```python!\npass\n```\n```!\nraw\n```"), "```python\npass\n```\n```\nraw\n```");
});
