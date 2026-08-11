import assert from "node:assert/strict";
import test from "node:test";
import { validateFrontmatter } from "../src/validation.js";

test("rejects HedgeDoc code-fence modifiers with a line number", () => {
  const article = "---\ntitle: Syntax\nslug: syntax\n---\ntext\n```python!\npass\n```";
  assert.throws(() => validateFrontmatter(article), /HedgeDoc-only syntax at line 2/);
});
