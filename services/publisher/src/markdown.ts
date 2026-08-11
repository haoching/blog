export function normalizeLegacyMarkdown(raw: string): string {
  return raw.replace(/^(\s*```[a-z0-9_-]*)!\s*$/gim, "$1");
}
