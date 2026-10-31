import { readFile, writeFile } from "node:fs/promises";

// Run after GotIt's textbook manifest changes: node scripts/sync-gotit-textbooks.mjs
const manifest = JSON.parse(await readFile(new URL("../../GotIt/src/data/wordbank.manifest.json", import.meta.url), "utf8"));
const textbooks = manifest.publishers.flatMap(({ publisher, books }) => books.map((book) => ({
  publisherId: publisher.id,
  publisherName: publisher.name,
  bookId: book.id,
  bookName: book.name,
  unitKeys: book.units.map((unit) => unit.key ?? String(unit.number)),
})));
await writeFile(new URL("../server/gotit-textbook-catalog.ts", import.meta.url), [
  "// Generated from GotIt/src/data/wordbank.manifest.json. Regenerate with node scripts/sync-gotit-textbooks.mjs",
  "export const gotitTextbookCatalog = [",
  ...textbooks.map((book) => `  ${JSON.stringify(book)},`),
  "];",
  "",
].join("\n"));
console.log(`Synced ${textbooks.length} GotIt textbooks`);
