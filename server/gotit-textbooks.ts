import { gotitTextbookCatalog } from "./gotit-textbook-catalog.js";

type GotItTextbook = Omit<(typeof gotitTextbookCatalog)[number], "unitKeys">;

const textbooksByUnitId = new Map<string, GotItTextbook>(gotitTextbookCatalog.flatMap(({ unitKeys, ...book }) =>
  unitKeys.map((key) => [`${book.publisherId}:${book.bookId}:u${key}`, book] as const)
));

export function currentGotItTextbook(selectedUnitId: string | null) {
  return textbooksByUnitId.get(selectedUnitId ?? "") ?? null;
}

export function summarizeGotItTextbooks(groups: Array<{ selected_unit_id: string | null; users: number }>) {
  let totalUsers = 0;
  let selectedUsers = 0;
  let unselectedUsers = 0;
  let unknownUsers = 0;
  const textbooks = new Map<string, GotItTextbook & { key: string; users: number }>();

  for (const group of groups) {
    const users = Number(group.users);
    totalUsers += users;
    if (!group.selected_unit_id) {
      unselectedUsers += users;
      continue;
    }
    const book = currentGotItTextbook(group.selected_unit_id);
    if (!book) {
      unknownUsers += users;
      continue;
    }
    selectedUsers += users;
    const key = `${book.publisherId}:${book.bookId}`;
    const existing = textbooks.get(key);
    if (existing) existing.users += users;
    else textbooks.set(key, { ...book, key, users });
  }

  return {
    totalUsers,
    selectedUsers,
    unselectedUsers,
    unknownUsers,
    textbooks: [...textbooks.values()].sort((a, b) => b.users - a.users || a.key.localeCompare(b.key)),
  };
}
