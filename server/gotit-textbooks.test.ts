import test from "node:test";
import assert from "node:assert/strict";
import { currentGotItTextbook, summarizeGotItTextbooks } from "./gotit-textbooks.js";

test("current textbook handles welcome, starter and zero-padded units", () => {
  assert.equal(currentGotItTextbook("rj:required-1:uwelcome")?.bookName, "必修第一册");
  assert.equal(currentGotItTextbook("rj:grade-7-1:ustarter-1")?.bookName, "七年级上册");
  assert.equal(currentGotItTextbook("bb-junior:alpha:u01")?.publisherName, "中考2000词");
  for (const id of [null, "", "rj:required-1", "rj:required-1:u999", "new:required-1:u1"]) {
    assert.equal(currentGotItTextbook(id), null);
  }
});

test("counts current users by publisher and book, across different units", () => {
  const stats = summarizeGotItTextbooks([
    { selected_unit_id: "rj:required-1:u1", users: 3 },
    { selected_unit_id: "rj:required-1:u2", users: 2 },
    { selected_unit_id: "shj:required-1:u1", users: 4 },
    { selected_unit_id: "rj:required-2:u1", users: 1 },
    { selected_unit_id: "", users: 2 },
    { selected_unit_id: null, users: 1 },
    { selected_unit_id: "removed:old:u1", users: 2 },
  ]);
  assert.deepEqual(stats.textbooks.map(({ key, users }) => ({ key, users })), [
    { key: "rj:required-1", users: 5 },
    { key: "shj:required-1", users: 4 },
    { key: "rj:required-2", users: 1 },
  ]);
  assert.equal(stats.totalUsers, 15);
  assert.equal(stats.selectedUsers, 10);
  assert.equal(stats.unselectedUsers, 3);
  assert.equal(stats.unknownUsers, 2);
  assert.equal(stats.totalUsers, stats.selectedUsers + stats.unselectedUsers + stats.unknownUsers);
  assert.equal(stats.selectedUsers, stats.textbooks.reduce((sum, row) => sum + row.users, 0));
});

test("switching textbooks moves a user to their current book only", () => {
  const before = summarizeGotItTextbooks([{ selected_unit_id: "rj:required-1:u1", users: 1 }]);
  const after = summarizeGotItTextbooks([{ selected_unit_id: "shj:required-1:u1", users: 1 }]);
  assert.equal(before.textbooks[0].key, "rj:required-1");
  assert.equal(after.textbooks.length, 1);
  assert.equal(after.textbooks[0].key, "shj:required-1");
  assert.equal(after.totalUsers, 1);
});

test("empty database returns zero counts", () => {
  assert.deepEqual(summarizeGotItTextbooks([]), {
    totalUsers: 0,
    selectedUsers: 0,
    unselectedUsers: 0,
    unknownUsers: 0,
    textbooks: [],
  });
});
