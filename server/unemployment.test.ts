import test from "node:test";
import assert from "node:assert/strict";
import Fastify from "fastify";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { registerUnemployment } from "./unemployment.js";

test("padmin bridge preserves admin boundary, signature, body and status", async () => {
  const secret = randomBytes(32).toString("hex"),
    root = await mkdtemp(path.join(os.tmpdir(), "uh-workbench-"));
  await writeFile(path.join(root, "index.html"), "<h1>Workbench fixture</h1>");
  const upstream = Fastify(),
    app = Fastify();
  let calls = 0;
  upstream.all("/api/v1/admin/*", async (req, reply) => {
    calls++;
    const h = req.headers,
      hash = createHash("sha256")
        .update(JSON.stringify(req.body ?? null))
        .digest("hex");
    const expected = createHmac("sha256", secret)
      .update(
        [
          h["x-uh-time"],
          h["x-uh-nonce"],
          req.method,
          req.url,
          h["x-uh-actor"],
          hash,
        ].join("\n"),
      )
      .digest("hex");
    assert.equal(h["x-uh-signature"], expected);
    assert.equal(
      Buffer.from(String(h["x-uh-actor"]), "base64url").toString(),
      "admin@example.test",
    );
    assert.equal(h.authorization, undefined);
    assert.equal(h.cookie, undefined);
    if (req.url.endsWith("/contents/conflict"))
      return reply.code(409).send({ message: "版本冲突" });
    return {
      data: { url: req.url, body: req.body ?? null },
      meta: { requestId: req.id },
    };
  });
  await upstream.listen({ port: 0, host: "127.0.0.1" });
  registerUnemployment(app, {
    origin: upstream.listeningOrigin,
    secret,
    workbenchDir: root,
    actor: (req) =>
      req.headers.authorization === "Bearer fixture-admin"
        ? "admin@example.test"
        : null,
  });
  const headers = {
    authorization: "Bearer fixture-admin",
    cookie: "unrelated=do-not-forward",
  };
  try {
    assert.equal(
      (await app.inject("/padmin/api/unemployment/users")).statusCode,
      401,
    );
    const read = await app.inject({
      url: "/padmin/api/unemployment/users?page=2&q=hello",
      headers,
    });
    assert.equal(read.statusCode, 200);
    assert.equal(read.json().data.url, "/api/v1/admin/users?page=2&q=hello");
    const payload = { disabledTools: ["budget"] };
    const write = await app.inject({
      method: "PUT",
      url: "/padmin/api/unemployment/settings",
      headers,
      payload,
    });
    assert.equal(write.statusCode, 200);
    assert.deepEqual(write.json().data.body, payload);
    const noBody = await app.inject({
      method: "POST",
      url: "/padmin/api/unemployment/feedback/fixture/resolve",
      headers,
    });
    assert.equal(noBody.statusCode, 200);
    assert.equal(noBody.json().data.body, null);
    const conflict = await app.inject({
      url: "/padmin/api/unemployment/contents/conflict",
      headers,
    });
    assert.equal(conflict.statusCode, 409);
    assert.equal(conflict.json().error, "版本冲突");
    const before = calls;
    for (const suffix of [
      "/login",
      "/logout",
      "/users/../logout",
      "/users/%2e%2e/logout",
      "/unknown",
    ])
      assert.equal(
        (
          await app.inject({
            url: "/padmin/api/unemployment" + suffix,
            headers,
          })
        ).statusCode,
        404,
      );
    assert.equal(calls, before);
    const html = await app.inject("/padmin/unemployment/workbench/index.html");
    assert.equal(html.statusCode, 200);
    assert.match(html.headers["content-type"]!, /text\/html/);
    assert.equal(
      (await app.inject("/padmin/unemployment/workbench/%2e%2e/package.json"))
        .statusCode,
      404,
    );
  } finally {
    await app.close();
    await upstream.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("unconfigured bridge gives an actionable admin error", async () => {
  const app = Fastify();
  registerUnemployment(app, {
    workbenchDir: "/not-used",
    actor: () => "admin@example.test",
  });
  try {
    assert.equal(
      (await app.inject("/padmin/api/unemployment/users")).statusCode,
      503,
    );
  } finally {
    await app.close();
  }
});
