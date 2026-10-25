import test from "node:test";
import assert from "node:assert/strict";
import Fastify from "fastify";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { registerUnemployment } from "./unemployment.js";

test("padmin bridge preserves admin boundary, signature, body and status", async () => {
  const secret = randomBytes(32).toString("hex");
  const upstream = Fastify(),
    app = Fastify();
  let calls = 0;
  let html = "<h1>Workbench version 1</h1>";
  upstream.get("/padmin/unemployment/workbench/*", async (req,reply) => {
    assert.equal(req.headers.authorization, undefined);
    assert.equal(req.headers.cookie, undefined);
    const rel=(req.params as {"*":string})["*"];
    if (rel === "index.html") return reply.type("text/html").send(html);
    if (rel === "assets/index-a.js") return reply.type("text/javascript").send("console.log('fixture')");
    return reply.code(404).send({error:"missing"});
  });
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
    const page = await app.inject({url:"/padmin/unemployment/workbench/index.html?embedded=1&section=contents",headers});
    assert.equal(page.statusCode, 200);
    assert.match(page.headers["content-type"]!, /text\/html/);
    assert.equal(page.headers["cache-control"],"no-store");
    assert.match(page.body,/version 1/);
    html = "<h1>Workbench version 2</h1>";
    assert.match((await app.inject("/padmin/unemployment/workbench/index.html?embedded=1")).body,/version 2/);
    const js=await app.inject("/padmin/unemployment/workbench/assets/index-a.js");
    assert.equal(js.statusCode,200);
    assert.match(js.headers["content-type"]!,/text\/javascript/);
    assert.match(js.headers["cache-control"]!,/immutable/);
    assert.equal((await app.inject("/padmin/unemployment/workbench/assets/missing.js")).statusCode,404);
    assert.equal(
      (await app.inject("/padmin/unemployment/workbench/%2e%2e/package.json"))
        .statusCode,
      404,
    );
  } finally {
    await app.close();
    await upstream.close();
  }
});

test("unconfigured bridge gives an actionable admin error", async () => {
  const app = Fastify();
  registerUnemployment(app, {
    actor: () => "admin@example.test",
  });
  try {
    assert.equal(
      (await app.inject("/padmin/api/unemployment/users")).statusCode,
      503,
    );
    assert.equal((await app.inject("/padmin/unemployment/workbench/index.html")).statusCode,503);
  } finally {
    await app.close();
  }
});
