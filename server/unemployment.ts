import { createHash, createHmac, randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
type Options = {
  origin?: string;
  secret?: string;
  actor: (req: FastifyRequest) => string | null;
};
export function registerUnemployment(app: FastifyInstance, options: Options) {
  const prefix = "/padmin/api/unemployment";
  app.all(prefix + "/*", { bodyLimit: 300000 }, async (req, reply) => {
    const actor = options.actor(req);
    if (!actor) return reply.code(401).send({ error: "请先登录管理后台" });
    if (!options.origin || !options.secret || options.secret.length < 32)
      return reply.code(503).send({ error: "失业有数后台连接尚未配置" });
    const suffix = req.url.slice(prefix.length);
    if (
      !/^\/(me|users|activity|contents|sources|feedback|audit|settings|home-sections|benefit-policy|insurance-policies|training-catalog)(?:[/?]|$)/.test(
        suffix,
      )
    )
      return reply.code(404).send({ error: "接口不存在" });
    const pathname = suffix.split("?")[0];
    try {
      if (
        decodeURIComponent(pathname)
          .split("/")
          .some((v) => v === "." || v === "..")
      )
        return reply.code(404).send({ error: "接口不存在" });
    } catch {
      return reply.code(404).send({ error: "接口不存在" });
    }
    let target: URL;
    try {
      target = new URL("/api/v1/admin" + suffix, options.origin);
      if (
        !["http:", "https:"].includes(target.protocol) ||
        !target.pathname.startsWith("/api/v1/admin/")
      )
        throw new Error();
    } catch {
      return reply.code(503).send({ error: "失业有数后台地址配置无效" });
    }
    const timestamp = String(Date.now()),
      nonce = randomBytes(16).toString("hex"),
      actorHeader = Buffer.from(actor).toString("base64url");
    const hash = createHash("sha256")
      .update(JSON.stringify(req.body ?? null))
      .digest("hex");
    const signature = createHmac("sha256", options.secret)
      .update(
        [
          timestamp,
          nonce,
          req.method,
          target.pathname + target.search,
          actorHeader,
          hash,
        ].join("\n"),
      )
      .digest("hex");
    try {
      const response = await fetch(target, {
        method: req.method,
        redirect: "error",
        signal: AbortSignal.timeout(15000),
        headers: {
          ...(req.body === undefined ? {} : { "Content-Type": "application/json" }),
          "X-UH-Time": timestamp,
          "X-UH-Nonce": nonce,
          "X-UH-Actor": actorHeader,
          "X-UH-Signature": signature,
        },
        body:
          req.method === "GET" ||
          req.method === "HEAD" ||
          req.body === undefined
            ? undefined
            : JSON.stringify(req.body),
      });
      const data = (await response.json()) as {
        message?: string;
        error?: string;
      };
      reply.header("Cache-Control", "no-store");
      return reply
        .code(response.status)
        .send(
          response.ok
            ? data
            : {
                ...data,
                error: data.message || data.error || "失业有数服务暂不可用",
              },
        );
    } catch {
      return reply
        .code(502)
        .send({ error: "无法连接失业有数服务，请稍后重试" });
    }
  });
  app.get("/padmin/unemployment/workbench/*", async (req, reply) => {
    const relative = (req.params as { "*": string })["*"] || "index.html";
    if (relative !== "index.html" && !/^assets\/[\w.-]+\.(js|css)$/.test(relative))
      return reply.code(404).send({ error: "文件不存在" });
    if (!options.origin) return reply.code(503).send({ error: "失业有数后台连接尚未配置" });
    let target: URL;
    try {
      target = new URL("/padmin/unemployment/workbench/" + relative, options.origin);
      if (!["http:", "https:"].includes(target.protocol)) throw new Error();
    } catch {
      return reply.code(503).send({ error: "失业有数后台地址配置无效" });
    }
    try {
      const response = await fetch(target, {redirect:"error",signal:AbortSignal.timeout(15000)});
      reply.header("Cache-Control", response.ok && relative !== "index.html" ? "public, max-age=31536000, immutable" : "no-store");
      reply.header("X-Content-Type-Options", "nosniff");
      return reply.code(response.status).type(response.headers.get("content-type") || "application/octet-stream").send(Buffer.from(await response.arrayBuffer()));
    } catch {
      return reply.code(502).send({ error: "无法连接失业有数服务，请稍后重试" });
    }
  });
}
