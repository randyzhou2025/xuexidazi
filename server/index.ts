import "dotenv/config";
import { createHmac, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";
import postgres from "postgres";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const padminDist = path.join(projectRoot, "dist/padmin");
const logoDir = path.join(projectRoot, "logo");
const assetsDir = path.join(projectRoot, "assets");

const coreDatabaseUrl = process.env.XUEXIDAZI_DATABASE_URL ?? process.env.EXAM_DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET ?? "";
if (!coreDatabaseUrl) throw new Error("XUEXIDAZI_DATABASE_URL is required");
if (!jwtSecret || jwtSecret.length < 16) throw new Error("JWT_SECRET must be at least 16 chars");

const coreSql = postgres(coreDatabaseUrl, { max: 10 });
const ptoeSql = process.env.PTOE_DATABASE_URL ? postgres(process.env.PTOE_DATABASE_URL, { max: 10 }) : null;
const gotitSql = process.env.GOTIT_DATABASE_URL ? postgres(process.env.GOTIT_DATABASE_URL, { max: 10 }) : null;
const ptoeSessionSecret = process.env.PTOE_SESSION_SECRET ?? "";
const ptoeIdleReleaseDays = Number(process.env.PTOE_IDLE_RELEASE_DAYS ?? 30);
const ptoeMaxDevicesDefault = Number(process.env.PTOE_MAX_DEVICES_DEFAULT ?? 2);

interface AuthUser {
  id: string;
  email: string;
  displayName: string | null;
  role: string;
  isAuthorized: boolean;
  createdAt: string;
  subscriptionExpiresOn: string | null;
}

interface JwtPayload {
  sub: string;
  role: string;
}

function toIso(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  return new Date(String(value)).toISOString();
}

function toDateOnly(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function publicUser(row: Record<string, unknown>): AuthUser {
  return {
    id: String(row.id),
    email: String(row.email),
    displayName: row.display_name == null ? null : String(row.display_name),
    role: String(row.role),
    isAuthorized: Boolean(row.is_authorized),
    createdAt: toIso(row.created_at) ?? "",
    subscriptionExpiresOn: toDateOnly(row.subscription_expires_on),
  };
}

function signToken(user: { id: string; role: string }): string {
  return jwt.sign({ sub: user.id, role: user.role }, jwtSecret, {
    expiresIn: process.env.JWT_EXPIRES_IN ?? "7d",
  } as jwt.SignOptions);
}

function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice("Bearer ".length);
}

async function userFromToken(request: FastifyRequest): Promise<AuthUser | null> {
  const token = bearerToken(request);
  if (!token) return null;
  let payload: JwtPayload;
  try {
    payload = jwt.verify(token, jwtSecret) as unknown as JwtPayload;
  } catch {
    return null;
  }
  const rows = await coreSql`
    select id, email, display_name, role, is_authorized, created_at, subscription_expires_on
    from users
    where id = ${payload.sub}
    limit 1
  `;
  return rows[0] ? publicUser(rows[0]) : null;
}

async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const user = await userFromToken(request);
  if (!user) {
    await reply.code(401).send({ error: "未登录或令牌无效" });
    return;
  }
  if (user.role !== "admin") {
    await reply.code(403).send({ error: "需要管理员权限" });
    return;
  }
  request.adminUser = user;
}

function requirePtoe(reply: FastifyReply) {
  if (!ptoeSql) {
    reply.code(503).send({ error: "PTOE_DATABASE_URL 未配置，PeriodicTable 管理功能不可用" });
    return null;
  }
  if (!ptoeSessionSecret || ptoeSessionSecret.length < 32) {
    reply.code(503).send({ error: "PTOE_SESSION_SECRET 未配置或长度不足" });
    return null;
  }
  return ptoeSql;
}

function requireGotit(reply: FastifyReply) {
  if (!gotitSql) {
    reply.code(503).send({ error: "GOTIT_DATABASE_URL 未配置，课本单词通管理功能不可用" });
    return null;
  }
  return gotitSql;
}

function maskOpenId(openid: string): string {
  if (openid.length <= 8) return "***";
  return `${openid.slice(0, 4)}***${openid.slice(-4)}`;
}

function shanghaiDateString(date = new Date()): string {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function validDateOnly(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function dateKeyAfter(dateKey: string, days: number): string {
  const cursor = new Date(`${dateKey}T12:00:00+08:00`);
  cursor.setUTCDate(cursor.getUTCDate() + days);
  return shanghaiDateString(cursor);
}

function shanghaiWeekContext(now = new Date()) {
  const dateKey = shanghaiDateString(now);
  const current = new Date(`${dateKey}T12:00:00+08:00`);
  const weekday = current.getUTCDay() || 7;
  const mondayKey = dateKeyAfter(dateKey, 1 - weekday);
  const sundayKey = dateKeyAfter(mondayKey, 6);
  const thursdayKey = dateKeyAfter(mondayKey, 3);
  const weekYear = Number(thursdayKey.slice(0, 4));
  const januaryFourthKey = `${weekYear}-01-04`;
  const janFourth = new Date(`${januaryFourthKey}T12:00:00+08:00`);
  const janFourthWeekday = janFourth.getUTCDay() || 7;
  const firstMondayKey = dateKeyAfter(januaryFourthKey, 1 - janFourthWeekday);
  const weekNumber =
    Math.floor(
      (new Date(`${mondayKey}T12:00:00+08:00`).getTime() -
        new Date(`${firstMondayKey}T12:00:00+08:00`).getTime()) /
        604_800_000
    ) + 1;
  return {
    dateKey,
    weekKey: `${weekYear}-W${String(weekNumber).padStart(2, "0")}`,
    weekStart: mondayKey,
    weekEnd: sundayKey,
    weekStartIso: `${mondayKey}T00:00:00+08:00`,
    weekEndIso: `${sundayKey}T23:59:59.999+08:00`,
  };
}

type GotitLeaderboardMetric = "time" | "words" | "power";
type GotitLeaderboardPeriod = "week" | "total";

function parseGotitLeaderboardMetric(value: unknown): GotitLeaderboardMetric | null {
  return value === "time" || value === "words" || value === "power" ? value : null;
}

function parseGotitLeaderboardPeriod(value: unknown): GotitLeaderboardPeriod | null {
  return value === "week" || value === "total" ? value : null;
}

function formatLeaderboardDisplayValue(metric: GotitLeaderboardMetric, value: number): string {
  if (metric === "time") {
    const minutes = Math.floor(value / 60);
    return minutes > 0 && value < 60 ? "<1 分钟" : `${minutes.toLocaleString("zh-CN")} 分钟`;
  }
  if (metric === "words") return `${value.toLocaleString("zh-CN")} 词`;
  return `${value.toLocaleString("zh-CN")} 分`;
}

function addDays(date: Date, days: number): Date {
  const next = new Date(date);
  next.setDate(next.getDate() + days);
  return next;
}

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function generateLicenseCode(): { normalized: string; formatted: string } {
  let suffix = "";
  for (let i = 0; i < 8; i += 1) {
    suffix += ALPHABET[randomBytes(1)[0]! % ALPHABET.length];
  }
  const normalized = `PTOE${suffix}`;
  return {
    normalized,
    formatted: `PTOE-${suffix.slice(0, 4)}-${suffix.slice(4)}`,
  };
}

function hashLicenseCode(normalizedCode: string): string {
  return createHmac("sha256", ptoeSessionSecret).update(`license:${normalizedCode}`).digest("hex");
}

function codePrefixFromNormalized(normalized: string): string {
  const suffix = normalized.slice(4);
  return `PTOE-${suffix.slice(0, 4)}`;
}

const jkExamProjectIds = [
  "jk-exam-fire-operator",
  "jk-exam-special-operation",
  "jk-exam-ai-trainer",
  "jk-exam-network-security-admin",
  "jk-exam-omni-media-operator",
  "jk-exam-ecommerce-specialist",
  "jk-exam-internet-marketer",
  "jk-exam-elderly-care-worker",
  "jk-exam-domestic-worker",
] as const;

const jkExamLabels: Record<string, string> = {
  "jk-exam-fire-operator": "消防设施操作员",
  "jk-exam-special-operation": "特种作业人员",
  "jk-exam-ai-trainer": "人工智能训练师",
  "jk-exam-network-security-admin": "网络与信息安全管理员",
  "jk-exam-omni-media-operator": "全媒体运营师",
  "jk-exam-ecommerce-specialist": "电子商务师",
  "jk-exam-internet-marketer": "互联网营销师",
  "jk-exam-elderly-care-worker": "养老护理员",
  "jk-exam-domestic-worker": "家政服务员",
};

function buildProjectSummaries(rows: Array<{ project_id: string; unique_visitors: number; total_clicks: number }>) {
  const byId = new Map(rows.map((row) => [row.project_id, row]));
  const pick = (id: string) => byId.get(id) ?? { project_id: id, unique_visitors: 0, total_clicks: 0 };
  const jkExams = jkExamProjectIds.map((id) => {
    const s = pick(id);
    return { projectId: id, label: jkExamLabels[id], uniqueVisitors: s.unique_visitors, totalClicks: s.total_clicks };
  });
  const jkTotal = jkExams.reduce(
    (sum, item) => ({
      uniqueVisitors: sum.uniqueVisitors + item.uniqueVisitors,
      totalClicks: sum.totalClicks + item.totalClicks,
    }),
    { uniqueVisitors: 0, totalClicks: 0 }
  );
  const examprep = pick("examprep");
  const promptTool = pick("prompt-tool");
  const privacyOnline = pick("privacy-blur-online");
  const privacyDownload = pick("privacy-blur-download");
  return [
    {
      projectId: "jinengkao-exams",
      label: "技能考 · 考试详情（上海站）",
      uniqueVisitors: jkTotal.uniqueVisitors,
      totalClicks: jkTotal.totalClicks,
      breakdown: Object.fromEntries(jkExams.map((item) => [item.projectId, item])),
    },
    { projectId: "examprep", label: "ExamMaster", uniqueVisitors: examprep.unique_visitors, totalClicks: examprep.total_clicks },
    { projectId: "prompt-tool", label: "AI提示词生成助手", uniqueVisitors: promptTool.unique_visitors, totalClicks: promptTool.total_clicks },
    {
      projectId: "privacy-blur",
      label: "PrivacyBlur",
      uniqueVisitors: privacyOnline.unique_visitors + privacyDownload.unique_visitors,
      totalClicks: privacyOnline.total_clicks + privacyDownload.total_clicks,
      breakdown: {
        online: { label: "打开在线版", uniqueVisitors: privacyOnline.unique_visitors, totalClicks: privacyOnline.total_clicks },
        download: { label: "下载本地版", uniqueVisitors: privacyDownload.unique_visitors, totalClicks: privacyDownload.total_clicks },
      },
    },
  ];
}

function clientIp(request: FastifyRequest): string {
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) return forwarded.split(",")[0]!.trim();
  const realIp = request.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.length > 0) return realIp.trim();
  return request.ip ?? "unknown";
}

async function sendStatic(reply: FastifyReply, file: string): Promise<void> {
  const ext = path.extname(file);
  const type =
    ext === ".html"
      ? "text/html; charset=utf-8"
      : ext === ".css"
        ? "text/css; charset=utf-8"
      : ext === ".js"
        ? "text/javascript; charset=utf-8"
      : ext === ".txt"
        ? "text/plain; charset=utf-8"
      : ext === ".xml"
        ? "application/xml; charset=utf-8"
        : ext === ".webmanifest" || ext === ".json"
          ? "application/manifest+json; charset=utf-8"
          : ext === ".png"
          ? "image/png"
          : ext === ".jpg" || ext === ".jpeg"
            ? "image/jpeg"
            : ext === ".webp"
              ? "image/webp"
              : ext === ".ico"
                ? "image/x-icon"
          : ext === ".svg"
            ? "image/svg+xml"
            : "application/octet-stream";
  const body = await fs.readFile(file);
  reply.type(type).send(body);
}

declare module "fastify" {
  interface FastifyRequest {
    adminUser?: AuthUser;
  }
}

const app = Fastify({ logger: true });

app.addHook("preHandler", async (request, reply) => {
  if (!request.url.startsWith("/padmin/api/")) return;
  const open = request.url === "/padmin/api/auth/login" || request.url === "/padmin/api/health";
  if (!open) await requireAdmin(request, reply);
});

app.get("/padmin/api/health", async () => ({ ok: true }));

app.post("/api/auth/login", async (request, reply) => {
  const body = request.body as { email?: string; password?: string };
  const email = body.email?.trim().toLowerCase();
  if (!email || !body.password) return reply.code(400).send({ error: "请求参数无效" });
  const rows = await coreSql`select * from users where email = ${email} limit 1`;
  const row = rows[0];
  if (!row || !row.password_hash || !(await bcrypt.compare(body.password, String(row.password_hash)))) {
    return reply.code(401).send({ error: "邮箱或密码错误" });
  }
  const user = publicUser(row);
  await coreSql`
    insert into login_logs (user_id, username, ip, location)
    values (${user.id}, ${user.email}, ${clientIp(request)}, ${"未知"})
  `;
  return reply.send({ token: signToken(user), user });
});

app.post("/api/auth/register", async (request, reply) => {
  const body = request.body as { email?: string; password?: string; displayName?: string };
  const email = body.email?.trim().toLowerCase();
  if (!email || !body.password || body.password.length < 8) return reply.code(400).send({ error: "请求参数无效" });
  const exists = await coreSql`select id from users where email = ${email} limit 1`;
  if (exists.length > 0) return reply.code(409).send({ error: "该邮箱已注册" });
  const passwordHash = await bcrypt.hash(body.password, 10);
  const rows = await coreSql`
    insert into users (email, password_hash, display_name, role, is_authorized)
    values (${email}, ${passwordHash}, ${body.displayName?.trim() || null}, ${"user"}, ${false})
    returning id, email, display_name, role, is_authorized, created_at, subscription_expires_on
  `;
  const user = publicUser(rows[0]!);
  await coreSql`
    insert into login_logs (user_id, username, ip, location)
    values (${user.id}, ${user.email}, ${clientIp(request)}, ${"未知"})
  `;
  return reply.send({ token: signToken(user), user });
});

app.get("/api/auth/me", async (request, reply) => {
  const user = await userFromToken(request);
  if (!user) return reply.code(401).send({ error: "未登录或令牌无效" });
  return reply.send({ user });
});

app.post("/padmin/api/auth/login", async (request, reply) => {
  const body = request.body as { email?: string; password?: string };
  const email = body.email?.trim().toLowerCase();
  if (!email || !body.password) return reply.code(400).send({ error: "请输入邮箱和密码" });
  const rows = await coreSql`select * from users where email = ${email} limit 1`;
  const row = rows[0];
  if (!row || !row.password_hash || !(await bcrypt.compare(body.password, String(row.password_hash)))) {
    return reply.code(401).send({ error: "邮箱或密码错误" });
  }
  const user = publicUser(row);
  if (user.role !== "admin") return reply.code(403).send({ error: "需要管理员权限" });
  await coreSql`
    insert into login_logs (user_id, username, ip, location)
    values (${user.id}, ${user.email}, ${clientIp(request)}, ${"未知"})
  `;
  return reply.send({ token: signToken(user), user });
});

app.get("/padmin/api/auth/me", async (request) => ({ user: request.adminUser }));

app.get("/padmin/api/summary", async () => {
  const today = shanghaiDateString();
  const [users, active, ptoeCodes, ptoeSessions, gotitUsers, gotitTodayActive, gotitTodayRegistered] = await Promise.all([
    coreSql`select count(*)::int as total from users`,
    coreSql`select count(*)::int as total from user_daily_activity where activity_date = ${today}`,
    ptoeSql ? ptoeSql`select count(*)::int as total from license_codes` : Promise.resolve([{ total: 0 }]),
    ptoeSql ? ptoeSql`select count(*)::int as total from sessions where expires_at > now()` : Promise.resolve([{ total: 0 }]),
    gotitSql ? gotitSql`select count(*)::int as total from users` : Promise.resolve([{ total: 0 }]),
    gotitSql
      ? gotitSql`select count(distinct user_id)::int as total from user_daily_stats where stat_date = ${today}::date`
      : Promise.resolve([{ total: 0 }]),
    gotitSql
      ? gotitSql`select count(*)::int as total from users where (created_at at time zone 'Asia/Shanghai')::date = ${today}::date`
      : Promise.resolve([{ total: 0 }]),
  ]);
  return {
    users: users[0]?.total ?? 0,
    todayActive: active[0]?.total ?? 0,
    licenseCodes: ptoeCodes[0]?.total ?? 0,
    activePtoeSessions: ptoeSessions[0]?.total ?? 0,
    gotitUsers: gotitUsers[0]?.total ?? 0,
    gotitTodayActive: gotitTodayActive[0]?.total ?? 0,
    gotitTodayRegistered: gotitTodayRegistered[0]?.total ?? 0,
  };
});

app.get("/padmin/api/studymate/users", async (request) => {
  const query = request.query as { page?: string; pageSize?: string; q?: string };
  const page = Math.max(1, Number(query.page ?? 1));
  const pageSize = Math.min(100, Math.max(1, Number(query.pageSize ?? 20)));
  const offset = (page - 1) * pageSize;
  const q = query.q?.trim();
  const pattern = q ? `%${q}%` : "";
  const rows = q
    ? await coreSql`
        select id, email, display_name, role, is_authorized, created_at, last_active_at, last_active_ip, subscription_expires_on
        from users
        where email ilike ${pattern} or coalesce(display_name, '') ilike ${pattern}
        order by created_at desc
        limit ${pageSize} offset ${offset}
      `
    : await coreSql`
        select id, email, display_name, role, is_authorized, created_at, last_active_at, last_active_ip, subscription_expires_on
        from users
        order by created_at desc
        limit ${pageSize} offset ${offset}
      `;
  const totals = q
    ? await coreSql`
        select count(*)::int as total from users
        where email ilike ${pattern} or coalesce(display_name, '') ilike ${pattern}
      `
    : await coreSql`select count(*)::int as total from users`;
  const today = shanghaiDateString();
  const [todayActive, todayRegistered] = await Promise.all([
    coreSql`select count(*)::int as total from user_daily_activity where activity_date = ${today}`,
    coreSql`select count(*)::int as total from users where (created_at at time zone 'Asia/Shanghai')::date = ${today}::date`,
  ]);
  const total = totals[0]?.total ?? 0;
  return {
    users: rows.map((row) => ({
      ...publicUser(row),
      lastActiveAt: toIso(row.last_active_at),
      lastActiveIp: row.last_active_ip ?? null,
    })),
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
    todayActiveCount: todayActive[0]?.total ?? 0,
    todayRegisteredCount: todayRegistered[0]?.total ?? 0,
  };
});

app.patch("/padmin/api/studymate/users/:id", async (request, reply) => {
  const { id } = request.params as { id: string };
  const body = request.body as { isAuthorized?: boolean; subscriptionExpiresOn?: string | null };
  const current = await coreSql`
    select id, email, display_name, role, is_authorized, created_at, subscription_expires_on
    from users
    where id = ${id}
    limit 1
  `;
  if (!current[0]) return reply.code(404).send({ error: "用户不存在" });
  if (current[0].role === "admin") return reply.code(400).send({ error: "管理员账号不能在此修改授权" });
  const hasAuth = Object.prototype.hasOwnProperty.call(body, "isAuthorized");
  const hasSub = Object.prototype.hasOwnProperty.call(body, "subscriptionExpiresOn");
  if (!hasAuth && !hasSub) return reply.code(400).send({ error: "无可更新字段" });
  if (hasSub && body.subscriptionExpiresOn !== null && !validDateOnly(String(body.subscriptionExpiresOn))) {
    return reply.code(400).send({ error: "订阅到期日格式无效" });
  }
  const updated = await coreSql`
    update users
    set
      is_authorized = ${hasAuth ? Boolean(body.isAuthorized) : Boolean(current[0].is_authorized)},
      subscription_expires_on = ${hasSub ? body.subscriptionExpiresOn : current[0].subscription_expires_on}
    where id = ${id}
    returning id, email, display_name, role, is_authorized, created_at, last_active_at, last_active_ip, subscription_expires_on
  `;
  return { user: { ...publicUser(updated[0]!), lastActiveAt: toIso(updated[0]!.last_active_at), lastActiveIp: updated[0]!.last_active_ip ?? null } };
});

app.get("/padmin/api/studymate/login-logs", async () => {
  const rows = await coreSql`
    select id, user_id, username, ip, location, login_at
    from login_logs
    order by login_at desc
    limit 200
  `;
  return {
    logs: rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      username: row.username,
      ip: row.ip,
      location: row.location,
      loginAt: toIso(row.login_at),
    })),
  };
});

app.get("/padmin/api/exam/daily-activity", async (request, reply) => {
  const query = request.query as { date?: string };
  const date = query.date?.trim() || shanghaiDateString();
  if (!validDateOnly(date)) return reply.code(400).send({ error: "date 须为 YYYY-MM-DD" });
  const rows = await coreSql`
    select
      a.user_id,
      u.email,
      u.display_name,
      u.created_at as registered_at,
      a.first_seen_at,
      a.last_seen_at,
      a.ping_count,
      a.last_ip,
      a.flags
    from user_daily_activity a
    inner join users u on u.id = a.user_id
    where a.activity_date = ${date}
    order by a.last_seen_at desc
  `;
  return {
    date,
    count: rows.length,
    users: rows.map((row) => ({
      userId: row.user_id,
      email: row.email,
      displayName: row.display_name,
      registeredAt: toIso(row.registered_at),
      firstSeenAt: toIso(row.first_seen_at),
      lastSeenAt: toIso(row.last_seen_at),
      pingCount: row.ping_count,
      lastIp: row.last_ip,
      lastLocation: "未知",
      flags: row.flags ?? null,
    })),
  };
});

app.get("/padmin/api/studymate/homepage-activity", async (request, reply) => {
  const query = request.query as { date?: string };
  const date = query.date?.trim() || shanghaiDateString();
  if (!validDateOnly(date)) return reply.code(400).send({ error: "date 须为 YYYY-MM-DD" });
  const [visits, projectRows] = await Promise.all([
    coreSql`
      select v.visitor_key, v.user_id, u.email, u.display_name, v.ip, v.first_seen_at, v.last_seen_at, v.visit_count
      from homepage_daily_visits v
      left join users u on u.id = v.user_id
      where v.activity_date = ${date}
      order by v.last_seen_at desc
    `,
    coreSql`
      select project_id, count(*)::int as unique_visitors, coalesce(sum(click_count), 0)::int as total_clicks
      from homepage_project_clicks
      where activity_date = ${date}
      group by project_id
    `,
  ]);
  const visitors = visits.map((row) => ({
    visitorKey: row.visitor_key,
    userId: row.user_id,
    email: row.email,
    displayName: row.display_name,
    isRegistered: row.user_id != null,
    ip: row.ip,
    firstSeenAt: toIso(row.first_seen_at),
    lastSeenAt: toIso(row.last_seen_at),
    visitCount: row.visit_count,
  }));
  return {
    date,
    count: visitors.length,
    registeredCount: visitors.filter((v) => v.isRegistered).length,
    anonymousCount: visitors.filter((v) => !v.isRegistered).length,
    visitors,
    projects: buildProjectSummaries(
      projectRows as unknown as Array<{ project_id: string; unique_visitors: number; total_clicks: number }>
    ),
  };
});

app.get("/padmin/api/ptoe/codes", async (_request, reply) => {
  const sql = requirePtoe(reply);
  if (!sql) return;
  const idleCutoff = addDays(new Date(), -ptoeIdleReleaseDays);
  const rows = await sql`
    select
      lc.id,
      lc.code_prefix,
      lc.max_devices,
      lc.status,
      lc.expires_at,
      lc.buyer_note,
      lc.created_at,
      count(s.id)::int as active_sessions
    from license_codes lc
    left join sessions s
      on s.license_code_id = lc.id
      and s.expires_at > now()
      and s.last_seen_at > ${idleCutoff}
    group by lc.id
    order by lc.created_at desc
  `;
  return {
    codes: rows.map((row) => ({
      id: row.id,
      codePrefix: row.code_prefix,
      maxDevices: row.max_devices,
      status: row.status,
      expiresAt: toIso(row.expires_at),
      buyerNote: row.buyer_note,
      createdAt: toIso(row.created_at),
      activeSessions: row.active_sessions,
    })),
  };
});

app.post("/padmin/api/ptoe/codes", async (request, reply) => {
  const sql = requirePtoe(reply);
  if (!sql) return;
  const body = request.body as { buyerNote?: string; maxDevices?: number; expiresAt?: string | null };
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const code = generateLicenseCode();
    try {
      const rows = await sql`
        insert into license_codes (code_hash, code_prefix, max_devices, buyer_note, expires_at)
        values (
          ${hashLicenseCode(code.normalized)},
          ${codePrefixFromNormalized(code.normalized)},
          ${body.maxDevices ?? ptoeMaxDevicesDefault},
          ${body.buyerNote?.trim() || null},
          ${body.expiresAt ? new Date(body.expiresAt) : null}
        )
        returning id, code_prefix, max_devices, status, expires_at, buyer_note, created_at
      `;
      return reply.code(201).send({ code: code.formatted, license: rows[0] });
    } catch {
      // retry collision
    }
  }
  return reply.code(500).send({ error: "生成授权码失败，请重试" });
});

app.patch("/padmin/api/ptoe/codes/:id", async (request, reply) => {
  const sql = requirePtoe(reply);
  if (!sql) return;
  const { id } = request.params as { id: string };
  const body = request.body as { status?: "active" | "disabled"; buyerNote?: string | null; maxDevices?: number; expiresAt?: string | null };
  const current = await sql`select * from license_codes where id = ${id} limit 1`;
  if (!current[0]) return reply.code(404).send({ error: "授权码不存在" });
  const rows = await sql`
    update license_codes
    set
      status = ${body.status ?? current[0].status},
      buyer_note = ${Object.prototype.hasOwnProperty.call(body, "buyerNote") ? body.buyerNote : current[0].buyer_note},
      max_devices = ${body.maxDevices ?? current[0].max_devices},
      expires_at = ${Object.prototype.hasOwnProperty.call(body, "expiresAt") ? (body.expiresAt ? new Date(body.expiresAt) : null) : current[0].expires_at}
    where id = ${id}
    returning id, code_prefix, max_devices, status, expires_at, buyer_note, created_at
  `;
  return { license: rows[0] };
});

app.post("/padmin/api/ptoe/codes/:id/revoke-all", async (request, reply) => {
  const sql = requirePtoe(reply);
  if (!sql) return;
  const { id } = request.params as { id: string };
  await sql`delete from sessions where license_code_id = ${id}`;
  return { ok: true };
});

app.get("/padmin/api/ptoe/sessions", async (_request, reply) => {
  const sql = requirePtoe(reply);
  if (!sql) return;
  const idleCutoff = addDays(new Date(), -ptoeIdleReleaseDays);
  const rows = await sql`
    select
      s.id,
      s.license_code_id,
      lc.code_prefix,
      lc.buyer_note,
      lc.status as code_status,
      s.device_id,
      s.device_label,
      s.last_ip,
      s.expires_at,
      s.last_seen_at,
      s.created_at
    from sessions s
    inner join license_codes lc on lc.id = s.license_code_id
    order by s.last_seen_at desc
  `;
  const now = new Date();
  return {
    sessions: rows.map((row) => ({
      id: row.id,
      licenseCodeId: row.license_code_id,
      codePrefix: row.code_prefix,
      buyerNote: row.buyer_note,
      deviceId: row.device_id,
      deviceLabel: row.device_label,
      lastIp: row.last_ip,
      expiresAt: toIso(row.expires_at),
      lastSeenAt: toIso(row.last_seen_at),
      createdAt: toIso(row.created_at),
      active: row.code_status === "active" && row.expires_at > now && row.last_seen_at > idleCutoff,
    })),
  };
});

app.delete("/padmin/api/ptoe/sessions/:id", async (request, reply) => {
  const sql = requirePtoe(reply);
  if (!sql) return;
  const { id } = request.params as { id: string };
  const deleted = await sql`delete from sessions where id = ${id} returning id`;
  if (!deleted[0]) return reply.code(404).send({ error: "会话不存在" });
  return { ok: true };
});

app.get("/padmin/api/ptoe/logs", async (request, reply) => {
  const sql = requirePtoe(reply);
  if (!sql) return;
  const query = request.query as { limit?: string };
  const limit = Math.min(Number(query.limit ?? 100), 200);
  const rows = await sql`
    select
      l.id,
      l.event_type,
      l.ip,
      l.user_agent,
      l.meta,
      l.created_at,
      lc.code_prefix,
      lc.buyer_note
    from activation_logs l
    left join license_codes lc on lc.id = l.license_code_id
    order by l.created_at desc
    limit ${limit}
  `;
  return {
    logs: rows.map((row) => ({
      id: row.id,
      eventType: row.event_type,
      ip: row.ip,
      userAgent: row.user_agent,
      meta: row.meta,
      createdAt: toIso(row.created_at),
      codePrefix: row.code_prefix,
      buyerNote: row.buyer_note,
    })),
  };
});

app.get("/padmin/api/gotit/users", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const query = request.query as { page?: string; pageSize?: string; q?: string };
  const page = Math.max(1, Number(query.page ?? 1));
  const pageSize = Math.min(100, Math.max(1, Number(query.pageSize ?? 20)));
  const offset = (page - 1) * pageSize;
  const q = query.q?.trim();
  const pattern = q ? `%${q}%` : "";
  const rows = q
    ? await sql`
        select
          u.id,
          u.openid,
          u.nickname,
          u.avatar_url,
          u.phone_number,
          u.last_active_ip,
          u.last_active_location,
          u.created_at,
          u.updated_at,
          coalesce(jsonb_array_length(up.mastered_word_ids), 0) as mastered_count,
          coalesce(jsonb_array_length(up.saved_weak_word_ids), 0) as weak_count,
          coalesce(up.selected_unit_id, '') as selected_unit_id,
          coalesce(up.course_setup_completed, false) as course_setup_completed,
          theme.current_theme_name,
          up.updated_at as progress_updated_at
        from users u
        left join user_progress up on up.user_id = u.id
        left join lateral (
          select properties->>'themeName' as current_theme_name
          from usage_events
          where user_id = u.id and event_name = 'theme_selected'
          order by occurred_at desc
          limit 1
        ) theme on true
        where u.nickname ilike ${pattern} or u.openid ilike ${pattern}
        order by u.created_at desc
        limit ${pageSize} offset ${offset}
      `
    : await sql`
        select
          u.id,
          u.openid,
          u.nickname,
          u.avatar_url,
          u.phone_number,
          u.last_active_ip,
          u.last_active_location,
          u.created_at,
          u.updated_at,
          coalesce(jsonb_array_length(up.mastered_word_ids), 0) as mastered_count,
          coalesce(jsonb_array_length(up.saved_weak_word_ids), 0) as weak_count,
          coalesce(up.selected_unit_id, '') as selected_unit_id,
          coalesce(up.course_setup_completed, false) as course_setup_completed,
          theme.current_theme_name,
          up.updated_at as progress_updated_at
        from users u
        left join user_progress up on up.user_id = u.id
        left join lateral (
          select properties->>'themeName' as current_theme_name
          from usage_events
          where user_id = u.id and event_name = 'theme_selected'
          order by occurred_at desc
          limit 1
        ) theme on true
        order by u.created_at desc
        limit ${pageSize} offset ${offset}
      `;
  const totals = q
    ? await sql`
        select count(*)::int as total from users
        where nickname ilike ${pattern} or openid ilike ${pattern}
      `
    : await sql`select count(*)::int as total from users`;
  const today = shanghaiDateString();
  const [todayActive, todayRegistered, totalUsers, reminderEnabled] = await Promise.all([
    sql`select count(distinct user_id)::int as total from user_daily_stats where stat_date = ${today}::date`,
    sql`select count(*)::int as total from users where (created_at at time zone 'Asia/Shanghai')::date = ${today}::date`,
    sql`select count(*)::int as total from users`,
    sql`select count(*)::int as total from learning_reminders where enabled = true`,
  ]);
  const total = totals[0]?.total ?? 0;
  return {
    users: rows.map((row) => ({
      id: row.id,
      openidMasked: maskOpenId(String(row.openid)),
      nickname: row.nickname,
      avatarUrl: row.avatar_url ?? "",
      phoneBound: Boolean(row.phone_number),
      lastActiveIp: row.last_active_ip ?? null,
      lastActiveLocation: row.last_active_location ?? null,
      masteredCount: Number(row.mastered_count ?? 0),
      weakCount: Number(row.weak_count ?? 0),
      selectedUnitId: String(row.selected_unit_id ?? ""),
      courseSetupCompleted: Boolean(row.course_setup_completed),
      currentThemeName: row.current_theme_name ?? "—",
      progressUpdatedAt: toIso(row.progress_updated_at),
      createdAt: toIso(row.created_at),
      updatedAt: toIso(row.updated_at),
    })),
    total,
    totalUsers: totalUsers[0]?.total ?? 0,
    todayActiveCount: todayActive[0]?.total ?? 0,
    todayRegisteredCount: todayRegistered[0]?.total ?? 0,
    reminderEnabledCount: reminderEnabled[0]?.total ?? 0,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  };
});

app.get("/padmin/api/gotit/daily-activity", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const query = request.query as { date?: string };
  const date = query.date && validDateOnly(query.date) ? query.date : shanghaiDateString();
  const rows = await sql`
    select
      s.user_id,
      u.nickname,
      s.stat_date,
      s.words_studied,
      s.study_seconds,
      s.first_seen_at,
      s.last_seen_at
    from user_daily_stats s
    inner join users u on u.id = s.user_id
    where s.stat_date = ${date}::date
    order by s.words_studied desc, s.last_seen_at desc
  `;
  return {
    date,
    users: rows.map((row) => ({
      userId: row.user_id,
      nickname: row.nickname,
      wordsStudied: row.words_studied,
      studyMinutes: Math.round(Number(row.study_seconds) / 60),
      firstSeenAt: toIso(row.first_seen_at),
      lastSeenAt: toIso(row.last_seen_at),
    })),
  };
});

app.get("/padmin/api/gotit/feedbacks", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const query = request.query as { page?: string; pageSize?: string };
  const page = Math.max(1, Number(query.page ?? 1));
  const pageSize = Math.min(100, Math.max(1, Number(query.pageSize ?? 20)));
  const offset = (page - 1) * pageSize;
  const rows = await sql`
    select f.id, f.category, f.content, f.created_at, u.nickname
    from feedbacks f
    inner join users u on u.id = f.user_id
    order by f.created_at desc
    limit ${pageSize} offset ${offset}
  `;
  const totals = await sql`select count(*)::int as total from feedbacks`;
  const total = totals[0]?.total ?? 0;
  return {
    feedbacks: rows.map((row) => ({
      id: row.id,
      category: row.category,
      content: row.content,
      nickname: row.nickname,
      createdAt: toIso(row.created_at),
    })),
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  };
});

function leaderboardDisplayLimit(value?: string): number {
  try {
    const limit = Number(JSON.parse(value ?? "{}").displayLimit);
    return [10, 20, 50, 100].includes(limit) ? limit : 10;
  } catch {
    return 10;
  }
}

app.get("/padmin/api/gotit/usage-stats", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const query = request.query as { date?: string; page?: string; pageSize?: string };
  const date = query.date && validDateOnly(query.date) ? query.date : shanghaiDateString();
  const pageValue = Number(query.page ?? 1);
  const sizeValue = Number(query.pageSize ?? 20);
  const requestedPage = Number.isSafeInteger(pageValue) ? Math.max(1, pageValue) : 1;
  const pageSize = Number.isSafeInteger(sizeValue) ? Math.min(100, Math.max(1, sizeValue)) : 20;
  const [configRows, counts, exportModes, themes, totals] = await Promise.all([
    sql`
      select key, value
      from app_config
      where key in ('analytics_enabled', 'feature_announcements_enabled', 'leaderboard_config')
    `,
    sql`
      select event_name, count(*)::int as total
      from usage_events
      where (occurred_at at time zone 'Asia/Shanghai')::date = ${date}::date
      group by event_name
    `,
    sql`
      select coalesce(properties->>'mode', 'unknown') as mode, count(*)::int as total
      from usage_events
      where event_name = 'wordlist_export_click'
        and (occurred_at at time zone 'Asia/Shanghai')::date = ${date}::date
      group by properties->>'mode'
    `,
    sql`
      with latest_theme as (
        select distinct on (user_id)
          user_id,
          coalesce(properties->>'themeId', '') as theme_id,
          coalesce(properties->>'themeName', '未知主题') as theme_name
        from usage_events
        where event_name = 'theme_selected'
        order by user_id, occurred_at desc
      )
      select theme_id, theme_name, count(*)::int as users
      from latest_theme
      group by theme_id, theme_name
      order by users desc, theme_name
    `,
    sql`
      select count(*)::int as total
      from usage_events e
      inner join users u on u.id = e.user_id
      where (e.occurred_at at time zone 'Asia/Shanghai')::date = ${date}::date
    `,
  ]);
  const total = Number(totals[0]?.total ?? 0);
  const config = Object.fromEntries(configRows.map((row) => [String(row.key), String(row.value)]));
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(requestedPage, totalPages);
  const offset = (page - 1) * pageSize;
  const recentEvents = await sql`
    select e.id, e.event_name, e.properties, e.occurred_at, u.nickname
    from usage_events e
    inner join users u on u.id = e.user_id
    where (e.occurred_at at time zone 'Asia/Shanghai')::date = ${date}::date
    order by e.occurred_at desc, e.id desc
    limit ${pageSize} offset ${offset}
  `;

  return {
    date,
    total,
    page,
    pageSize,
    totalPages,
    analyticsEnabled: config.analytics_enabled !== "false",
    featureAnnouncementsEnabled: config.feature_announcements_enabled !== "false",
    leaderboardDisplayLimit: leaderboardDisplayLimit(config.leaderboard_config),
    counts: Object.fromEntries(counts.map((row) => [String(row.event_name), Number(row.total)])),
    exportModes: Object.fromEntries(exportModes.map((row) => [String(row.mode), Number(row.total)])),
    themes: themes.map((row) => ({
      themeId: row.theme_id,
      themeName: row.theme_name,
      users: Number(row.users),
    })),
    recentEvents: recentEvents.map((row) => ({
      id: row.id,
      eventName: row.event_name,
      properties: row.properties ?? {},
      nickname: row.nickname,
      occurredAt: toIso(row.occurred_at),
    })),
  };
});

app.patch("/padmin/api/gotit/leaderboard-config", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const body = request.body as { displayLimit?: unknown } | null;
  if (typeof body?.displayLimit !== "number" || ![10, 20, 50, 100].includes(body.displayLimit)) {
    return reply.code(400).send({ error: "排行榜展示人数仅支持 10、20、50、100" });
  }
  await sql`
    insert into app_config (key, value)
    values ('leaderboard_config', ${JSON.stringify({ displayLimit: body.displayLimit })})
    on conflict (key) do update set value =
      (app_config.value::jsonb || excluded.value::jsonb)::text
  `;
  return { leaderboardDisplayLimit: body.displayLimit };
});

app.patch("/padmin/api/gotit/analytics-config", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const body = request.body as { enabled?: unknown };
  if (typeof body.enabled !== "boolean") {
    return reply.code(400).send({ error: "enabled 必须为布尔值" });
  }
  await sql`
    insert into app_config (key, value)
    values ('analytics_enabled', ${body.enabled ? "true" : "false"})
    on conflict (key) do update set value = excluded.value
  `;
  return { analyticsEnabled: body.enabled };
});

app.patch("/padmin/api/gotit/feature-announcements-config", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const body = request.body as { enabled?: unknown };
  if (typeof body.enabled !== "boolean") {
    return reply.code(400).send({ error: "enabled 必须为布尔值" });
  }
  await sql`
    insert into app_config (key, value)
    values ('feature_announcements_enabled', ${body.enabled ? "true" : "false"})
    on conflict (key) do update set value = excluded.value
  `;
  return { featureAnnouncementsEnabled: body.enabled };
});

app.get("/padmin/api/gotit/leaderboard-stats", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const query = request.query as {
    metric?: string;
    period?: string;
    weekKey?: string;
    q?: string;
    page?: string;
    pageSize?: string;
  };
  const metric = parseGotitLeaderboardMetric(query.metric);
  const period = parseGotitLeaderboardPeriod(query.period);
  if (!metric || !period) {
    return reply.code(400).send({ error: "metric 需为 time/words/power，period 需为 week/total" });
  }
  const context = shanghaiWeekContext();
  const weekKey = query.weekKey?.trim() || context.weekKey;
  const page = Math.max(1, Number(query.page ?? 1));
  const pageSize = Math.min(100, Math.max(1, Number(query.pageSize ?? 20)));
  const offset = (page - 1) * pageSize;
  const q = query.q?.trim() ?? "";
  const pattern = q ? `%${q}%` : null;

  let weekStart = context.weekStart;
  let weekEnd = context.weekEnd;
  if (period === "week" && query.weekKey?.trim()) {
    const match = /^(\d{4})-W(\d{2})$/.exec(weekKey);
    if (!match) return reply.code(400).send({ error: "weekKey 格式应为 YYYY-Www" });
    const year = Number(match[1]);
    const week = Number(match[2]);
    const janFourthKey = `${year}-01-04`;
    const janFourth = new Date(`${janFourthKey}T12:00:00+08:00`);
    const janFourthWeekday = janFourth.getUTCDay() || 7;
    const firstMondayKey = dateKeyAfter(janFourthKey, 1 - janFourthWeekday);
    weekStart = dateKeyAfter(firstMondayKey, (week - 1) * 7);
    weekEnd = dateKeyAfter(weekStart, 6);
  }

  const rows =
    metric === "time" && period === "week"
      ? await sql`
          with totals as (
            select s.user_id, sum(s.study_seconds)::bigint as value
            from user_daily_stats s
            where s.stat_date between ${weekStart}::date and ${weekEnd}::date
            group by s.user_id
            having sum(s.study_seconds) > 0
          ),
          ranked as (
            select totals.user_id, u.nickname, totals.value,
              row_number() over (order by totals.value desc, totals.user_id asc) as rank
            from totals
            inner join users u on u.id = totals.user_id
            where ${pattern}::text is null or u.nickname ilike ${pattern}
          )
          select user_id, nickname, value, rank from ranked
          order by rank asc
          limit ${pageSize} offset ${offset}
        `
      : metric === "time" && period === "total"
        ? await sql`
            with totals as (
              select s.user_id, sum(s.study_seconds)::bigint as value
              from user_daily_stats s
              group by s.user_id
              having sum(s.study_seconds) > 0
            ),
            ranked as (
              select totals.user_id, u.nickname, totals.value,
                row_number() over (order by totals.value desc, totals.user_id asc) as rank
              from totals
              inner join users u on u.id = totals.user_id
              where ${pattern}::text is null or u.nickname ilike ${pattern}
            )
            select user_id, nickname, value, rank from ranked
            order by rank asc
            limit ${pageSize} offset ${offset}
          `
        : metric === "words" && period === "week"
          ? await sql`
              with totals as (
                select m.user_id, count(*)::bigint as value
                from user_word_mastery m
                where m.first_mastered_at between ${`${weekStart}T00:00:00+08:00`}::timestamptz
                  and ${`${weekEnd}T23:59:59.999+08:00`}::timestamptz
                group by m.user_id
              ),
              ranked as (
                select totals.user_id, u.nickname, totals.value,
                  row_number() over (order by totals.value desc, totals.user_id asc) as rank
                from totals
                inner join users u on u.id = totals.user_id
                where ${pattern}::text is null or u.nickname ilike ${pattern}
              )
              select user_id, nickname, value, rank from ranked
              order by rank asc
              limit ${pageSize} offset ${offset}
            `
          : metric === "words" && period === "total"
            ? await sql`
                with totals as (
                  select up.user_id,
                    coalesce(jsonb_array_length(up.mastered_word_ids), 0)::bigint as value
                  from user_progress up
                  where coalesce(jsonb_array_length(up.mastered_word_ids), 0) > 0
                ),
                ranked as (
                  select totals.user_id, u.nickname, totals.value,
                    row_number() over (order by totals.value desc, totals.user_id asc) as rank
                  from totals
                  inner join users u on u.id = totals.user_id
                  where ${pattern}::text is null or u.nickname ilike ${pattern}
                )
                select user_id, nickname, value, rank from ranked
                order by rank asc
                limit ${pageSize} offset ${offset}
              `
            : metric === "power" && period === "week"
              ? await sql`
                  with totals as (
                    select w.user_id, w.learning_power::bigint as value
                    from weekly_learning_power w
                    where w.week_key = ${weekKey} and w.learning_power > 0
                  ),
                  ranked as (
                    select totals.user_id, u.nickname, totals.value,
                      row_number() over (order by totals.value desc, totals.user_id asc) as rank
                    from totals
                    inner join users u on u.id = totals.user_id
                    where ${pattern}::text is null or u.nickname ilike ${pattern}
                  )
                  select user_id, nickname, value, rank from ranked
                  order by rank asc
                  limit ${pageSize} offset ${offset}
                `
              : await sql`
                  with totals as (
                    select w.user_id, sum(w.learning_power)::bigint as value
                    from weekly_learning_power w
                    group by w.user_id
                    having sum(w.learning_power) > 0
                  ),
                  ranked as (
                    select totals.user_id, u.nickname, totals.value,
                      row_number() over (order by totals.value desc, totals.user_id asc) as rank
                    from totals
                    inner join users u on u.id = totals.user_id
                    where ${pattern}::text is null or u.nickname ilike ${pattern}
                  )
                  select user_id, nickname, value, rank from ranked
                  order by rank asc
                  limit ${pageSize} offset ${offset}
                `;

  const countRows =
    metric === "time" && period === "week"
      ? await sql`
          select count(*)::int as total
          from (
            select s.user_id
            from user_daily_stats s
            inner join users u on u.id = s.user_id
            where s.stat_date between ${weekStart}::date and ${weekEnd}::date
              and (${pattern}::text is null or u.nickname ilike ${pattern})
            group by s.user_id
            having sum(s.study_seconds) > 0
          ) t
        `
      : metric === "time" && period === "total"
        ? await sql`
            select count(*)::int as total
            from (
              select s.user_id
              from user_daily_stats s
              inner join users u on u.id = s.user_id
              where ${pattern}::text is null or u.nickname ilike ${pattern}
              group by s.user_id
              having sum(s.study_seconds) > 0
            ) t
          `
        : metric === "words" && period === "week"
          ? await sql`
              select count(*)::int as total
              from (
                select m.user_id
                from user_word_mastery m
                inner join users u on u.id = m.user_id
                where m.first_mastered_at between ${`${weekStart}T00:00:00+08:00`}::timestamptz
                  and ${`${weekEnd}T23:59:59.999+08:00`}::timestamptz
                  and (${pattern}::text is null or u.nickname ilike ${pattern})
                group by m.user_id
              ) t
            `
          : metric === "words" && period === "total"
            ? await sql`
                select count(*)::int as total
                from user_progress up
                inner join users u on u.id = up.user_id
                where coalesce(jsonb_array_length(up.mastered_word_ids), 0) > 0
                  and (${pattern}::text is null or u.nickname ilike ${pattern})
              `
            : metric === "power" && period === "week"
              ? await sql`
                  select count(*)::int as total
                  from weekly_learning_power w
                  inner join users u on u.id = w.user_id
                  where w.week_key = ${weekKey} and w.learning_power > 0
                    and (${pattern}::text is null or u.nickname ilike ${pattern})
                `
              : await sql`
                  select count(*)::int as total
                  from (
                    select w.user_id
                    from weekly_learning_power w
                    inner join users u on u.id = w.user_id
                    where ${pattern}::text is null or u.nickname ilike ${pattern}
                    group by w.user_id
                    having sum(w.learning_power) > 0
                  ) t
                `;

  const total = countRows[0]?.total ?? 0;
  return {
    metric,
    period,
    weekKey: period === "week" ? weekKey : null,
    weekStart: period === "week" ? weekStart : null,
    weekEnd: period === "week" ? weekEnd : null,
    rows: rows.map((row) => ({
      rank: Number(row.rank),
      userId: String(row.user_id),
      nickname: row.nickname ?? "同学",
      value: Number(row.value),
      displayValue: formatLeaderboardDisplayValue(metric, Number(row.value)),
    })),
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  };
});

app.get("/padmin/api/gotit/leaderboard-stats/:userId/detail", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const { userId } = request.params as { userId: string };
  const query = request.query as { metric?: string; period?: string; weekKey?: string };
  const metric = parseGotitLeaderboardMetric(query.metric);
  const period = parseGotitLeaderboardPeriod(query.period);
  if (!metric || !period) {
    return reply.code(400).send({ error: "metric 需为 time/words/power，period 需为 week/total" });
  }
  const context = shanghaiWeekContext();
  const weekKey = query.weekKey?.trim() || context.weekKey;
  let weekStart = context.weekStart;
  let weekEnd = context.weekEnd;
  if (period === "week") {
    const match = /^(\d{4})-W(\d{2})$/.exec(weekKey);
    if (!match) return reply.code(400).send({ error: "weekKey 格式应为 YYYY-Www" });
    const year = Number(match[1]);
    const week = Number(match[2]);
    const janFourthKey = `${year}-01-04`;
    const janFourth = new Date(`${janFourthKey}T12:00:00+08:00`);
    const janFourthWeekday = janFourth.getUTCDay() || 7;
    const firstMondayKey = dateKeyAfter(janFourthKey, 1 - janFourthWeekday);
    weekStart = dateKeyAfter(firstMondayKey, (week - 1) * 7);
    weekEnd = dateKeyAfter(weekStart, 6);
  }

  const [user] = await sql`
    select id, nickname from users where id = ${userId}::uuid limit 1
  `;
  if (!user) return reply.code(404).send({ error: "用户不存在" });

  if (metric === "time") {
    const dailyRows =
      period === "week"
        ? await sql`
            select stat_date, study_seconds, words_studied
            from user_daily_stats
            where user_id = ${userId}::uuid
              and stat_date between ${weekStart}::date and ${weekEnd}::date
            order by stat_date asc
          `
        : await sql`
            select stat_date, study_seconds, words_studied
            from user_daily_stats
            where user_id = ${userId}::uuid
            order by stat_date desc
            limit 60
          `;
    const byDate = new Map(
      dailyRows.map((row) => [
        toDateOnly(row.stat_date) ?? "",
        {
          statDate: toDateOnly(row.stat_date) ?? "",
          studySeconds: Number(row.study_seconds ?? 0),
          studyMinutes: Math.round(Number(row.study_seconds ?? 0) / 60),
          wordsStudied: Number(row.words_studied ?? 0),
        },
      ])
    );
    const dailyStats =
      period === "week"
        ? Array.from({ length: 7 }, (_, index) => {
            const statDate = dateKeyAfter(weekStart, index);
            return (
              byDate.get(statDate) ?? {
                statDate,
                studySeconds: 0,
                studyMinutes: 0,
                wordsStudied: 0,
              }
            );
          })
        : [...byDate.values()];
    const totalSeconds = dailyStats.reduce((sum, row) => sum + row.studySeconds, 0);
    return {
      userId,
      nickname: user.nickname,
      metric,
      period,
      weekKey: period === "week" ? weekKey : null,
      weekStart: period === "week" ? weekStart : null,
      weekEnd: period === "week" ? weekEnd : null,
      totalValue: totalSeconds,
      displayValue: formatLeaderboardDisplayValue("time", totalSeconds),
      dailyStats,
    };
  }

  if (metric === "words") {
    if (period === "week") {
      const [countRow] = await sql`
        select count(*)::int as total
        from user_word_mastery
        where user_id = ${userId}::uuid
          and first_mastered_at between ${`${weekStart}T00:00:00+08:00`}::timestamptz
            and ${`${weekEnd}T23:59:59.999+08:00`}::timestamptz
      `;
      const samples = await sql`
        select word_id, first_mastered_at
        from user_word_mastery
        where user_id = ${userId}::uuid
          and first_mastered_at between ${`${weekStart}T00:00:00+08:00`}::timestamptz
            and ${`${weekEnd}T23:59:59.999+08:00`}::timestamptz
        order by first_mastered_at desc
        limit 20
      `;
      const total = Number(countRow?.total ?? 0);
      return {
        userId,
        nickname: user.nickname,
        metric,
        period,
        weekKey,
        weekStart,
        weekEnd,
        totalValue: total,
        displayValue: formatLeaderboardDisplayValue("words", total),
        masterySamples: samples.map((row) => ({
          wordId: String(row.word_id),
          firstMasteredAt: toIso(row.first_mastered_at),
        })),
      };
    }
    const [progress] = await sql`
      select coalesce(jsonb_array_length(mastered_word_ids), 0)::int as total, mastered_word_ids
      from user_progress where user_id = ${userId}::uuid limit 1
    `;
    const total = Number(progress?.total ?? 0);
    const samples = Array.isArray(progress?.mastered_word_ids)
      ? (progress.mastered_word_ids as string[]).slice(-20).reverse()
      : [];
    return {
      userId,
      nickname: user.nickname,
      metric,
      period,
      weekKey: null,
      weekStart: null,
      weekEnd: null,
      totalValue: total,
      displayValue: formatLeaderboardDisplayValue("words", total),
      masterySamples: samples.map((wordId) => ({ wordId, firstMasteredAt: null })),
    };
  }

  if (period === "week") {
    const [row] = await sql`
      select learning_power, valid_dictation_count, active_study_days, last_score_at
      from weekly_learning_power
      where user_id = ${userId}::uuid and week_key = ${weekKey}
      limit 1
    `;
    const total = Number(row?.learning_power ?? 0);
    return {
      userId,
      nickname: user.nickname,
      metric,
      period,
      weekKey,
      weekStart,
      weekEnd,
      totalValue: total,
      displayValue: formatLeaderboardDisplayValue("power", total),
      weeklyPower: {
        learningPower: total,
        validDictationCount: Number(row?.valid_dictation_count ?? 0),
        activeStudyDays: Number(row?.active_study_days ?? 0),
        lastScoreAt: toIso(row?.last_score_at),
      },
    };
  }

  const weeklyRows = await sql`
    select week_key, learning_power
    from weekly_learning_power
    where user_id = ${userId}::uuid
    order by week_key desc
    limit 24
  `;
  const total = weeklyRows.reduce((sum, row) => sum + Number(row.learning_power ?? 0), 0);
  return {
    userId,
    nickname: user.nickname,
    metric,
    period,
    weekKey: null,
    weekStart: null,
    weekEnd: null,
    totalValue: total,
    displayValue: formatLeaderboardDisplayValue("power", total),
    weeklyBreakdown: weeklyRows.map((row) => ({
      weekKey: String(row.week_key),
      learningPower: Number(row.learning_power ?? 0),
    })),
  };
});

app.patch("/padmin/api/gotit/user-daily-stats", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const body = request.body as {
    userId?: unknown;
    statDate?: unknown;
    studySeconds?: unknown;
    wordsStudied?: unknown;
  } | null;
  if (typeof body?.userId !== "string" || !validDateOnly(String(body.statDate ?? ""))) {
    return reply.code(400).send({ error: "userId 与 statDate(YYYY-MM-DD) 必填" });
  }
  if (typeof body.studySeconds !== "number" || !Number.isFinite(body.studySeconds) || body.studySeconds < 0) {
    return reply.code(400).send({ error: "studySeconds 必须为非负整数" });
  }
  const studySeconds = Math.floor(body.studySeconds);
  const wordsStudied =
    typeof body.wordsStudied === "number" && Number.isFinite(body.wordsStudied)
      ? Math.max(0, Math.floor(body.wordsStudied))
      : 0;
  const statDate = String(body.statDate);
  const userId = body.userId;
  await sql`
    insert into user_daily_stats (
      user_id, stat_date, words_studied, study_seconds, word_ids_today, first_seen_at, last_seen_at
    )
    values (
      ${userId}::uuid, ${statDate}::date, ${wordsStudied}, ${studySeconds}, '[]'::jsonb, now(), now()
    )
    on conflict (user_id, stat_date) do update set
      study_seconds = ${studySeconds},
      words_studied = coalesce(${wordsStudied}, user_daily_stats.words_studied),
      last_seen_at = now()
  `;
  return {
    userId,
    statDate,
    studySeconds,
    studyMinutes: Math.round(studySeconds / 60),
    wordsStudied,
  };
});

app.patch("/padmin/api/gotit/weekly-learning-power", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const body = request.body as {
    userId?: unknown;
    weekKey?: unknown;
    learningPower?: unknown;
    validDictationCount?: unknown;
    activeStudyDays?: unknown;
  } | null;
  if (typeof body?.userId !== "string" || typeof body.weekKey !== "string" || !/^\d{4}-W\d{2}$/.test(body.weekKey)) {
    return reply.code(400).send({ error: "userId 与 weekKey(YYYY-Www) 必填" });
  }
  if (typeof body.learningPower !== "number" || !Number.isFinite(body.learningPower) || body.learningPower < 0) {
    return reply.code(400).send({ error: "learningPower 必须为非负整数" });
  }
  const learningPower = Math.floor(body.learningPower);
  const validDictationCount =
    typeof body.validDictationCount === "number" && Number.isFinite(body.validDictationCount)
      ? Math.max(0, Math.floor(body.validDictationCount))
      : 0;
  const activeStudyDays =
    typeof body.activeStudyDays === "number" && Number.isFinite(body.activeStudyDays)
      ? Math.max(0, Math.floor(body.activeStudyDays))
      : 0;
  await sql`
    insert into weekly_learning_power (
      user_id, week_key, learning_power, valid_dictation_count, active_study_days,
      last_score_at, created_at, updated_at
    )
    values (
      ${body.userId}::uuid, ${body.weekKey}, ${learningPower}, ${validDictationCount}, ${activeStudyDays},
      now(), now(), now()
    )
    on conflict (user_id, week_key) do update set
      learning_power = ${learningPower},
      valid_dictation_count = ${validDictationCount},
      active_study_days = ${activeStudyDays},
      last_score_at = now(),
      updated_at = now()
  `;
  return {
    userId: body.userId,
    weekKey: body.weekKey,
    learningPower,
    validDictationCount,
    activeStudyDays,
  };
});

app.patch("/padmin/api/gotit/user-mastery-count", async (request, reply) => {
  const sql = requireGotit(reply);
  if (!sql) return;
  const body = request.body as {
    userId?: unknown;
    period?: unknown;
    weekKey?: unknown;
    targetCount?: unknown;
  } | null;
  const period = parseGotitLeaderboardPeriod(body?.period);
  if (typeof body?.userId !== "string" || !period || typeof body.targetCount !== "number") {
    return reply.code(400).send({ error: "userId、period(week/total) 与 targetCount 必填" });
  }
  const targetCount = Math.max(0, Math.floor(body.targetCount));
  if (period === "week") {
    const weekKey = typeof body.weekKey === "string" ? body.weekKey : shanghaiWeekContext().weekKey;
    const match = /^(\d{4})-W(\d{2})$/.exec(weekKey);
    if (!match) return reply.code(400).send({ error: "weekKey 格式应为 YYYY-Www" });
    const year = Number(match[1]);
    const week = Number(match[2]);
    const janFourthKey = `${year}-01-04`;
    const janFourth = new Date(`${janFourthKey}T12:00:00+08:00`);
    const janFourthWeekday = janFourth.getUTCDay() || 7;
    const firstMondayKey = dateKeyAfter(janFourthKey, 1 - janFourthWeekday);
    const weekStart = dateKeyAfter(firstMondayKey, (week - 1) * 7);
    const weekEnd = dateKeyAfter(weekStart, 6);
    const [countRow] = await sql`
      select count(*)::int as total
      from user_word_mastery
      where user_id = ${body.userId}::uuid
        and first_mastered_at between ${`${weekStart}T00:00:00+08:00`}::timestamptz
          and ${`${weekEnd}T23:59:59.999+08:00`}::timestamptz
    `;
    const current = Number(countRow?.total ?? 0);
    if (targetCount < current) {
      const removeCount = current - targetCount;
      await sql`
        delete from user_word_mastery
        where (user_id, word_id) in (
          select user_id, word_id
          from user_word_mastery
          where user_id = ${body.userId}::uuid
            and first_mastered_at between ${`${weekStart}T00:00:00+08:00`}::timestamptz
              and ${`${weekEnd}T23:59:59.999+08:00`}::timestamptz
          order by first_mastered_at desc
          limit ${removeCount}
        )
      `;
    }
    return { userId: body.userId, period, weekKey, targetCount, previousCount: current };
  }

  const [progress] = await sql`
    select mastered_word_ids
    from user_progress
    where user_id = ${body.userId}::uuid
    limit 1
  `;
  const currentIds = Array.isArray(progress?.mastered_word_ids)
    ? (progress.mastered_word_ids as string[]).filter((id) => typeof id === "string" && id.length > 0)
    : [];
  const nextIds = currentIds.slice(0, targetCount);
  await sql`
    update user_progress
    set mastered_word_ids = ${JSON.stringify(nextIds)}::jsonb, updated_at = now()
    where user_id = ${body.userId}::uuid
  `;
  return {
    userId: body.userId,
    period,
    targetCount,
    previousCount: currentIds.length,
  };
});

app.get("/robots.txt", async (_request, reply) => sendStatic(reply, path.join(projectRoot, "robots.txt")));
app.get("/sitemap.xml", async (_request, reply) => sendStatic(reply, path.join(projectRoot, "sitemap.xml")));
app.get("/site.webmanifest", async (_request, reply) => sendStatic(reply, path.join(projectRoot, "site.webmanifest")));
app.get("/favicon.ico", async (_request, reply) => sendStatic(reply, path.join(logoDir, "favicon/favicon.ico")));
app.get("/", async (_request, reply) => sendStatic(reply, path.join(projectRoot, "index.html")));
app.get("/styles.css", async (_request, reply) => sendStatic(reply, path.join(projectRoot, "styles.css")));
app.get("/script.js", async (_request, reply) => sendStatic(reply, path.join(projectRoot, "script.js")));
app.get("/logo/*", async (request, reply) => {
  const rel = (request.params as { "*": string })["*"] || "";
  const requested = path.normalize(path.join(logoDir, rel));
  if (requested.startsWith(`${logoDir}${path.sep}`) && existsSync(requested)) return sendStatic(reply, requested);
  return reply.code(404).send({ error: "Not found" });
});
app.get("/assets/*", async (request, reply) => {
  const rel = (request.params as { "*": string })["*"] || "";
  const requested = path.normalize(path.join(assetsDir, rel));
  if (requested.startsWith(`${assetsDir}${path.sep}`) && existsSync(requested)) return sendStatic(reply, requested);
  return reply.code(404).send({ error: "Not found" });
});

app.get("/padmin", async (_request, reply) => reply.redirect("/padmin/"));
app.get("/padmin/*", async (request, reply) => {
  const rel = (request.params as { "*": string })["*"] || "index.html";
  const requested = path.normalize(path.join(padminDist, rel));
  if (requested.startsWith(padminDist) && existsSync(requested)) {
    return sendStatic(reply, requested);
  }
  return sendStatic(reply, path.join(padminDist, "index.html"));
});

app.setNotFoundHandler(async (_request, reply) => {
  const index = path.join(projectRoot, "index.html");
  if (existsSync(index)) return sendStatic(reply, index);
  return reply.code(404).send({ error: "Not found" });
});

const port = Number(process.env.PORT ?? 8090);
const host = process.env.HOST ?? "0.0.0.0";

await fs.mkdir(padminDist, { recursive: true });
app.listen({ port, host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
