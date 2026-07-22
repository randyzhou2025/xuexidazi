import {
  BarChartOutlined,
  DashboardOutlined,
  FileTextOutlined,
  KeyOutlined,
  LoginOutlined,
  LogoutOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Avatar,
  Button,
  Card,
  DatePicker,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Modal,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import dayjs from "dayjs";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";

const TOKEN_KEY = "xuexidazi-auth-token";
const LEGACY_TOKEN_KEYS = ["exam-auth-token"];
const PAGE_SIZE = 20;

interface AuthUser {
  id: string;
  email: string;
  displayName: string | null;
  role: string;
  isAuthorized: boolean;
  createdAt: string;
  subscriptionExpiresOn: string | null;
}

interface UserRow extends AuthUser {
  lastActiveAt: string | null;
  lastActiveIp: string | null;
}

interface LoginLog {
  id: string;
  userId: string;
  username: string;
  ip: string;
  location: string;
  loginAt: string;
}

interface DailyUser {
  userId: string;
  email: string;
  displayName: string | null;
  registeredAt: string;
  firstSeenAt: string;
  lastSeenAt: string;
  pingCount: number;
  lastIp: string;
  lastLocation: string;
  flags: Record<string, number | boolean> | null;
}

interface HomepageVisitor {
  visitorKey: string;
  userId: string | null;
  email: string | null;
  displayName: string | null;
  isRegistered: boolean;
  ip: string;
  firstSeenAt: string;
  lastSeenAt: string;
  visitCount: number;
}

interface ProjectSummary {
  projectId: string;
  label: string;
  uniqueVisitors: number;
  totalClicks: number;
  breakdown?: Record<string, { label: string; uniqueVisitors: number; totalClicks: number }>;
}

interface PtoeCode {
  id: string;
  codePrefix: string;
  maxDevices: number;
  status: "active" | "disabled";
  expiresAt: string | null;
  buyerNote: string | null;
  createdAt: string;
  activeSessions: number;
}

interface PtoeSession {
  id: string;
  licenseCodeId: string;
  codePrefix: string;
  buyerNote: string | null;
  deviceId: string;
  deviceLabel: string | null;
  lastIp: string;
  expiresAt: string;
  lastSeenAt: string;
  createdAt: string;
  active: boolean;
}

interface PtoeLog {
  id: string;
  eventType: string;
  ip: string;
  userAgent: string | null;
  meta: Record<string, unknown> | null;
  createdAt: string;
  codePrefix: string | null;
  buyerNote: string | null;
}

function token() {
  try {
    return localStorage.getItem(TOKEN_KEY) || LEGACY_TOKEN_KEYS.map((key) => localStorage.getItem(key)).find(Boolean) || null;
  } catch {
    return null;
  }
}

function setToken(value: string | null) {
  try {
    if (value) {
      localStorage.setItem(TOKEN_KEY, value);
      LEGACY_TOKEN_KEYS.forEach((key) => localStorage.removeItem(key));
    } else {
      localStorage.removeItem(TOKEN_KEY);
      LEGACY_TOKEN_KEYS.forEach((key) => localStorage.removeItem(key));
    }
  } catch {
    /* ignore */
  }
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  const t = token();
  if (t) headers.set("Authorization", `Bearer ${t}`);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const res = await fetch(`/padmin/api${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "请求失败");
  return data as T;
}

function formatTime(value: string | null | undefined) {
  if (!value) return "—";
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function formatDate(value: string | null | undefined) {
  if (!value) return "—";
  return new Date(value).toLocaleDateString("zh-CN");
}

function moduleCounts(flags: DailyUser["flags"]) {
  if (!flags) return "—";
  const pick = (key: string) => {
    const value = flags[key];
    if (typeof value === "number") return value;
    return value === true ? 1 : 0;
  };
  const parts = [
    ["理论", pick("theory")],
    ["实操", pick("operate")],
    ["模考", pick("mock")],
  ].filter(([, count]) => Number(count) > 0);
  return parts.length ? parts.map(([label, count]) => `${label}${count}`).join("、") : "—";
}

function PageHead({ title, desc, extra }: { title: string; desc?: string; extra?: React.ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {desc ? <p>{desc}</p> : null}
      </div>
      {extra}
    </div>
  );
}

function LoginPage({ onLogin }: { onLogin: (user: AuthUser) => void }) {
  const [loading, setLoading] = useState(false);

  async function submit(values: { email: string; password: string }) {
    setLoading(true);
    try {
      const data = await api<{ token: string; user: AuthUser }>("/auth/login", {
        method: "POST",
        body: JSON.stringify(values),
      });
      setToken(data.token);
      onLogin(data.user);
      message.success("已登录");
    } catch (error) {
      message.error(error instanceof Error ? error.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-screen">
      <Card className="login-card">
        <Typography.Title level={3}>StudyMate Admin</Typography.Title>
        <Typography.Paragraph type="secondary">使用统一管理员账号登录。</Typography.Paragraph>
        <Form layout="vertical" onFinish={submit}>
          <Form.Item name="email" label="邮箱" rules={[{ required: true, type: "email" }]}>
            <Input autoComplete="email" placeholder="admin@local.test" />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loading}>
            登录
          </Button>
        </Form>
      </Card>
    </div>
  );
}

function AdminShell({ user, onLogout }: { user: AuthUser; onLogout: () => void }) {
  const location = useLocation();
  const navigate = useNavigate();
  const selected = location.pathname === "/" ? "/" : location.pathname;
  const menuItems = [
    { key: "/", icon: <DashboardOutlined />, label: <Link to="/">总览</Link> },
    { type: "group" as const, label: "StudyMate 公共体系" },
    { key: "/users", icon: <TeamOutlined />, label: <Link to="/users">用户管理</Link> },
    { key: "/login-logs", icon: <LoginOutlined />, label: <Link to="/login-logs">登录日志</Link> },
    { key: "/homepage", icon: <DashboardOutlined />, label: <Link to="/homepage">主页访问</Link> },
    { type: "group" as const, label: "ExamMaster 工具" },
    { key: "/exam/daily-activity", icon: <BarChartOutlined />, label: <Link to="/exam/daily-activity">备考活跃</Link> },
    { type: "group" as const, label: "PeriodicTable 工具" },
    { key: "/ptoe/codes", icon: <KeyOutlined />, label: <Link to="/ptoe/codes">授权码</Link> },
    { key: "/ptoe/sessions", icon: <ThunderboltOutlined />, label: <Link to="/ptoe/sessions">在线设备</Link> },
    { key: "/ptoe/logs", icon: <FileTextOutlined />, label: <Link to="/ptoe/logs">激活日志</Link> },
    { type: "group" as const, label: "课本单词通 工具" },
    { key: "/gotit/users", icon: <TeamOutlined />, label: <Link to="/gotit/users">用户管理</Link> },
    { key: "/gotit/daily-activity", icon: <BarChartOutlined />, label: <Link to="/gotit/daily-activity">学习活跃</Link> },
    { key: "/gotit/feedbacks", icon: <FileTextOutlined />, label: <Link to="/gotit/feedbacks">意见反馈</Link> },
  ];

  return (
    <Layout className="padmin-layout">
      <Layout.Sider breakpoint="lg" collapsedWidth={0}>
        <div className="padmin-logo">
          <span className="padmin-mark" />
          StudyMate
        </div>
        <Menu theme="dark" mode="inline" selectedKeys={[selected]} items={menuItems} />
      </Layout.Sider>
      <Layout>
        <Layout.Header className="padmin-header">
          <Typography.Text type="secondary">{user.displayName || user.email}</Typography.Text>
          <Space>
            <Button onClick={() => navigate("/")}>总览</Button>
            <Button
              icon={<LogoutOutlined />}
              onClick={() => {
                setToken(null);
                onLogout();
              }}
            >
              退出
            </Button>
          </Space>
        </Layout.Header>
        <Layout.Content className="padmin-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/users" element={<StudyMateUsers />} />
            <Route path="/login-logs" element={<LoginLogs />} />
            <Route path="/homepage" element={<HomepageActivity />} />
            <Route path="/exam/daily-activity" element={<DailyActivity />} />
            <Route path="/exam/users" element={<Navigate to="/users" replace />} />
            <Route path="/exam/login-logs" element={<Navigate to="/login-logs" replace />} />
            <Route path="/exam/homepage" element={<Navigate to="/homepage" replace />} />
            <Route path="/ptoe/codes" element={<PtoeCodes />} />
            <Route path="/ptoe/sessions" element={<PtoeSessions />} />
            <Route path="/ptoe/logs" element={<PtoeLogs />} />
            <Route path="/gotit/users" element={<GotItUsers />} />
            <Route path="/gotit/daily-activity" element={<GotItDailyActivity />} />
            <Route path="/gotit/feedbacks" element={<GotItFeedbacks />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout.Content>
      </Layout>
    </Layout>
  );
}

function Dashboard() {
  const [data, setData] = useState({
    users: 0,
    todayActive: 0,
    licenseCodes: 0,
    activePtoeSessions: 0,
    gotitUsers: 0,
    gotitTodayActive: 0,
  });
  const [error, setError] = useState("");
  useEffect(() => {
    api<typeof data>("/summary").then(setData).catch((e) => setError(e.message));
  }, []);
  return (
    <>
      <PageHead title="后台总览" desc="统一管理 StudyMate 公共用户体系及 ExamMaster、PeriodicTable、课本单词通工具数据。" />
      {error ? <Alert type="warning" message={error} showIcon style={{ marginBottom: 16 }} /> : null}
      <Space direction="vertical" size={16} style={{ width: "100%" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 16 }}>
          <Card><Statistic title="StudyMate 用户" value={data.users} /></Card>
          <Card><Statistic title="StudyMate 今日活跃" value={data.todayActive} /></Card>
          <Card><Statistic title="周期表授权码" value={data.licenseCodes} /></Card>
          <Card><Statistic title="周期表有效会话" value={data.activePtoeSessions} /></Card>
          <Card><Statistic title="课本单词通用户" value={data.gotitUsers} /></Card>
          <Card><Statistic title="课本单词通今日活跃" value={data.gotitTodayActive} /></Card>
        </div>
        <Alert
          type="info"
          showIcon
          message="数据源"
          description="本后台由 XueXiDaZi server 直接连接学习搭子公共用户库与各工具数据库，不调用旧项目管理 API。"
        />
      </Space>
    </>
  );
}

function StudyMateUsers() {
  const [rows, setRows] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState({ todayActiveCount: 0, todayRegisteredCount: 0 });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), pageSize: String(PAGE_SIZE) });
      if (query) params.set("q", query);
      const data = await api<{
        users: UserRow[];
        total: number;
        todayActiveCount: number;
        todayRegisteredCount: number;
      }>(`/studymate/users?${params}`);
      setRows(data.users);
      setTotal(data.total);
      setStats({ todayActiveCount: data.todayActiveCount, todayRegisteredCount: data.todayRegisteredCount });
    } catch (e) {
      message.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [page, query]);

  useEffect(() => void load(), [load]);

  async function patchUser(id: string, body: Record<string, unknown>) {
    const data = await api<{ user: UserRow }>(`/studymate/users/${id}`, { method: "PATCH", body: JSON.stringify(body) });
    setRows((prev) => prev.map((row) => (row.id === id ? data.user : row)));
  }

  const columns: ColumnsType<UserRow> = [
    { title: "邮箱", dataIndex: "email", width: 260 },
    { title: "用户名", dataIndex: "displayName", render: (v, r) => v || (r.role === "admin" ? "管理员" : "—") },
    { title: "角色", dataIndex: "role", render: (v) => <Tag color={v === "admin" ? "blue" : "default"}>{v}</Tag> },
    { title: "注册日期", dataIndex: "createdAt", render: formatDate },
    { title: "最后访问", dataIndex: "lastActiveAt", render: formatTime },
    {
      title: "授权",
      dataIndex: "isAuthorized",
      render: (v, r) => (
        <Switch
          disabled={r.role === "admin"}
          checked={v}
          onChange={(checked) => patchUser(r.id, { isAuthorized: checked }).catch((e) => message.error(e.message))}
        />
      ),
    },
    {
      title: "订阅到期日",
      dataIndex: "subscriptionExpiresOn",
      render: (v, r) => (
        <Input
          type="date"
          disabled={r.role === "admin"}
          defaultValue={v || ""}
          onBlur={(e) => patchUser(r.id, { subscriptionExpiresOn: e.target.value || null }).catch((err) => message.error(err.message))}
        />
      ),
    },
  ];

  return (
    <>
      <PageHead
        title="用户管理"
        desc={`StudyMate 统一账号。今日活跃 ${stats.todayActiveCount} 人，今日注册 ${stats.todayRegisteredCount} 人。`}
        extra={
          <Input.Search
            allowClear
            placeholder="搜索邮箱、用户名"
            onSearch={(value) => {
              setPage(1);
              setQuery(value.trim());
            }}
            style={{ width: 280 }}
          />
        }
      />
      <Table rowKey="id" loading={loading} columns={columns} dataSource={rows} pagination={{ current: page, pageSize: PAGE_SIZE, total, onChange: setPage }} scroll={{ x: 980 }} />
    </>
  );
}

function LoginLogs() {
  const [rows, setRows] = useState<LoginLog[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    setLoading(true);
    api<{ logs: LoginLog[] }>("/studymate/login-logs").then((d) => setRows(d.logs)).catch((e) => message.error(e.message)).finally(() => setLoading(false));
  }, []);
  return (
    <>
      <PageHead title="登录日志" desc="StudyMate 统一账号登录记录。" />
      <Table
        rowKey="id"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: "用户名", dataIndex: "username" },
          { title: "登录时间", dataIndex: "loginAt", render: formatTime },
          { title: "地点", dataIndex: "location" },
          { title: "IP", dataIndex: "ip", className: "mono" },
        ]}
        pagination={{ pageSize: PAGE_SIZE }}
      />
    </>
  );
}

function DailyActivity() {
  const [date, setDate] = useState(dayjs());
  const [rows, setRows] = useState<DailyUser[]>([]);
  const [loading, setLoading] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api<{ users: DailyUser[] }>(`/exam/daily-activity?date=${date.format("YYYY-MM-DD")}`)
      .then((d) => setRows(d.users))
      .catch((e) => message.error(e.message))
      .finally(() => setLoading(false));
  }, [date]);
  useEffect(() => void load(), [load]);
  return (
    <>
      <PageHead title="备考活跃" desc="ExamMaster 备考工具登录态访问和模块进入记录。" extra={<Space><DatePicker value={date} onChange={(v) => v && setDate(v)} /><Button onClick={load}>查询</Button></Space>} />
      <Table
        rowKey="userId"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: "邮箱", dataIndex: "email" },
          { title: "用户名", dataIndex: "displayName", render: (v) => v || "—" },
          { title: "首次活跃", dataIndex: "firstSeenAt", render: formatTime },
          { title: "末次活跃", dataIndex: "lastSeenAt", render: formatTime },
          { title: "次数", dataIndex: "pingCount" },
          { title: "IP", dataIndex: "lastIp", className: "mono" },
          { title: "模块", dataIndex: "flags", render: moduleCounts },
        ]}
        pagination={{ pageSize: PAGE_SIZE }}
        scroll={{ x: 900 }}
      />
    </>
  );
}

function HomepageActivity() {
  const [date, setDate] = useState(dayjs());
  const [visitors, setVisitors] = useState<HomepageVisitor[]>([]);
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api<{ visitors: HomepageVisitor[]; projects: ProjectSummary[] }>(`/studymate/homepage-activity?date=${date.format("YYYY-MM-DD")}`)
      .then((d) => {
        setVisitors(d.visitors);
        setProjects(d.projects);
      })
      .catch((e) => message.error(e.message))
      .finally(() => setLoading(false));
  }, [date]);
  useEffect(() => void load(), [load]);
  return (
    <>
      <PageHead title="主页访问" desc="StudyMate 根站访问和工具入口点击。" extra={<Space><DatePicker value={date} onChange={(v) => v && setDate(v)} /><Button onClick={load}>查询</Button></Space>} />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16, marginBottom: 16 }}>
        {projects.map((p) => (
          <Card key={p.projectId} loading={loading}>
            <Statistic title={p.label} value={p.totalClicks} suffix="次点击" />
            <Typography.Text type="secondary">{p.uniqueVisitors} 位访客</Typography.Text>
          </Card>
        ))}
      </div>
      <Table
        rowKey="visitorKey"
        loading={loading}
        dataSource={visitors}
        columns={[
          { title: "访客", render: (_, r) => r.email || "匿名访客" },
          { title: "类型", render: (_, r) => <Tag color={r.isRegistered ? "blue" : "default"}>{r.isRegistered ? "已登录" : "匿名"}</Tag> },
          { title: "首次访问", dataIndex: "firstSeenAt", render: formatTime },
          { title: "末次访问", dataIndex: "lastSeenAt", render: formatTime },
          { title: "次数", dataIndex: "visitCount" },
          { title: "IP", dataIndex: "ip", className: "mono" },
        ]}
        pagination={{ pageSize: PAGE_SIZE }}
      />
    </>
  );
}

function PtoeCodes() {
  const [rows, setRows] = useState<PtoeCode[]>([]);
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();
  const load = useCallback(() => {
    setLoading(true);
    api<{ codes: PtoeCode[] }>("/ptoe/codes").then((d) => setRows(d.codes)).catch((e) => message.error(e.message)).finally(() => setLoading(false));
  }, []);
  useEffect(() => void load(), [load]);
  async function createCode(values: { buyerNote?: string; maxDevices?: number; expiresAt?: dayjs.Dayjs }) {
    const data = await api<{ code: string }>("/ptoe/codes", {
      method: "POST",
      body: JSON.stringify({
        buyerNote: values.buyerNote,
        maxDevices: values.maxDevices,
        expiresAt: values.expiresAt?.toISOString(),
      }),
    });
    Modal.success({ title: "新授权码（仅显示一次）", content: <Typography.Text copyable className="mono">{data.code}</Typography.Text> });
    form.resetFields();
    load();
  }
  async function patchCode(id: string, body: Record<string, unknown>) {
    await api(`/ptoe/codes/${id}`, { method: "PATCH", body: JSON.stringify(body) });
    load();
  }
  return (
    <>
      <PageHead title="周期表授权码" desc="生成、停用和管理 PeriodicTable 授权码。" />
      <Card style={{ marginBottom: 16 }}>
        <Form form={form} layout="inline" onFinish={createCode}>
          <Form.Item name="buyerNote" label="备注"><Input placeholder="例如：微信-张三" /></Form.Item>
          <Form.Item name="maxDevices" label="设备数" initialValue={2}><InputNumber min={1} max={10} /></Form.Item>
          <Form.Item name="expiresAt" label="过期时间"><DatePicker showTime /></Form.Item>
          <Button type="primary" htmlType="submit">生成授权码</Button>
        </Form>
      </Card>
      <Table
        rowKey="id"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: "前缀", dataIndex: "codePrefix", className: "mono" },
          { title: "状态", dataIndex: "status", render: (v) => <Tag color={v === "active" ? "green" : "red"}>{v === "active" ? "启用" : "停用"}</Tag> },
          { title: "设备", render: (_, r) => `${r.activeSessions}/${r.maxDevices}` },
          { title: "备注", dataIndex: "buyerNote", render: (v) => v || "—" },
          { title: "过期", dataIndex: "expiresAt", render: formatTime },
          { title: "创建", dataIndex: "createdAt", render: formatTime },
          {
            title: "操作",
            render: (_, r) => (
              <Space>
                <Button size="small" onClick={() => patchCode(r.id, { status: r.status === "active" ? "disabled" : "active" })}>{r.status === "active" ? "停用" : "启用"}</Button>
                <Button size="small" danger onClick={() => api(`/ptoe/codes/${r.id}/revoke-all`, { method: "POST" }).then(load).catch((e) => message.error(e.message))}>撤销会话</Button>
              </Space>
            ),
          },
        ]}
        pagination={{ pageSize: PAGE_SIZE }}
        scroll={{ x: 980 }}
      />
    </>
  );
}

function PtoeSessions() {
  const [rows, setRows] = useState<PtoeSession[]>([]);
  const [loading, setLoading] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api<{ sessions: PtoeSession[] }>("/ptoe/sessions").then((d) => setRows(d.sessions)).catch((e) => message.error(e.message)).finally(() => setLoading(false));
  }, []);
  useEffect(() => void load(), [load]);
  return (
    <>
      <PageHead title="周期表在线设备" desc="查看设备绑定，必要时强制解绑。" extra={<Button onClick={load}>刷新</Button>} />
      <Table
        rowKey="id"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: "状态", dataIndex: "active", render: (v) => <Tag color={v ? "green" : "default"}>{v ? "在线" : "失效"}</Tag> },
          { title: "授权码", dataIndex: "codePrefix", className: "mono" },
          { title: "备注", dataIndex: "buyerNote", render: (v) => v || "—" },
          { title: "设备", dataIndex: "deviceId", className: "mono", ellipsis: true },
          { title: "最近 IP", dataIndex: "lastIp", className: "mono" },
          { title: "最后访问", dataIndex: "lastSeenAt", render: formatTime },
          { title: "过期", dataIndex: "expiresAt", render: formatTime },
          { title: "操作", render: (_, r) => <Button danger size="small" onClick={() => api(`/ptoe/sessions/${r.id}`, { method: "DELETE" }).then(load).catch((e) => message.error(e.message))}>强制解绑</Button> },
        ]}
        pagination={{ pageSize: PAGE_SIZE }}
        scroll={{ x: 1000 }}
      />
    </>
  );
}

function PtoeLogs() {
  const [rows, setRows] = useState<PtoeLog[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    setLoading(true);
    api<{ logs: PtoeLog[] }>("/ptoe/logs?limit=100").then((d) => setRows(d.logs)).catch((e) => message.error(e.message)).finally(() => setLoading(false));
  }, []);
  return (
    <>
      <PageHead title="周期表激活日志" desc="授权码激活、失败和解绑事件。" />
      <Table
        rowKey="id"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: "时间", dataIndex: "createdAt", render: formatTime },
          { title: "事件", dataIndex: "eventType" },
          { title: "授权码", dataIndex: "codePrefix", className: "mono", render: (v) => v || "—" },
          { title: "备注", dataIndex: "buyerNote", render: (v) => v || "—" },
          { title: "IP", dataIndex: "ip", className: "mono" },
          { title: "详情", dataIndex: "meta", render: (v) => (v ? JSON.stringify(v) : "—") },
        ]}
        pagination={{ pageSize: PAGE_SIZE }}
        scroll={{ x: 900 }}
      />
    </>
  );
}

interface GotItUserRow {
  id: string;
  openidMasked: string;
  nickname: string;
  avatarUrl: string;
  phoneBound: boolean;
  masteredCount: number;
  weakCount: number;
  selectedUnitId: string;
  courseSetupCompleted: boolean;
  progressUpdatedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface GotItDailyUser {
  userId: string;
  nickname: string;
  wordsStudied: number;
  studyMinutes: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

interface GotItFeedbackRow {
  id: string;
  category: string;
  content: string;
  nickname: string;
  createdAt: string;
}

function GotItUsers() {
  const [rows, setRows] = useState<GotItUserRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), pageSize: String(PAGE_SIZE) });
      if (query) params.set("q", query);
      const data = await api<{ users: GotItUserRow[]; total: number }>(`/gotit/users?${params}`);
      setRows(data.users);
      setTotal(data.total);
    } catch (error) {
      message.error(error instanceof Error ? error.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [page, query]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <>
      <PageHead
        title="课本单词通用户"
        desc="GotIt 小程序用户列表（openid 脱敏展示）。"
        extra={<Space><Input.Search allowClear placeholder="搜索昵称/openid" onSearch={(v) => { setPage(1); setQuery(v); }} /><Button onClick={() => void load()}>刷新</Button></Space>}
      />
      <Table
        rowKey="id"
        loading={loading}
        dataSource={rows}
        columns={[
          {
            title: "头像",
            width: 72,
            render: (_, r) => (
              <Avatar src={r.avatarUrl || undefined} size={40}>
                {r.nickname.slice(0, 1) || "?"}
              </Avatar>
            ),
          },
          { title: "昵称", dataIndex: "nickname" },
          { title: "掌握", dataIndex: "masteredCount", width: 72 },
          { title: "生词", dataIndex: "weakCount", width: 72 },
          {
            title: "当前单元",
            dataIndex: "selectedUnitId",
            ellipsis: true,
            render: (v: string) => v || "—",
          },
          {
            title: "进度同步",
            dataIndex: "progressUpdatedAt",
            width: 168,
            render: (v: string | null) => formatTime(v),
          },
          { title: "OpenID", dataIndex: "openidMasked", className: "mono" },
          { title: "手机号", render: (_, r) => (r.phoneBound ? "已绑定" : "—") },
          { title: "注册时间", dataIndex: "createdAt", render: formatTime },
          { title: "更新时间", dataIndex: "updatedAt", render: formatTime },
        ]}
        pagination={{ current: page, pageSize: PAGE_SIZE, total, onChange: setPage }}
        scroll={{ x: 1100 }}
      />
    </>
  );
}

function GotItDailyActivity() {
  const [date, setDate] = useState(dayjs());
  const [rows, setRows] = useState<GotItDailyUser[]>([]);
  const [loading, setLoading] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api<{ users: GotItDailyUser[] }>(`/gotit/daily-activity?date=${date.format("YYYY-MM-DD")}`)
      .then((d) => setRows(d.users))
      .catch((e) => message.error(e.message))
      .finally(() => setLoading(false));
  }, [date]);
  useEffect(() => void load(), [load]);
  return (
    <>
      <PageHead title="课本单词通学习活跃" desc="按日查看 user_daily_stats 学习数据。" extra={<Space><DatePicker value={date} onChange={(v) => v && setDate(v)} /><Button onClick={load}>查询</Button></Space>} />
      <Table
        rowKey="userId"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: "昵称", dataIndex: "nickname" },
          { title: "今日单词", dataIndex: "wordsStudied" },
          { title: "今日时长(分钟)", dataIndex: "studyMinutes" },
          { title: "首次活跃", dataIndex: "firstSeenAt", render: formatTime },
          { title: "末次活跃", dataIndex: "lastSeenAt", render: formatTime },
        ]}
        pagination={{ pageSize: PAGE_SIZE }}
        scroll={{ x: 900 }}
      />
    </>
  );
}

function GotItFeedbacks() {
  const [rows, setRows] = useState<GotItFeedbackRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const load = useCallback(() => {
    setLoading(true);
    api<{ feedbacks: GotItFeedbackRow[]; total: number }>(`/gotit/feedbacks?page=${page}&pageSize=${PAGE_SIZE}`)
      .then((d) => {
        setRows(d.feedbacks);
        setTotal(d.total);
      })
      .catch((e) => message.error(e.message))
      .finally(() => setLoading(false));
  }, [page]);
  useEffect(() => void load(), [load]);
  return (
    <>
      <PageHead title="课本单词通意见反馈" desc="一期文字反馈列表。" extra={<Button onClick={load}>刷新</Button>} />
      <Table
        rowKey="id"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: "类型", dataIndex: "category" },
          { title: "昵称", dataIndex: "nickname" },
          { title: "内容", dataIndex: "content", ellipsis: true },
          { title: "提交时间", dataIndex: "createdAt", render: formatTime },
        ]}
        pagination={{ current: page, pageSize: PAGE_SIZE, total, onChange: setPage }}
        scroll={{ x: 900 }}
      />
    </>
  );
}

export default function App() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    if (!token()) {
      setChecking(false);
      return;
    }
    api<{ user: AuthUser }>("/auth/me")
      .then((data) => setUser(data.user))
      .catch(() => setToken(null))
      .finally(() => setChecking(false));
  }, []);

  if (checking) return <div className="login-screen"><Card>加载中...</Card></div>;
  if (!user) return <LoginPage onLogin={setUser} />;
  return <AdminShell user={user} onLogout={() => setUser(null)} />;
}
