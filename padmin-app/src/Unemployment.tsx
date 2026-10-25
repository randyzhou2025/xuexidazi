import { useEffect, useState } from "react";
import {
  Alert,
  Avatar,
  Card,
  DatePicker,
  Input,
  Space,
  Statistic,
  Table,
  Typography,
} from "antd";
import dayjs from "dayjs";
type Api = <T>(path: string, options?: RequestInit) => Promise<T>;
type User = { id: string; nickname: string; createdAt: string };
type UserRow = User & {
  lastActiveAt: string;
  activeDays: number;
  openidMasked: string;
};
type UserList = {
  users: UserRow[];
  total: number;
  page: number;
  pageSize: number;
  stats: {
    total: number;
    todayNew: number;
    todayActive: number;
    weekActive: number;
  };
};
type DailyRow = {
  user: User;
  firstSeenAt: string;
  lastSeenAt: string;
  visits: number;
};
type Activity = {
  day: string;
  users: DailyRow[];
  total: number;
  page: number;
  pageSize: number;
};
const time = (v: string) =>
  new Date(v).toLocaleString("zh-CN", {
    timeZone: "Asia/Shanghai",
    hour12: false,
  });
function userName(u: User) {
  return (
    <Space>
      <Avatar style={{ background: "#edf3ff", color: "#4773be" }}>
        {u.nickname.slice(0, 1)}
      </Avatar>
      <div>
        <Typography.Text>{u.nickname}</Typography.Text>
        <Typography.Text
          type="secondary"
          style={{ display: "block", fontSize: 11 }}
          copyable
        >
          {u.id}
        </Typography.Text>
      </div>
    </Space>
  );
}
export function UnemploymentUsers({ api }: { api: Api }) {
  const [data, setData] = useState<UserList | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false),
    [query, setQuery] = useState(""),
    [page, setPage] = useState(1),
    [pageSize, setPageSize] = useState(20);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    api<{ data: UserList }>(
      `/unemployment/users?page=${page}&pageSize=${pageSize}&q=${encodeURIComponent(query)}`,
      { signal: controller.signal },
    )
      .then((r) => setData(r.data))
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, page, pageSize, query]);
  return (
    <>
      <Typography.Title level={2}>失业有数用户</Typography.Title>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))",
          gap: 16,
          marginBottom: 20,
        }}
      >
        {(
          [
            ["total", "总用户"],
            ["todayNew", "今日新增"],
            ["todayActive", "今日活跃"],
            ["weekActive", "近7日活跃"],
          ] as const
        ).map(([key, label]) => (
          <Card key={key}>
            <Statistic title={label} value={data?.stats[key] ?? "—"} />
          </Card>
        ))}
      </div>
      {error && (
        <Alert
          type="error"
          showIcon
          message={error}
          style={{ marginBottom: 16 }}
        />
      )}
      <Card>
        <Input.Search
          placeholder="搜索昵称或用户编号"
          allowClear
          onSearch={(v) => {
            setQuery(v);
            setPage(1);
          }}
          style={{ maxWidth: 360, marginBottom: 18 }}
        />
        <Table<UserRow>
          rowKey="id"
          loading={loading}
          dataSource={data?.users || []}
          scroll={{ x: 900 }}
          pagination={{
            current: page,
            pageSize,
            total: data?.total || 0,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100],
            onChange: (p, s) => {
              setPage(p);
              setPageSize(s);
            },
          }}
          columns={[
            { title: "用户", render: (_, u) => userName(u), width: 260 },
            { title: "注册时间", dataIndex: "createdAt", render: time },
            { title: "最近访问", dataIndex: "lastActiveAt", render: time },
            { title: "累计活跃天数", dataIndex: "activeDays", width: 130 },
            { title: "微信标识", dataIndex: "openidMasked", width: 160 },
          ]}
        />
      </Card>
    </>
  );
}
export function UnemploymentActivity({ api }: { api: Api }) {
  const [data, setData] = useState<Activity | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false),
    [date, setDate] = useState(
      dayjs(
        new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Shanghai" }).format(
          new Date(),
        ),
      ),
    ),
    [page, setPage] = useState(1),
    [pageSize, setPageSize] = useState(20);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    api<{ data: Activity }>(
      `/unemployment/activity?day=${date.format("YYYY-MM-DD")}&page=${page}&pageSize=${pageSize}`,
      { signal: controller.signal },
    )
      .then((r) => setData(r.data))
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, date, page, pageSize]);
  return (
    <>
      <Typography.Title level={2}>失业有数访问活跃</Typography.Title>
      <Space style={{ marginBottom: 20 }}>
        <DatePicker
          value={date}
          allowClear={false}
          onChange={(v) => {
            if (v) {
              setDate(v);
              setPage(1);
            }
          }}
        />
        <Typography.Text type="secondary">
          当日活跃 {data?.total ?? "—"} 人 · 北京时间
        </Typography.Text>
      </Space>
      {error && (
        <Alert
          type="error"
          showIcon
          message={error}
          style={{ marginBottom: 16 }}
        />
      )}
      <Card>
        <Table<DailyRow>
          rowKey={(r) => r.user.id}
          loading={loading}
          dataSource={data?.users || []}
          scroll={{ x: 800 }}
          pagination={{
            current: page,
            pageSize,
            total: data?.total || 0,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100],
            onChange: (p, s) => {
              setPage(p);
              setPageSize(s);
            },
          }}
          columns={[
            { title: "用户", render: (_, r) => userName(r.user), width: 260 },
            { title: "首次访问", dataIndex: "firstSeenAt", render: time },
            { title: "最近访问", dataIndex: "lastSeenAt", render: time },
            { title: "访问次数", dataIndex: "visits", width: 120 },
          ]}
        />
      </Card>
    </>
  );
}
export function UnemploymentWorkbench({ section }: { section: string }) {
  return (
    <iframe
      key={section}
      title="失业有数管理工作台"
      src={`/padmin/unemployment/workbench/index.html?embedded=1&section=${encodeURIComponent(section)}`}
      style={{
        width: "100%",
        height: "calc(100vh - 112px)",
        minHeight: 400,
        display: "block",
        border: 0,
        background: "transparent",
      }}
    />
  );
}
