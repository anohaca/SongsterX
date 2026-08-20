import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  Divider,
  Dropdown,
  Field,
  FluentProvider,
  Input,
  Option,
  Select,
  Switch,
  Tab,
  TabList,
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableHeaderCell,
  TableRow,
  Textarea,
  Text,
  Tooltip,
  webDarkTheme,
  webLightTheme,
} from "@fluentui/react-components";
import {
  AppsListRegular,
  ChevronDownRegular,
  ChevronRightRegular,
  CircleRegular,
  DocumentTextRegular,
  FlowRegular,
  GridDotsRegular,
  HomeRegular,
  ListRegular,
  PanelBottomRegular,
  PlayRegular,
  SearchRegular,
  SettingsRegular,
  StopRegular,
} from "@fluentui/react-icons";
import { Fragment, useEffect, useId, useMemo, useRef, useState, type ReactElement, type ReactNode } from "react";

type RuntimeStatus = {
  state: "stopped" | "starting" | "running" | "stopping" | "error" | "exited";
  mode: string;
  listen: string;
  dns: string;
  vmGatewayIp?: string | null;
  vmGatewayDnsIp?: string | null;
  gatewayPacketPathReady: boolean;
  pid: number | null;
  moduleProxy?: string | null;
  message: string;
};

type GuestInterfaceStats = {
  interface: string;
  rxPackets: number;
  txPackets: number;
  rxBytes: number;
  txBytes: number;
};

type GuestPacketStats = {
  lan?: GuestInterfaceStats | null;
  tun?: GuestInterfaceStats | null;
};

type GuestAgentStatus = {
  agentVersion: string;
  activeVersion: string;
  healthy: boolean;
  ready: boolean;
  networkReady: boolean;
  gatewayLanIp?: string | null;
  upstreamInterface?: string | null;
  lastError?: string | null;
  packetStats?: GuestPacketStats | null;
};

type RuntimeLog = {
  timestamp: string;
  timestampUs?: number;
  level: "debug" | "info" | "warn" | "error";
  message: string;
};

type ConnectionRuntime = "host" | "guest" | "system";

type ConnectionEventKind = "connection" | "rule" | "dns" | "socket" | "tls" | "mitm" | "transfer" | "close" | "error";

type ConnectionEvent = {
  id: string;
  timestamp: string;
  timestampUs?: number;
  level: RuntimeLog["level"];
  kind: ConnectionEventKind;
  title: string;
  detail: string;
  requestId?: string;
  runtime: ConnectionRuntime;
  inferred?: boolean;
};

const runtimeRequestPattern = /\[(\d+)(?:\s+\d+ms)?\]\s*(.*)$/;

function runtimeRequestId(message: string): string | null {
  return message.match(runtimeRequestPattern)?.[1] ?? null;
}

function compactRuntimeMessage(message: string): string {
  const match = message.match(runtimeRequestPattern);
  return match ? `[${match[1]}] ${match[2]}` : message;
}

function runtimeLogBody(message: string): string {
  const match = message.match(runtimeRequestPattern);
  return match?.[2] ?? message;
}

function runtimeTimestampUs(log: Pick<RuntimeLog, "timestamp" | "timestampUs">): number | undefined {
  if (typeof log.timestampUs === "number" && Number.isFinite(log.timestampUs)) return log.timestampUs;
  const match = log.timestamp.match(/^unix:(\d+)(?:\.(\d{1,6}))?/);
  if (!match) return undefined;
  const fraction = (match[2] ?? "").padEnd(6, "0");
  const value = Number(match[1]) * 1_000_000 + Number(fraction || "0");
  return Number.isSafeInteger(value) ? value : undefined;
}

function isoFromTimestampUs(timestampUs: number | undefined, fallback = new Date().toISOString()): string {
  if (timestampUs === undefined || !Number.isSafeInteger(timestampUs)) return fallback;
  return new Date(Math.floor(timestampUs / 1_000)).toISOString();
}

function formatPreciseTimestamp(timestamp: string, timestampUs?: number): string {
  const precise = timestampUs ?? runtimeTimestampUs({ timestamp });
  if (precise === undefined) return timestamp;
  const date = new Date(Math.floor(precise / 1_000));
  if (Number.isNaN(date.getTime())) return timestamp;
  const fraction = String(precise % 1_000_000).padStart(6, "0");
  return `${date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}.${fraction}`;
}

function logLevelRank(level: RuntimeLog["level"]): number {
  return { debug: 0, info: 1, warn: 2, error: 3 }[level];
}

function appendRuntimeLog(current: RuntimeLog[], next: RuntimeLog): RuntimeLog[] {
  const requestId = runtimeRequestId(next.message);
  if (!requestId) return [...current.slice(-199), next];

  const existingIndex = current.findIndex((log) => runtimeRequestId(log.message) === requestId);
  if (existingIndex < 0) return [...current.slice(-199), { ...next, message: compactRuntimeMessage(next.message) }];

  const existing = current[existingIndex];
  const existingBody = runtimeLogBody(existing.message);
  const nextBody = runtimeLogBody(next.message);
  const message = existingBody === nextBody || existingBody.includes(nextBody)
    ? `[${requestId}] ${existingBody}`
    : `[${requestId}] ${existingBody} · ${nextBody}`;
  const merged: RuntimeLog = {
    timestamp: next.timestamp,
    timestampUs: next.timestampUs,
    level: logLevelRank(next.level) > logLevelRank(existing.level) ? next.level : existing.level,
    message,
  };
  return [...current.slice(0, existingIndex), ...current.slice(existingIndex + 1), merged].slice(-200);
}

function connectionEventFromRuntimeLog(log: RuntimeLog): ConnectionEvent | null {
  const match = log.message.match(runtimeRequestPattern);
  if (!match) return null;
  const requestId = match[1];
  const detail = match[2].trim();
  const lower = detail.toLowerCase();
  let kind: ConnectionEventKind = "connection";
  let title = "连接";
  if (lower.includes("dns")) {
    kind = "dns";
    title = "DNS";
  } else if (lower.includes("inbound connection from") || lower.includes("accepted")) {
    kind = "connection";
    title = "入口接收";
  } else if (lower.includes("rule") || lower.includes("route") || lower.includes("匹配")) {
    kind = "rule";
    title = "规则";
  } else if (lower.includes("tls") || lower.includes("ssl") || lower.includes("handshake")) {
    kind = "tls";
    title = "TLS";
  } else if (lower.includes("mitm") || lower.includes("mimt") || lower.includes("man-in-the-middle")) {
    kind = "mitm";
    title = "MITM";
  } else if (lower.includes("upload") || lower.includes("download") || lower.includes("stream")) {
    kind = "transfer";
    title = "数据传输";
  } else if (lower.includes("close") || lower.includes("disconnect") || lower.includes("closed") || lower.includes("stop")) {
    kind = "close";
    title = "连接结束";
  } else if (lower.includes("error") || lower.includes("failed") || lower.includes("失败")) {
    kind = "error";
    title = "错误";
  } else if (lower.includes("connect") || lower.includes("socket") || lower.includes("inbound") || lower.includes("outbound")) {
    kind = "socket";
    title = "Socket";
  }
  return {
    id: `event:${Date.now()}:${requestId}:${Math.random().toString(36).slice(2, 8)}`,
    timestampUs: runtimeTimestampUs(log) ?? Date.now() * 1_000,
    timestamp: isoFromTimestampUs(runtimeTimestampUs(log)),
    level: log.level,
    kind,
    title,
    detail,
    requestId,
    runtime: "host",
  };
}

function appendConnectionEvent(current: ConnectionEvent[], next: ConnectionEvent): ConnectionEvent[] {
  const nextUs = next.timestampUs ?? Date.parse(next.timestamp) * 1_000;
  const duplicate = current.some((event) => event.requestId === next.requestId && event.detail === next.detail && Math.abs((event.timestampUs ?? Date.parse(event.timestamp) * 1_000) - nextUs) < 500_000);
  return duplicate ? current : [...current.slice(-999), next];
}

type ConnectionInfo = {
  id: string;
  runtime: ConnectionRuntime;
  logId?: string;
  clashId?: string;
  status: "observed" | "active" | "completed";
  source: string;
  destination: string;
  host: string;
  network: string;
  outbound: string;
  upload?: number | null;
  download?: number | null;
  start: string;
  process?: string;
  pid?: number;
  state?: string;
  systemSocketKey?: string;
  systemId?: string;
  startUs?: number;
  lastSeen?: number;
  lastSeenUs?: number;
  durationMs?: number;
};

type RuntimeConnectionSnapshot = {
  id: string;
  runtime: ConnectionRuntime;
  source: string;
  destination: string;
  host: string;
  network: string;
  outbound: string;
  upload?: number | null;
  download?: number | null;
  start: string;
  process?: string;
  pid?: number;
  state?: string;
  systemSocketKey?: string;
};

function parseConnectionEndpoint(value: string): { host: string; port: string } {
  const match = value.match(/^(.*?)(?::(\d+))?$/);
  return { host: match?.[1] ?? value, port: match?.[2] ?? "" };
}

function connectionFromRuntimeLog(log: RuntimeLog): ConnectionInfo | null {
  const match = log.message.match(runtimeRequestPattern);
  if (!match) return null;
  const id = match[1];
  const body = match[2];
  const source = body.match(/inbound connection from (.+)$/)?.[1] ?? "";
  const destination = body.match(/(?:inbound|outbound) connection to (.+)$/)?.[1] ?? "";
  const outbound = body.match(/outbound\/[^\s\[]+\[([^\]]+)\]/)?.[1] ?? "";
  const startUs = runtimeTimestampUs(log) ?? Date.now() * 1_000;
  return {
    id: `log:${id}`,
    runtime: "host",
    logId: id,
    status: "observed",
    source,
    destination,
    host: parseConnectionEndpoint(destination).host,
    network: "",
    outbound,
    upload: undefined,
    download: undefined,
    start: isoFromTimestampUs(startUs),
    startUs,
    lastSeen: Math.floor(startUs / 1_000),
    lastSeenUs: startUs,
  };
}

function timestampUsFromValue(value: string): number | undefined {
  const unix = value.match(/^unix:(\d+)(?:\.(\d{1,6}))?/);
  if (unix) {
    const fraction = (unix[2] ?? "").padEnd(6, "0");
    return Number(unix[1]) * 1_000_000 + Number(fraction || "0");
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return undefined;
  const fraction = value.match(/\.(\d{1,6})(?:\s|Z|$)/)?.[1];
  return fraction ? Math.floor(parsed / 1_000) * 1_000_000 + Number(fraction.padEnd(6, "0")) : parsed * 1_000;
}

function connectionStartMs(value: string): number | undefined {
  const timestampUs = timestampUsFromValue(value);
  return timestampUs === undefined ? undefined : Math.floor(timestampUs / 1_000);
}

function connectionHost(connection: ConnectionInfo): string {
  return parseConnectionEndpoint(connection.host || connection.destination).host.toLowerCase();
}

function connectionPort(connection: ConnectionInfo): string {
  return parseConnectionEndpoint(connection.destination || connection.host).port;
}

function sameConnectionEndpoint(left: ConnectionInfo, right: ConnectionInfo): boolean {
  if (left.runtime !== right.runtime) return false;
  const leftSource = left.source.trim().toLowerCase();
  const rightSource = right.source.trim().toLowerCase();
  const sourceMatches = Boolean(leftSource && rightSource && leftSource === rightSource);
  const leftHost = connectionHost(left);
  const rightHost = connectionHost(right);
  const hostMatches = Boolean(leftHost && rightHost && leftHost === rightHost);
  const leftPort = connectionPort(left);
  const rightPort = connectionPort(right);
  const portMatches = !leftPort || !rightPort || leftPort === rightPort;
  const sourceIsUnknown = !leftSource || !rightSource;
  return hostMatches && portMatches && (sourceMatches || sourceIsUnknown);
}

function findConnectionIndex(current: ConnectionInfo[], next: ConnectionInfo, excludedIndex = -1): number {
  if (next.systemSocketKey) {
    const systemIndex = current.findIndex((connection, index) => index !== excludedIndex
      && connection.status !== "completed"
      && connection.runtime === "system"
      && connection.systemSocketKey === next.systemSocketKey);
    if (systemIndex >= 0) return systemIndex;
  }
  if (next.clashId) {
    const clashIndex = current.findIndex((connection, index) => index !== excludedIndex && connection.status !== "completed" && connection.runtime === next.runtime && connection.clashId === next.clashId);
    if (clashIndex >= 0) return clashIndex;
  }
  if (next.logId) {
    const logIndex = current.findIndex((connection, index) => index !== excludedIndex && connection.runtime === next.runtime && connection.logId === next.logId);
    if (logIndex >= 0) return logIndex;
  }
  const nextStart = connectionStartMs(next.start) ?? Date.now();
  const candidates = current.map((connection, index) => ({ connection, index })).filter(({ connection, index }) => {
    if (index === excludedIndex) return false;
    if (connection.status === "completed") return false;
    const previousStart = connectionStartMs(connection.start) ?? connection.lastSeen ?? 0;
    return sameConnectionEndpoint(connection, next) && Math.abs(nextStart - previousStart) <= 15_000;
  });
  if (candidates.length !== 1) return -1;
  return candidates[0]?.index ?? -1;
}

function mergeConnectionFields(previous: ConnectionInfo, next: ConnectionInfo): ConnectionInfo {
  const previousStart = connectionStartMs(previous.start);
  const nextStart = connectionStartMs(next.start);
  const start = previousStart !== undefined && nextStart !== undefined
    ? new Date(Math.min(previousStart, nextStart)).toISOString()
    : previous.start || next.start;
  const status = previous.status === "active" || next.status === "active"
    ? "active"
    : previous.status === "completed" || next.status === "completed"
      ? "completed"
      : "observed";
  const previousStartUs = previous.startUs ?? (previousStart === undefined ? undefined : previousStart * 1_000);
  const nextStartUs = next.startUs ?? (nextStart === undefined ? undefined : nextStart * 1_000);
  const startUs = previousStartUs === undefined ? nextStartUs : nextStartUs === undefined ? previousStartUs : Math.min(previousStartUs, nextStartUs);
  const previousLastSeenUs = previous.lastSeenUs ?? (previous.lastSeen === undefined ? undefined : previous.lastSeen * 1_000);
  const nextLastSeenUs = next.lastSeenUs ?? (next.lastSeen === undefined ? undefined : next.lastSeen * 1_000);
  const lastSeenUs = previousLastSeenUs === undefined ? nextLastSeenUs : nextLastSeenUs === undefined ? previousLastSeenUs : Math.max(previousLastSeenUs, nextLastSeenUs);
  return {
    ...previous,
    ...next,
    id: previous.logId ? previous.id : next.logId ? next.id : previous.id,
    logId: previous.logId || next.logId,
    clashId: previous.clashId || next.clashId,
    status,
    source: previous.source || next.source,
    destination: previous.destination || next.destination,
    host: previous.host || next.host,
    network: previous.network || next.network,
    outbound: previous.outbound || next.outbound,
    process: previous.process || next.process,
    pid: previous.pid ?? next.pid,
    state: previous.state || next.state,
    upload: next.upload ?? previous.upload,
    download: next.download ?? previous.download,
    start,
    startUs,
    lastSeen: Math.max(previous.lastSeen ?? 0, next.lastSeen ?? 0) || undefined,
    lastSeenUs,
    durationMs: next.durationMs ?? previous.durationMs,
  };
}

function mergeConnectionInfo(current: ConnectionInfo[], next: ConnectionInfo): ConnectionInfo[] {
  const index = findConnectionIndex(current, next);
  if (index < 0) return [...current.slice(-199), next];
  const duplicateIndex = findConnectionIndex(current, next, index);
  if (duplicateIndex >= 0) {
    const primary = mergeConnectionFields(current[index], current[duplicateIndex]);
    const withoutDuplicate = current.filter((_, currentIndex) => currentIndex !== duplicateIndex);
    const primaryIndex = index > duplicateIndex ? index - 1 : index;
    withoutDuplicate[primaryIndex] = mergeConnectionFields(primary, next);
    return withoutDuplicate.slice(-200);
  }
  const merged = mergeConnectionFields(current[index], next);
  return [...current.slice(0, index), ...current.slice(index + 1), merged].slice(-200);
}

function snapshotToConnection(snapshot: RuntimeConnectionSnapshot, lastSeen: number): ConnectionInfo {
  const startUs = timestampUsFromValue(snapshot.start);
  const isSystem = snapshot.runtime === "system";
  return {
    ...snapshot,
    id: isSystem ? snapshot.id : `clash:${snapshot.runtime}:${snapshot.id}`,
    clashId: isSystem ? undefined : snapshot.id,
    systemId: isSystem ? snapshot.id : undefined,
    status: "active",
    lastSeen,
    lastSeenUs: lastSeen * 1_000,
    startUs,
  };
}

function connectionRuntimeLabel(runtime: ConnectionInfo["runtime"]): string {
  if (runtime === "guest") return "Gateway guest";
  if (runtime === "system") return "系统网络";
  return "Host sing-box";
}

function connectionOutboundLabel(outbound: string): string {
  return outbound === "SYSTEM" ? "系统直连" : outbound || "FINAL";
}

function connectionRuntimeKey(connection: ConnectionInfo): string {
  return `${connection.runtime}:${connection.clashId ?? connection.systemId ?? connection.id}`;
}

function connectionEventsFor(connection: ConnectionInfo, events: ConnectionEvent[]): ConnectionEvent[] {
  const matched = connection.logId
    ? events.filter((event) => event.runtime === connection.runtime && event.requestId === connection.logId)
    : [];
  if (matched.length > 0) return matched;
  const now = connection.start || new Date().toISOString();
  const nowUs = connection.startUs;
  const source = connection.source || "未知客户端";
  const destination = connectionDisplayAddress(connection);
  const inferred: ConnectionEvent[] = [
    {
      id: `inferred:${connection.id}:accepted`,
      timestamp: now,
      timestampUs: nowUs,
      level: "info",
      kind: "connection",
      title: connection.runtime === "system" ? "系统连接快照" : "连接快照",
      detail: connection.runtime === "system"
        ? `macOS 系统连接观察器记录了这条 ${connection.network?.toUpperCase() || "网络"} 连接；仅包含元数据，未读取数据包内容。`
        : `${connectionRuntimeLabel(connection.runtime)}通过 Clash API 报告了这条连接；未提供逐行事件流。`,
      runtime: connection.runtime,
      inferred: true,
    },
    {
      id: `inferred:${connection.id}:route`,
      timestamp: now,
      timestampUs: nowUs,
      level: "info",
      kind: "socket",
      title: "路由",
      detail: `${source} → ${destination}${connection.outbound ? ` · ${connectionOutboundLabel(connection.outbound)}` : ""}${connection.process ? ` · 进程 ${connection.process}${connection.pid ? ` (${connection.pid})` : ""}` : ""}`,
      runtime: connection.runtime,
      inferred: true,
    },
  ];
  if (connection.status === "completed") {
    inferred.push({
      id: `inferred:${connection.id}:closed`,
      timestamp: connection.lastSeen ? new Date(connection.lastSeen).toISOString() : now,
      timestampUs: connection.lastSeenUs,
      level: "info",
      kind: "close",
      title: "连接结束",
      detail: `连接已完成${connection.durationMs === undefined ? "" : `，持续 ${formatConnectionDuration(connection, connection.lastSeenUs ?? Date.now() * 1_000)}`}`,
      runtime: connection.runtime,
      inferred: true,
    });
  }
  return inferred;
}

function isIngressConnectionEvent(event: ConnectionEvent): boolean {
  const detail = event.detail.toLowerCase();
  return detail.includes("inbound connection from") || event.title === "入口接收";
}

function completeConnection(connection: ConnectionInfo, finishedAtUs: number): ConnectionInfo {
  if (connection.status !== "active") return connection;
  const startedAtUs = connection.startUs ?? (() => {
    const startedAt = connectionStartMs(connection.start);
    return startedAt === undefined ? undefined : startedAt * 1_000;
  })();
  return {
    ...connection,
    status: "completed",
    durationMs: startedAtUs === undefined ? undefined : Math.max(0, (finishedAtUs - startedAtUs) / 1_000),
    lastSeen: Math.floor(finishedAtUs / 1_000),
    lastSeenUs: finishedAtUs,
  };
}

function endSystemObservation(connection: ConnectionInfo, finishedAtUs: number): ConnectionInfo {
  if (connection.runtime !== "system" || connection.status !== "active") return connection;
  const startedAtUs = connection.startUs ?? timestampUsFromValue(connection.start);
  return {
    ...connection,
    status: "observed",
    durationMs: startedAtUs === undefined ? undefined : Math.max(0, (finishedAtUs - startedAtUs) / 1_000),
    lastSeen: Math.floor(finishedAtUs / 1_000),
    lastSeenUs: finishedAtUs,
  };
}

type RuntimeMetrics = {
  uploadTotal: number;
  downloadTotal: number;
  activeConnections: number;
  memory: number;
  connections: RuntimeConnectionSnapshot[];
  hostSnapshotValid: boolean;
  hostSnapshotError?: string | null;
  guestSnapshotValid: boolean;
  guestSnapshotError?: string | null;
  systemSnapshotValid: boolean;
  systemSnapshotError?: string | null;
};

type ProxyNode = {
  tag: string;
  type: string;
  server: string;
  serverPort: number;
  serverPorts: string;
  hopInterval: string;
  hopIntervalMax: string;
  password: string;
  username: string;
  sni: string;
  network: string;
  wsPath: string;
  wsHost: string;
  transportMethod: string;
  transportServiceName: string;
  transportHeaders: string;
  transportIdleTimeout: string;
  transportPingTimeout: string;
  transportPermitWithoutStream: boolean;
  transportMaxEarlyData: number;
  transportEarlyDataHeaderName: string;
  transportQuicSecurity: string;
  transportQuicKey: string;
  insecure: boolean;
  tlsEnabled: boolean;
  tlsEngine: string;
  tlsDisableSni: boolean;
  tlsAlpn: string;
  tlsMinVersion: string;
  tlsMaxVersion: string;
  tlsCertificatePath: string;
  tlsCertificatePublicKeySha256: string;
  tlsHandshakeTimeout: string;
  tlsUtlFingerprint: string;
  tlsRealityPublicKey: string;
  tlsRealityShortId: string;
  uuid: string;
  method: string;
  plugin: string;
  pluginOptions: string;
  flow: string;
  packetEncoding: string;
  security: string;
  alterId: number;
  version: number;
  privateKey: string;
  privateKeyPath: string;
  peerPublicKey: string;
  preSharedKey: string;
  localAddress: string;
  wireguardSystemInterface: boolean;
  wireguardInterfaceName: string;
  wireguardMtu: number;
  wireguardWorkers: number;
  wireguardNetwork: string;
  wireguardReserved: string;
  upMbps: number;
  downMbps: number;
  upBandwidth: string;
  downBandwidth: string;
  authBase64: string;
  obfs: string;
  obfsPassword: string;
  congestionControl: string;
  udpRelayMode: string;
  zeroRttHandshake: boolean;
  heartbeat: string;
  tuicUdpOverStream: boolean;
  idleSessionCheckInterval: string;
  idleSessionExpiration: string;
  minIdleSession: number;
  psk: string;
  snellUserkey: string;
  snellReuse: boolean;
  snellObfsMode: string;
  snellObfsHost: string;
  snellMode: string;
  sshPrivateKey: string;
  sshPrivateKeyPassphrase: string;
  sshHostKey: string;
  sshHostKeyAlgorithms: string;
  sshClientVersion: string;
  sshCipher: string;
  sshMac: string;
  sshKexAlgorithm: string;
  executablePath: string;
  dataDirectory: string;
  torArgs: string;
  anytlsClientMetadata: string;
  detour: string;
  bindInterface: string;
  inet4BindAddress: string;
  inet6BindAddress: string;
  bindAddressNoPort: boolean;
  routingMark: number;
  reuseAddr: boolean;
  connectTimeout: string;
  tcpFastOpen: boolean;
  tcpMultiPath: boolean;
  disableTcpKeepAlive: boolean;
  tcpKeepAlive: string;
  tcpKeepAliveInterval: string;
  udpFragment: boolean;
  domainResolver: string;
  networkStrategy: string;
  networkType: string;
  fallbackNetworkType: string;
  fallbackDelay: string;
  domainStrategy: string;
  multiplexEnabled: boolean;
  multiplexProtocol: string;
  multiplexMaxConnections: number;
  multiplexMinStreams: number;
  multiplexMaxStreams: number;
  multiplexPadding: boolean;
  multiplexBrutal: string;
  extraJson: string;
};

type PolicyGroup = {
  name: string;
  type: string;
  members: string[];
  default: string;
  url: string;
  interval: string;
  tolerance: number;
  idleTimeout: string;
  interruptExistConnections: boolean;
};

type RuleCondition = {
  id: string;
  type: "field" | "logical";
  field?: string;
  value?: string;
  mode?: "and" | "or";
  invert?: boolean;
  rules?: RuleCondition[];
};

type RuleSetConfig = {
  type: "local" | "remote";
  tag: string;
  format: "source" | "binary";
  path: string;
  url: string;
  updateInterval: string;
};

type ProxyRule = {
  id: string;
  name: string;
  action: "route" | "reject" | "hijack-dns";
  outbound: string;
  enabled: boolean;
  condition: RuleCondition;
};

type ProxyConfig = {
  nodes: ProxyNode[];
  groups: PolicyGroup[];
  rules: ProxyRule[];
  ruleSets: RuleSetConfig[];
};

type ProxyInfo = {
  name: string;
  kind: string;
  now: string;
  all: string[];
};

type ModuleInfo = {
  id: string;
  name: string;
  description: string;
  version: string;
  localFile: string;
  source: string;
  sha256: string;
  verified: boolean;
  enabled: boolean;
  sections: string[];
  scriptAssets: string[];
  mitmHostnames: string[];
  ruleCount: number;
  scriptCount: number;
  runtimeStatus: string;
  warning: string;
  arguments: ModuleArgumentInfo[];
};

type ConfigDocument = {
  id: string;
  title: string;
  path: string;
  content: string;
};

type ModuleArgumentInfo = {
  name: string;
  defaultValue: string;
  value: string;
  description: string;
};

type RuntimeSettings = {
  mode: "mixed" | "gateway";
  listen: string;
  port: number;
  dnsMode: "system" | "custom" | "fakeip";
  dnsServer: string;
  singBoxPath: string;
  vmnetHelperPath: string;
  vfkitPath: string;
  gatewayGuestKernelPath: string;
  gatewayGuestInitrdPath: string;
  gatewayGuestCmdline: string;
  gatewayGuestCpus: number;
  gatewayGuestMemoryMib: number;
  gatewayHostIp: string;
  gatewayGuestHostIp: string;
  gatewayHostCidr: string;
  gatewayGuestAgentPort: number;
  gatewayGuestLanSelector: string;
  gatewayGuestHostSelector: string;
  gatewayUpstreamGateway: string;
  gatewayLanInterface: string;
  gatewayIp: string;
  gatewayCidr: string;
  gatewayDnsIp: string;
  gatewayClients: string;
  gatewayClientPolicy: "all" | "allowlist";
  gatewayPolicyMode: "shared" | "separate";
  logLevel: "trace" | "debug" | "info" | "warn" | "error";
};

type ProxyConfigTarget = "host" | "guest";

type AppearanceMode = "system" | "light" | "dark";

type View = "overview" | "activity" | "strategy" | "rules" | "modules" | "config" | "settings";

function loadAppearanceMode(): AppearanceMode {
  if (typeof window === "undefined") return "system";
  try {
    const stored = window.localStorage.getItem("songsterx.appearance");
    return stored === "light" || stored === "dark" ? stored : "system";
  } catch {
    return "system";
  }
}

const defaultStatus: RuntimeStatus = {
  state: "stopped",
  mode: "mixed direct",
  listen: "127.0.0.1:2080",
  dns: "系统 DNS",
  vmGatewayIp: null,
  vmGatewayDnsIp: null,
  gatewayPacketPathReady: false,
  pid: null,
  moduleProxy: null,
  message: "尚未启动",
};

const defaultSettings: RuntimeSettings = {
  mode: "mixed",
  listen: "127.0.0.1",
  port: 2080,
  dnsMode: "system",
  dnsServer: "223.5.5.5",
  singBoxPath: "",
  vmnetHelperPath: "",
  vfkitPath: "",
  gatewayGuestKernelPath: "",
  gatewayGuestInitrdPath: "",
  gatewayGuestCmdline: "console=hvc0 quiet",
  gatewayGuestCpus: 1,
  gatewayGuestMemoryMib: 512,
  gatewayHostIp: "192.168.250.1",
  gatewayGuestHostIp: "192.168.250.2",
  gatewayHostCidr: "192.168.250.0/24",
  gatewayGuestAgentPort: 38291,
  gatewayGuestLanSelector: "",
  gatewayGuestHostSelector: "",
  gatewayUpstreamGateway: "",
  gatewayLanInterface: "",
  gatewayIp: "",
  gatewayCidr: "",
  gatewayDnsIp: "",
  gatewayClients: "",
  gatewayClientPolicy: "all",
  gatewayPolicyMode: "shared",
  logLevel: "info",
};

const songsterDarkTheme = {
  ...webDarkTheme,
  colorNeutralBackground1: "#242426",
  colorNeutralBackground2: "#1c1c1e",
  colorNeutralBackground3: "#2c2c2e",
  colorNeutralBackground4: "#333336",
  colorNeutralForeground1: "#f5f5f7",
  colorNeutralForeground2: "#a1a1a6",
  colorNeutralForeground3: "#6e6e73",
  colorNeutralStroke1: "rgba(255, 255, 255, .1)",
  colorNeutralStroke2: "rgba(255, 255, 255, .06)",
  colorBrandBackground: "#0a84ff",
  colorBrandBackgroundHover: "#409cff",
  colorBrandForeground1: "#ffffff",
};

const songsterLightTheme = {
  ...webLightTheme,
  colorBrandBackground: "#0071e3",
  colorBrandBackgroundHover: "#0077ed",
  colorBrandForeground1: "#ffffff",
};

const pageTitles: Record<View, string> = {
  overview: "概览",
  activity: "活动",
  strategy: "策略",
  rules: "规则",
  modules: "模块",
  config: "配置文件",
  settings: "设置",
};

function App() {
  const [view, setView] = useState<View>("overview");
  const [status, setStatus] = useState<RuntimeStatus>(defaultStatus);
  const [guestStatus, setGuestStatus] = useState<GuestAgentStatus | null>(null);
  const [guestStatusError, setGuestStatusError] = useState("");
  const [settings, setSettings] = useState<RuntimeSettings>(defaultSettings);
  const [persistedSettings, setPersistedSettings] = useState<RuntimeSettings>(defaultSettings);
  const [logs, setLogs] = useState<RuntimeLog[]>([]);
  const [connectionEvents, setConnectionEvents] = useState<ConnectionEvent[]>([]);
  const [metrics, setMetrics] = useState<RuntimeMetrics>({ uploadTotal: 0, downloadTotal: 0, activeConnections: 0, memory: 0, connections: [], hostSnapshotValid: true, hostSnapshotError: null, guestSnapshotValid: true, guestSnapshotError: null, systemSnapshotValid: true, systemSnapshotError: null });
  const [connectionHistory, setConnectionHistory] = useState<ConnectionInfo[]>([]);
  const [proxyConfig, setProxyConfig] = useState<ProxyConfig>({ nodes: [], groups: [], rules: [], ruleSets: [] });
  const [guestProxyConfig, setGuestProxyConfig] = useState<ProxyConfig>({ nodes: [], groups: [], rules: [], ruleSets: [] });
  const [proxyConfigTarget, setProxyConfigTarget] = useState<ProxyConfigTarget>("host");
  const [proxies, setProxies] = useState<ProxyInfo[]>([]);
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [configDocuments, setConfigDocuments] = useState<ConfigDocument[]>([]);
  const [configError, setConfigError] = useState("");
  const [testingProxy, setTestingProxy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [settingsMessage, setSettingsMessage] = useState("");
  const [appearanceMode, setAppearanceMode] = useState<AppearanceMode>(loadAppearanceMode);
  const [systemDark, setSystemDark] = useState(true);
  const prefersDark = appearanceMode === "dark" || (appearanceMode === "system" && systemDark);

  const isRunning = status.state === "running";
  const isActive = isRunning || status.state === "starting" || status.state === "stopping";
  const settingsDirty = useMemo(
    () => JSON.stringify(settings) !== JSON.stringify(persistedSettings),
    [settings, persistedSettings],
  );
  const visibleGateway = isActive && status.mode.includes("gateway");
  const statusLabel = useMemo(() => {
    if (status.state === "running") return "运行中";
    if (status.state === "starting") return "启动中";
    if (status.state === "stopping") return "停止中";
    if (status.state === "error") return "错误";
    if (status.state === "exited") return "已退出";
    return "已停止";
  }, [status.state]);

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const updateTheme = () => setSystemDark(media.matches);
    updateTheme();
    media.addEventListener("change", updateTheme);
    return () => media.removeEventListener("change", updateTheme);
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem("songsterx.appearance", appearanceMode);
    } catch {
      // 本地存储不可用时仍保留当前会话的主题选择。
    }
  }, [appearanceMode]);

  useEffect(() => {
    // Fluent UI 的 Dialog 通过 Portal 挂载到 body，不能继承 Provider 内的自定义主题变量。
    // 将主题类同步到 html，使弹窗及其 Portal 内容也能使用 --sx-* 变量。
    const root = document.documentElement;
    root.classList.toggle("theme-dark", prefersDark);
    root.classList.toggle("theme-light", !prefersDark);
  }, [prefersDark]);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let unlistenMetrics: UnlistenFn | undefined;
    void (async () => {
      unlisten = await listen<RuntimeLog>("runtime-log", (event) => {
        setLogs((current) => appendRuntimeLog(current, event.payload));
        const traceEvent = connectionEventFromRuntimeLog(event.payload);
        if (traceEvent) {
          setConnectionEvents((current) => appendConnectionEvent(current, traceEvent));
          if (traceEvent.kind === "close" && traceEvent.requestId) {
            setConnectionHistory((current) => current.map((connection) => connection.logId === traceEvent.requestId
              ? completeConnection(connection, traceEvent.timestampUs ?? Date.now() * 1_000)
              : connection));
          }
        }
        const connection = connectionFromRuntimeLog(event.payload);
        if (connection) setConnectionHistory((current) => mergeConnectionInfo(current, connection));
      });
      unlistenMetrics = await listen<RuntimeMetrics>("runtime-metrics", (event) => {
        setMetrics(event.payload);
        setConnectionHistory((current) => {
          const lastSeenUs = Date.now() * 1_000;
          const lastSeen = Math.floor(lastSeenUs / 1_000);
          const activeSnapshots = event.payload.connections.map((connection) => snapshotToConnection(connection, lastSeen));
          const merged = activeSnapshots.reduce((history, connection) => mergeConnectionInfo(history, connection), current);
          const activeIds = new Set(activeSnapshots.map((connection) => connectionRuntimeKey(connection)));
          const snapshotValid: Record<ConnectionRuntime, boolean> = {
            host: event.payload.hostSnapshotValid !== false,
            guest: event.payload.guestSnapshotValid !== false,
            system: event.payload.systemSnapshotValid !== false,
          };
          return merged.map((connection) => (connection.clashId || connection.runtime === "system") && !activeIds.has(connectionRuntimeKey(connection)) && snapshotValid[connection.runtime]
            ? completeConnection(connection, lastSeenUs)
            : connection);
        });
      });
      await refreshStatus();
      await refreshSettings();
      await refreshProxyConfig();
      await refreshModules();
      await refreshConfigDocuments();
    })();
    return () => {
      unlisten?.();
      unlistenMetrics?.();
    };
  }, []);

  function addLocalLog(level: RuntimeLog["level"], message: string) {
    const timestampUs = Date.now() * 1_000;
    setLogs((current) => appendRuntimeLog(current, { timestamp: new Date(timestampUs / 1_000).toISOString(), timestampUs, level, message }));
  }

  async function refreshStatus() {
    try {
      setStatus(await invoke<RuntimeStatus>("get_runtime_status"));
    } catch (error) {
      addLocalLog("error", String(error));
    }
  }

  useEffect(() => {
    if (status.state !== "starting" && status.state !== "stopping") return;
    const timer = window.setInterval(() => {
      void refreshStatus();
    }, 250);
    return () => window.clearInterval(timer);
  }, [status.state]);

  useEffect(() => {
    if (status.state !== "stopped") return;
    const stoppedAtUs = Date.now() * 1_000;
    setMetrics((current) => ({ ...current, activeConnections: 0, connections: [] }));
    setConnectionHistory((current) => current.map((connection) => connection.runtime === "system"
      ? endSystemObservation(connection, stoppedAtUs)
      : completeConnection(connection, stoppedAtUs)));
  }, [status.state]);

  async function refreshSettings() {
    try {
      const loaded = await invoke<RuntimeSettings>("get_runtime_settings");
      setSettings(loaded);
      setPersistedSettings(loaded);
    } catch (error) {
      addLocalLog("error", String(error));
    }
  }

  async function refreshProxyConfig() {
    try {
      const [host, guest] = await Promise.all([
        invoke<ProxyConfig>("get_proxy_config"),
        invoke<ProxyConfig>("get_gateway_guest_proxy_config"),
      ]);
      setProxyConfig(host);
      setGuestProxyConfig(guest);
    } catch (error) {
      addLocalLog("error", String(error));
    }
  }

  async function refreshModules() {
    try {
      setModules(await invoke<ModuleInfo[]>("get_modules"));
    } catch (error) {
      addLocalLog("error", String(error));
    }
  }

  async function refreshConfigDocuments() {
    try {
      setConfigDocuments(await invoke<ConfigDocument[]>("get_config_documents"));
      setConfigError("");
    } catch (error) {
      setConfigError(String(error));
      addLocalLog("error", String(error));
    }
  }

  async function reloadConfigDocuments() {
    try {
      await invoke("reload_songsterx_config");
      await Promise.all([refreshSettings(), refreshProxyConfig(), refreshModules(), refreshConfigDocuments()]);
      addLocalLog("info", "已从 SongsterX.conf 重载配置。");
    } catch (error) {
      addLocalLog("error", String(error));
      throw error;
    }
  }

  async function importModules(files: File[]) {
    try {
      const importedFiles = await Promise.all(files.map(async (file) => ({ name: file.name, content: await file.text() })));
      setModules(await invoke<ModuleInfo[]>("import_module", { files: importedFiles }));
      addLocalLog("info", `已导入模块：${files[0]?.name || "未命名模块"}`);
    } catch (error) {
      addLocalLog("error", String(error));
      throw error;
    }
  }

  async function importModuleUrl(url: string) {
    try {
      setModules(await invoke<ModuleInfo[]>("import_module_url", { url }));
      addLocalLog("info", `已从网络导入模块：${url}`);
    } catch (error) {
      addLocalLog("error", String(error));
      throw error;
    }
  }

  async function toggleModule(id: string, enabled: boolean) {
    try {
      setModules(await invoke<ModuleInfo[]>("set_module_enabled", { id, enabled }));
      addLocalLog("info", enabled ? `模块已启用：${id}（下次启动时生成运行计划）` : `模块已停用：${id}`);
    } catch (error) {
      addLocalLog("error", String(error));
    }
  }

  async function setModuleArgument(id: string, key: string, value: string) {
    try {
      setModules(await invoke<ModuleInfo[]>("set_module_argument", { id, key, value }));
      addLocalLog("info", `模块参数已保存：${id}.${key}`);
    } catch (error) {
      addLocalLog("error", String(error));
      throw error;
    }
  }

  async function refreshProxies(quiet = false) {
    try {
      const target = settings.gatewayPolicyMode === "separate" ? proxyConfigTarget : "host";
      setProxies(await invoke<ProxyInfo[]>("get_proxies", { target }));
    } catch (error) {
      if (!quiet) addLocalLog("error", String(error));
    }
  }

  async function selectProxy(group: string, name: string) {
    try {
      const target = settings.gatewayPolicyMode === "separate" ? proxyConfigTarget : "host";
      await invoke("select_proxy", { group, name, target });
      await refreshProxies();
    } catch (error) {
      addLocalLog("error", String(error));
    }
  }

  async function testProxyDelay(name: string): Promise<number> {
    const target = settings.gatewayPolicyMode === "separate" ? proxyConfigTarget : "host";
    return invoke<number>("test_proxy_delay", { name, url: "http://www.gstatic.com/generate_204", timeoutMs: 5_000, target });
  }

  async function saveProxyConfig(config: ProxyConfig, target: ProxyConfigTarget = "host"): Promise<ProxyConfig> {
    const wasRunning = isActive;
    try {
      if (wasRunning) {
        setStatus(await invoke<RuntimeStatus>("stop_runtime"));
      }
      const command = target === "guest" ? "save_gateway_guest_proxy_config" : "save_proxy_config";
      const saved = await invoke<ProxyConfig>(command, { config });
      if (target === "guest") setGuestProxyConfig(saved);
      else setProxyConfig(saved);
      if (wasRunning) {
        setStatus(await invoke<RuntimeStatus>("start_mix_direct"));
        await refreshProxies(true);
        addLocalLog("info", "代理配置已保存并重新加载运行时。");
      } else {
        addLocalLog("info", "代理配置已保存，下次启动时生效。");
      }
      return saved;
    } catch (error) {
      if (wasRunning) {
        try {
          setStatus(await invoke<RuntimeStatus>("start_mix_direct"));
        } catch (restartError) {
          addLocalLog("error", `配置保存后重新启动失败：${String(restartError)}`);
        }
      }
      addLocalLog("error", String(error));
      throw error;
    }
  }

  async function toggleRuntime() {
    if (status.state === "stopping") return;
    setBusy(true);
    try {
      const shouldStop = status.state === "running" || status.state === "starting";
      if (!shouldStop && settingsDirty) {
        const saved = await invoke<RuntimeSettings>("save_runtime_settings", { settings });
        setSettings(saved);
        setPersistedSettings(saved);
        addLocalLog("info", "已自动保存入口设置，启动时将同时使用 Mixed 和所选网关模式。");
      }
      if (!shouldStop) setConnectionHistory([]);
      setStatus(await invoke<RuntimeStatus>(shouldStop ? "stop_runtime" : "start_mix_direct"));
    } catch (error) {
      const message = String(error);
      setSettingsMessage(message);
      setStatus((current) => current.state === "stopped" ? { ...current, state: "error", message } : current);
      addLocalLog("error", message);
      await refreshStatus();
      setStatus((current) => current.state === "stopped" ? { ...current, state: "error", message } : current);
    } finally {
      setBusy(false);
    }
  }

  async function saveSettings() {
    setSettingsBusy(true);
    setSettingsMessage("");
    try {
      const saved = await invoke<RuntimeSettings>("save_runtime_settings", { settings });
      setSettings(saved);
      setPersistedSettings(saved);
      await refreshProxyConfig();
      setSettingsMessage("设置已保存；点击启动后按当前入口配置运行。");
    } catch (error) {
      setSettingsMessage(String(error));
    } finally {
      setSettingsBusy(false);
    }
  }

  async function resetSettings() {
    setSettingsBusy(true);
    setSettingsMessage("");
    try {
      const reset = await invoke<RuntimeSettings>("reset_runtime_settings");
      setSettings(reset);
      setPersistedSettings(reset);
      setProxyConfigTarget("host");
      await refreshProxyConfig();
      setSettingsMessage("已恢复默认设置。");
    } catch (error) {
      setSettingsMessage(String(error));
    } finally {
      setSettingsBusy(false);
    }
  }

  useEffect(() => {
    if (view !== "strategy" || !isActive || testingProxy) return;
    void refreshProxies(true);
    const timer = window.setInterval(() => void refreshProxies(true), 3000);
    return () => window.clearInterval(timer);
  }, [view, isActive, testingProxy, proxyConfigTarget, settings.gatewayPolicyMode]);

  useEffect(() => {
    if (!isActive || !status.mode.includes("gateway")) {
      setGuestStatus(null);
      setGuestStatusError("");
      return;
    }

    let cancelled = false;
    const refreshGuestStatus = async () => {
      try {
        const next = await invoke<GuestAgentStatus>("get_gateway_guest_status");
        if (!cancelled) {
          setGuestStatus(next);
          setGuestStatusError("");
          void refreshStatus();
        }
      } catch (error) {
        if (!cancelled) setGuestStatusError(String(error));
      }
    };

    void refreshGuestStatus();
    const timer = window.setInterval(() => void refreshGuestStatus(), 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [isActive, status.mode]);

  const title = pageTitles[view];
  const subtitle = view === "overview"
    ? (visibleGateway ? "Mixed + 局域网网关 · 不含 DHCP" : "本地 Mixed 代理")
    : view === "activity"
      ? "请求记录与运行日志"
      : view === "strategy"
        ? "出站策略引擎"
        : view === "rules"
          ? "逻辑规则引擎"
        : view === "modules"
          ? "导入的模块、脚本和规则集"
        : view === "config"
          ? "SongsterX.conf 与 sing-box 运行时文件"
        : "应用偏好";

  return (
    <FluentProvider theme={prefersDark ? songsterDarkTheme : songsterLightTheme} className={prefersDark ? "theme-dark" : "theme-light"}>
      <div className="songster-provider">
        <div className="app-shell">
          <Sidebar view={view} onNavigate={setView} />
          <main className="app-main">
            <header className="top-bar">
              <div className="top-bar-title">
                <Text as="h1" size={600} weight="semibold">{title}</Text>
                <Text className="top-bar-subtitle" size={200}>{subtitle}</Text>
              </div>
              <div className="top-bar-actions">
                <StatusBadge status={status} label={statusLabel} /><Badge className="mode-badge" appearance="outline" color={visibleGateway ? "informative" : "subtle"}>{visibleGateway ? "Mixed + 网关" : "Mixed"}</Badge>
                <Button appearance="subtle" onClick={() => void refreshStatus()}>刷新</Button>
                <Button appearance={isActive ? "secondary" : "primary"} icon={isActive ? <StopRegular /> : <PlayRegular />} disabled={busy} onClick={() => void toggleRuntime()}>
                  {busy ? "处理中…" : isActive ? "停止" : "启动"}
                </Button>
              </div>
            </header>

            {view === "overview" && <OverviewPage status={status} settings={settings} settingsDirty={settingsDirty} metrics={metrics} running={isActive} guestStatus={guestStatus} guestStatusError={guestStatusError} onNavigate={setView} />}
            {view === "activity" && <ActivityPage connections={connectionHistory} connectionEvents={connectionEvents} running={isActive} logs={logs} hostSnapshotValid={metrics.hostSnapshotValid} hostSnapshotError={metrics.hostSnapshotError} guestSnapshotValid={metrics.guestSnapshotValid} guestSnapshotError={metrics.guestSnapshotError} systemSnapshotValid={metrics.systemSnapshotValid} systemSnapshotError={metrics.systemSnapshotError} onClear={() => { setLogs([]); setConnectionEvents([]); }} />}
            {view === "strategy" && <StrategyPage config={proxyConfigTarget === "guest" && settings.gatewayPolicyMode === "separate" ? guestProxyConfig : proxyConfig} proxies={proxies} running={isActive} policyMode={settings.gatewayPolicyMode} target={proxyConfigTarget} onTargetChange={setProxyConfigTarget} onSelect={(group, name) => void selectProxy(group, name)} onTestDelay={testProxyDelay} onTestingChange={setTestingProxy} onSave={async (config, target) => { await saveProxyConfig(config, target); }} />}
            {view === "rules" && <RulesPage config={proxyConfigTarget === "guest" && settings.gatewayPolicyMode === "separate" ? guestProxyConfig : proxyConfig} running={isActive} policyMode={settings.gatewayPolicyMode} target={proxyConfigTarget} onTargetChange={setProxyConfigTarget} onSave={async (config, target) => { await saveProxyConfig(config, target); }} />}
            {view === "modules" && <ModulesPage modules={modules} onToggleModule={toggleModule} onSetModuleArgument={setModuleArgument} onImportModule={importModules} onImportModuleUrl={importModuleUrl} />}
            {view === "config" && <div className="page-content page-stack"><ConfigViewer documents={configDocuments} error={configError} onRefresh={refreshConfigDocuments} onReload={reloadConfigDocuments} /></div>}
            {view === "settings" && <SettingsPage settings={settings} settingsDirty={settingsDirty} running={isActive} runtimeBusy={busy} busy={settingsBusy} message={settingsMessage} appearanceMode={appearanceMode} onAppearanceChange={setAppearanceMode} onChange={setSettings} onSave={() => void saveSettings()} onReset={() => void resetSettings()} onStop={() => void toggleRuntime()} />}
          </main>
        </div>
      </div>
    </FluentProvider>
  );
}

function Sidebar({ view, onNavigate }: { view: View; onNavigate: (view: View) => void }) {
  return (
    <aside className="app-sidebar">
      <div className="brand-block">
        <div className="brand-mark"><GridDotsRegular /></div>
        <div>
          <Text className="brand-name" weight="semibold">SongsterX</Text>
          <Text className="brand-version" size={100}>MIXED RUNTIME · 0.1</Text>
        </div>
      </div>
      <nav className="sidebar-nav" aria-label="主导航">
        <NavItem active={view === "overview"} label="概览" icon={<HomeRegular />} onClick={() => onNavigate("overview")} />
        <NavItem active={view === "activity"} label="活动" icon={<PanelBottomRegular />} onClick={() => onNavigate("activity")} />
        <NavGroup label="配置">
          <NavItem active={view === "strategy"} label="策略" icon={<FlowRegular />} onClick={() => onNavigate("strategy")} />
          <NavItem active={view === "rules"} label="规则" icon={<ListRegular />} onClick={() => onNavigate("rules")} />
          <NavItem active={view === "modules"} label="模块" icon={<AppsListRegular />} onClick={() => onNavigate("modules")} />
          <NavItem active={view === "config"} label="配置文件" icon={<DocumentTextRegular />} onClick={() => onNavigate("config")} />
        </NavGroup>
      </nav>
      <div className="sidebar-bottom">
        <NavItem active={view === "settings"} label="设置" icon={<AppsListRegular />} onClick={() => onNavigate("settings")} />
      </div>
    </aside>
  );
}

function NavGroup({ label, children }: { label: string; children: ReactNode }) {
  return <section className="nav-group"><Text className="nav-group-label" size={100}>{label}</Text>{children}</section>;
}

function NavItem({ active, label, icon, badge, onClick }: { active: boolean; label: string; icon: ReactElement; badge?: string; onClick: () => void }) {
  return <Button className={`nav-item ${active ? "active" : ""}`} appearance="subtle" icon={icon} aria-current={active ? "page" : undefined} onClick={onClick}><span className="nav-item-label">{label}</span>{badge && <Badge className="nav-item-badge" appearance="outline" color="subtle" size="small">{badge}</Badge>}</Button>;
}

function StatusBadge({ status, label }: { status: RuntimeStatus; label: string }) {
  const color = status.state === "running" ? "success" : status.state === "error" || status.state === "exited" ? "danger" : "subtle";
  return <Badge className={`status-badge status-${status.state}`} appearance="tint" color={color as "success" | "danger" | "subtle"}><span className="status-dot" />{label}</Badge>;
}

function SectionHeading({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return <div className="section-heading"><div><Text as="h2" size={500} weight="semibold">{title}</Text>{description && <Text className="section-description" size={300}>{description}</Text>}</div>{action}</div>;
}

function OverviewPage({ status, settings, settingsDirty, metrics, running, guestStatus, guestStatusError, onNavigate }: { status: RuntimeStatus; settings: RuntimeSettings; settingsDirty: boolean; metrics: RuntimeMetrics; running: boolean; guestStatus: GuestAgentStatus | null; guestStatusError: string; onNavigate: (view: View) => void }) {
  const [copyMessage, setCopyMessage] = useState("");
  const gatewayMode = running ? status.mode.includes("gateway") : settings.mode === "gateway";
  const runtimeName = gatewayMode ? "Mixed + 局域网网关" : "Mixed 代理";
  const gatewayIp = status.vmGatewayIp || settings.gatewayIp;
  const mixedListen = running ? status.listen : `${settings.listen}:${settings.port}`;
  const gatewayDnsIp = status.vmGatewayDnsIp || (settings.dnsMode === "fakeip" ? "198.18.0.2" : settings.gatewayDnsIp);
  const gatewayState = running
    ? (gatewayMode && !status.gatewayPacketPathReady ? "等待局域网验收" : "运行中")
    : status.state === "error" ? "暂不可用" : settingsDirty ? "待应用" : "未启动";
  const runtimePresentation = {
    stopped: { title: `${runtimeName}已停止`, tone: "stopped" },
    starting: { title: `正在启动${runtimeName}…`, tone: "starting" },
    running: { title: `${runtimeName}正在运行`, tone: "running" },
    stopping: { title: `正在停止${runtimeName}…`, tone: "starting" },
    error: { title: `${runtimeName}启动失败`, tone: "error" },
    exited: { title: `${runtimeName}已退出`, tone: "error" },
  }[status.state];

  async function copyProxyAddress() {
    try {
      await navigator.clipboard.writeText(status.listen);
      setCopyMessage("代理地址已复制");
    } catch {
      setCopyMessage("复制失败，请手动记录地址");
    }
    window.setTimeout(() => setCopyMessage(""), 2200);
  }

  return (
    <div className="page-content overview">
      <section className={`hero ${runtimePresentation.tone === "error" ? "has-error" : ""}`}>
        <div className="hero-main">
          <div className={`hero-dot ${runtimePresentation.tone}`} />
          <div className="hero-copy">
            <Text className="hero-title" weight="semibold">{runtimePresentation.title}</Text>
            <button className="hero-listen" onClick={() => void copyProxyAddress()} title="点击复制监听地址">
              {mixedListen}
              {copyMessage && <span className="hero-copied">{copyMessage}</span>}
            </button>
            <Text className="hero-message" size={200}>{running ? status.message : gatewayMode ? "vfkit 双 virtio-net、guest 网络和 guest-agent 已配置；实体 LAN 流量仍需现场验证。" : status.message}</Text>
          </div>
        </div>
        <div className="hero-actions">
          <Button appearance="secondary" onClick={() => onNavigate("settings")}>入口设置</Button>
        </div>
      </section>

      <section className="stats-grid">
        <StatCard label="当前连接" value={String(metrics.activeConnections)} />
        <StatCard label="下行" value={formatBytes(metrics.downloadTotal)} mono />
        <StatCard label="上行" value={formatBytes(metrics.uploadTotal)} mono />
        <StatCard label="内存" value={formatBytes(metrics.memory)} mono />
      </section>

      <Card className="panel gateway-overview-panel">
        <div className="gateway-overview-heading"><div><Text as="h2" size={400} weight="semibold">入口</Text><Text size={200}>本机 Mixed 代理始终可用；局域网网关通过 vfkit guest 接管实体 LAN 流量，二者可同时运行。</Text></div><Badge appearance="tint" color={running && (!gatewayMode || status.gatewayPacketPathReady) ? "success" : status.state === "error" ? "danger" : running ? "warning" : settingsDirty ? "warning" : "subtle"}>{gatewayState}</Badge></div>
        <div className="gateway-overview-grid">
          <DefinitionRow label="本机 Mixed" value={mixedListen} mono />
          <DefinitionRow label="DNS" value={status.dns || "系统 DNS"} />
          {gatewayMode && <DefinitionRow label="物理网卡" value={settings.gatewayLanInterface || "未填写"} mono />}
          {gatewayMode && <DefinitionRow label="网关 IP" value={gatewayIp || "未填写"} mono />}
          {gatewayMode && <DefinitionRow label="客户端 DNS" value={gatewayDnsIp || "未填写"} mono />}
        </div>
        {gatewayMode && <GatewayPacketPath guestStatus={guestStatus} error={guestStatusError} running={running} verified={status.gatewayPacketPathReady} />}
        {!running && <div className="gateway-overview-note"><Text size={200}>{settingsDirty ? "当前选择尚未保存；点击设置页的“应用更改”，或直接点击顶部“启动”自动保存。" : "Gateway 启动时会检查 vmnet、vfkit、guest-agent 和 sing-box readiness；客户端需手工配置网关和 DNS。"}</Text><Button appearance="subtle" onClick={() => onNavigate("settings")}>查看网关设置</Button></div>}
      </Card>

      <section className="overview-live-section">
        <SectionHeading title="实时连接" description="当前仍在传输的连接；已完成请求请前往活动查看。" action={<Badge appearance="outline" color={running ? "success" : "subtle"}>{metrics.activeConnections} 个</Badge>} />
        <Card className="panel overview-live-panel"><LiveConnections metrics={metrics} running={running} /></Card>
      </section>
    </div>
  );
}

function GatewayPacketPath({ guestStatus, error, running, verified }: { guestStatus: GuestAgentStatus | null; error: string; running: boolean; verified: boolean }) {
  const lan = guestStatus?.packetStats?.lan ?? null;
  const tun = guestStatus?.packetStats?.tun ?? null;
  const pathReady = Boolean(lan && tun && (lan.rxPackets > 0 || lan.txPackets > 0) && (tun.rxPackets > 0 || tun.txPackets > 0));
  const state = !running ? "未运行" : error ? "探测失败" : !guestStatus ? "探测中…" : !lan || !tun ? "接口不可见" : verified ? "已验收" : pathReady ? "观察到流量，确认中" : "等待流量";
  const badgeColor = state === "已验收" ? "success" : state === "探测失败" || state === "接口不可见" ? "danger" : state === "等待流量" || state === "观察到流量，确认中" ? "warning" : "subtle";

  return <div className="gateway-packet-path">
    <div className="gateway-packet-heading"><div><Text as="h3" size={300} weight="semibold">Guest packet path</Text><Text size={200}>LAN RX/TX 和 tun0 RX/TX 来自 guest 内核计数，不代表本机 Mixed 入口的请求记录。</Text></div><Badge appearance="tint" color={badgeColor as "success" | "danger" | "warning" | "subtle"}>{state}</Badge></div>
    <div className="gateway-packet-grid">
      <PacketStatsRow label="LAN" stats={lan} />
      <PacketStatsRow label="TUN" stats={tun} />
    </div>
    <Text className="gateway-packet-note" size={200}>{error || (running ? (verified ? "LAN 客户端流量已通过 guest LAN → tun0 数据面。" : "让客户端把网关设为上方 IP 后访问一次网络；启动后的 LAN 和 TUN 计数都增加后才会标记为已验收。") : "启动 Gateway 后，这里会显示 guest 内核接口计数。")}</Text>
  </div>;
}

function PacketStatsRow({ label, stats }: { label: string; stats: GuestInterfaceStats | null }) {
  return <div className="gateway-packet-row"><Text size={200} weight="semibold">{label} {stats ? <span className="mono-value">({stats.interface})</span> : <span className="gateway-packet-muted">(不可用)</span>}</Text><div className="gateway-packet-values"><span>RX <strong>{stats ? formatCount(stats.rxPackets) : "—"}</strong></span><span>TX <strong>{stats ? formatCount(stats.txPackets) : "—"}</strong></span><span>{stats ? `${formatBytes(stats.rxBytes)} / ${formatBytes(stats.txBytes)}` : "等待接口"}</span></div></div>;
}

function StatCard({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="stat-card"><Text className="stat-label" size={200}>{label}</Text><Text className={`stat-value ${mono ? "mono-value" : ""}`} weight="semibold">{value}</Text></div>;
}

function formatBytes(bytes: number | null | undefined): string {
  if (bytes === undefined || bytes === null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatCount(value: number): string {
  return value.toLocaleString("zh-CN");
}

function DefinitionRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="definition-row"><Text size={300}>{label}</Text><Text className={mono ? "mono-value" : ""} size={300} weight="semibold">{value}</Text></div>;
}

function ActivityRow({ log }: { log: RuntimeLog }) {
  return <div className="activity-row"><span className={`activity-level-dot log-${log.level}`} /><div className="activity-row-main"><Text className="activity-message" size={200}>{log.message}</Text></div><Text className="activity-time mono-value" size={200}>{formatPreciseTimestamp(log.timestamp, log.timestampUs)}</Text></div>;
}

function LogLevelBadge({ level }: { level: RuntimeLog["level"] }) {
  const labels: Record<RuntimeLog["level"], string> = { debug: "调试", info: "信息", warn: "警告", error: "错误" };
  return <span className={`log-level log-${level}`}><span className="log-level-dot" />{labels[level]}</span>;
}

function formatConnectionTime(value: string, explicitTimestampUs?: number): string {
  const timestampUs = explicitTimestampUs ?? timestampUsFromValue(value);
  const date = new Date(timestampUs === undefined ? value : Math.floor(timestampUs / 1_000));
  if (Number.isNaN(date.getTime())) return "—";
  const clock = date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  if (timestampUs === undefined) return clock;
  return `${clock}.${String(timestampUs % 1_000_000).padStart(6, "0")}`;
}

function formatConnectionDuration(connection: ConnectionInfo, nowUs: number): string {
  if (connection.status === "completed" && connection.durationMs === undefined) return "—";
  if (connection.status === "observed" && connection.durationMs === undefined) return "—";
  if (connection.durationMs !== undefined) {
    return formatElapsedMs(connection.durationMs);
  }
  const startedAtUs = connection.startUs ?? timestampUsFromValue(connection.start);
  if (startedAtUs === undefined) return "—";
  return formatElapsedMs(Math.max(0, (nowUs - startedAtUs) / 1_000));
}

function formatElapsedMs(value: number): string {
  const milliseconds = Math.max(0, value);
  if (milliseconds < 1) return `${Math.round(milliseconds * 1_000)} μs`;
  if (milliseconds < 1_000) return `${milliseconds.toFixed(3).replace(/\.?(0+)$/, "")} ms`;
  const seconds = milliseconds / 1_000;
  if (seconds < 60) return `${seconds.toFixed(3).replace(/\.?(0+)$/, "")} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} m ${(seconds % 60).toFixed(3).replace(/\.?(0+)$/, "")} s`;
}

function connectionStatusLabel(status: ConnectionInfo["status"]): string {
  return status === "active" ? "活跃" : status === "completed" ? "已完成" : "已记录";
}

function connectionStatusColor(status: ConnectionInfo["status"]): "warning" | "success" | "subtle" {
  return status === "active" ? "warning" : status === "completed" ? "success" : "subtle";
}

function connectionDisplayId(connection: ConnectionInfo): string {
  if (connection.logId) return connection.logId;
  if (connection.clashId) return connection.clashId.slice(0, 8);
  return connection.id;
}

function connectionDisplayAddress(connection: ConnectionInfo): string {
  const host = connection.host || parseConnectionEndpoint(connection.destination).host;
  const port = connectionPort(connection);
  return host ? `${host}${port ? `:${port}` : ""}` : connection.destination || "—";
}

function formatConnectionDateTime(value: string, explicitTimestampUs?: number): string {
  const timestampUs = explicitTimestampUs ?? timestampUsFromValue(value);
  const date = new Date(timestampUs === undefined ? value : Math.floor(timestampUs / 1_000));
  if (Number.isNaN(date.getTime())) return "—";
  const formatted = date.toLocaleString("zh-CN", { dateStyle: "medium", timeStyle: "medium" });
  return timestampUs === undefined
    ? formatted
    : `${formatted}.${String(timestampUs % 1_000_000).padStart(6, "0")}`;
}

function ConnectionStatus({ status }: { status: ConnectionInfo["status"] }) {
  return <Badge className="activity-status-badge" appearance={status === "active" ? "tint" : "outline"} color={connectionStatusColor(status)}><span className={`connection-status-dot ${status === "active" ? "is-active" : ""}`} />{connectionStatusLabel(status)}</Badge>;
}

function formatEventDelta(timestampUs: number | undefined, baseUs: number | undefined): string {
  if (timestampUs === undefined || baseUs === undefined) return "";
  const deltaMs = (timestampUs - baseUs) / 1_000;
  if (Math.abs(deltaMs) < 1) return `${deltaMs >= 0 ? "+" : ""}${(deltaMs * 1_000).toFixed(0)} μs`;
  return `${deltaMs >= 0 ? "+" : ""}${deltaMs.toFixed(3)} ms`;
}

function ConnectionEventRow({ event, baseUs }: { event: ConnectionEvent; baseUs?: number }) {
  return <div className={`connection-event-row event-${event.kind}`}>
    <span className="connection-event-marker" aria-hidden="true" />
    <div className="connection-event-main">
      <div className="connection-event-heading"><strong>{event.title}</strong>{event.inferred && <span className="connection-event-inferred">快照推断</span>}<span className={`connection-event-level log-${event.level}`}>{event.level}</span></div>
      <div className="connection-event-detail">{event.detail}</div>
    </div>
    <time className="connection-event-time mono-cell"><span>{formatPreciseTimestamp(event.timestamp, event.timestampUs)}</span>{formatEventDelta(event.timestampUs, baseUs) && <small>{formatEventDelta(event.timestampUs, baseUs)}</small>}</time>
  </div>;
}

function ConnectionDataPanel({ connection, direction }: { connection: ConnectionInfo; direction: "request" | "response" }) {
  const isRequest = direction === "request";
  const isSystem = connection.runtime === "system";
  const payloadLabel = isSystem ? (isRequest ? "发送数据" : "接收数据") : (isRequest ? "HTTP 请求体" : "HTTP 响应体");
  const protocol = connection.network ? connection.network.toUpperCase() : "—";
  return <div className="connection-data-panel">
    <div className="connection-data-status"><span className="connection-data-icon">{isRequest ? "↑" : "↓"}</span><div><strong>{isRequest ? "请求数据" : "响应数据"}</strong><span>{payloadLabel}</span></div><Badge appearance="outline" color="subtle">未捕获</Badge></div>
    <dl className="connection-data-grid">
      <div><dt>端点</dt><dd className="mono-cell">{isRequest ? connection.source || "—" : connectionDisplayAddress(connection)}</dd></div>
      <div><dt>协议</dt><dd>{protocol}</dd></div>
      <div><dt>字节数</dt><dd className="mono-cell">{formatBytes(isRequest ? connection.upload : connection.download)}</dd></div>
      <div><dt>采集状态</dt><dd>当前只记录连接元数据</dd></div>
    </dl>
    <Text className="connection-data-note" size={200}>{connection.runtime === "guest" ? "Guest 当前通过 Clash API 提供连接快照，未暴露 HTTP body。" : connection.runtime === "system" ? "系统网络记录只包含进程和连接元数据；不会读取或解密数据包内容。" : "启用并命中模块 MITM 后，才可以进一步采集 HTTP 头和正文；普通 TLS 连接不会解密展示。"}</Text>
  </div>;
}

function ConnectionDetails({ connection, events }: { connection: ConnectionInfo; events: ConnectionEvent[] }) {
  const [detailTab, setDetailTab] = useState("events");
  const timeline = connectionEventsFor(connection, events).slice().sort((left, right) => (left.timestampUs ?? Date.parse(left.timestamp) * 1_000) - (right.timestampUs ?? Date.parse(right.timestamp) * 1_000));
  const ingressEvent = timeline.find(isIngressConnectionEvent);
  const timelineBaseUs = ingressEvent?.timestampUs ?? connection.startUs ?? timeline[0]?.timestampUs;
  const elapsedEndUs = connection.status === "active"
    ? Date.now() * 1_000
    : connection.lastSeenUs;
  const elapsedFromIngress = timelineBaseUs === undefined || elapsedEndUs === undefined
    ? "—"
    : formatElapsedMs(Math.max(0, (elapsedEndUs - timelineBaseUs) / 1_000));
  const isSystem = connection.runtime === "system";
  const timeLabel = isSystem ? "首次观测" : "入口时间";
  const elapsedLabel = isSystem ? "观测时长" : "入口起算耗时";
  const protocol = connection.network ? connection.network.toUpperCase() : "—";
  return <div className="connection-detail-shell">
    <div className="connection-detail-header"><div><Text className="connection-detail-title" weight="semibold">{connection.host || connectionDisplayAddress(connection)}</Text><Text className="connection-detail-subtitle" size={200}>{connectionRuntimeLabel(connection.runtime)}{connection.process ? ` · ${connection.process}${connection.pid ? ` (${connection.pid})` : ""}` : ""} · {connection.source || "未知客户端"} → {connectionDisplayAddress(connection)}</Text></div><ConnectionStatus status={connection.status} /></div>
    <dl className="activity-connection-details">
      <div><dt>运行位置</dt><dd>{connectionRuntimeLabel(connection.runtime)}</dd></div>
      <div><dt>显示 ID</dt><dd className="mono-cell">{connectionDisplayId(connection)}</dd></div>
      <div><dt>日志 ID</dt><dd className={connection.logId ? "mono-cell" : "activity-muted"}>{connection.logId || "—"}</dd></div>
      <div><dt>Clash ID</dt><dd className={connection.clashId ? "mono-cell" : "activity-muted"}>{connection.clashId || "—"}</dd></div>
      <div><dt>客户端端点</dt><dd className={connection.source ? "mono-cell" : "activity-muted"}>{connection.source || "—"}</dd></div>
      <div><dt>目标端点</dt><dd className={connection.destination ? "mono-cell" : "activity-muted"}>{connection.destination || "—"}</dd></div>
      <div><dt>主机</dt><dd className={connection.host ? "mono-cell" : "activity-muted"}>{connection.host || "—"}</dd></div>
      <div><dt>进程 / PID</dt><dd className={connection.process ? "mono-cell" : "activity-muted"}>{connection.process ? `${connection.process}${connection.pid ? ` / ${connection.pid}` : ""}` : "—"}</dd></div>
      <div><dt>系统状态</dt><dd>{connection.state || "—"}</dd></div>
      <div><dt>{timeLabel}</dt><dd className={connection.start ? "mono-cell" : "activity-muted"}>{formatConnectionDateTime(connection.start, timelineBaseUs ?? connection.startUs)}</dd></div>
      <div><dt>{elapsedLabel}</dt><dd className="mono-cell">{elapsedFromIngress}</dd></div>
      <div><dt>策略 / 协议</dt><dd>{connectionOutboundLabel(connection.outbound)} · {protocol}</dd></div>
    </dl>
    <TabList className="connection-detail-tabs" selectedValue={detailTab} onTabSelect={(_, data) => setDetailTab(String(data.value))} aria-label="连接详情">
      <Tab value="events">事件 <span className="connection-tab-count">{timeline.length}</span></Tab>
      <Tab value="request">请求数据</Tab>
      <Tab value="response">响应数据</Tab>
    </TabList>
    {detailTab === "events" && <div className="connection-event-list" aria-label="连接事件时间线">{timeline.map((event) => <ConnectionEventRow key={event.id} event={event} baseUs={timelineBaseUs} />)}</div>}
    {detailTab === "request" && <ConnectionDataPanel connection={connection} direction="request" />}
    {detailTab === "response" && <ConnectionDataPanel connection={connection} direction="response" />}
  </div>;
}

function ConnectionTraffic({ connection }: { connection: ConnectionInfo }) {
  return <div className="activity-traffic"><span className={connection.upload == null ? "activity-muted" : undefined}>↑ {formatBytes(connection.upload)}</span><span className={connection.download == null ? "activity-muted" : undefined}>↓ {formatBytes(connection.download)}</span></div>;
}

function ActivityPage({ connections, connectionEvents, running, logs, hostSnapshotValid, hostSnapshotError, guestSnapshotValid, guestSnapshotError, systemSnapshotValid, systemSnapshotError, onClear }: { connections: ConnectionInfo[]; connectionEvents: ConnectionEvent[]; running: boolean; logs: RuntimeLog[]; hostSnapshotValid: boolean; hostSnapshotError?: string | null; guestSnapshotValid: boolean; guestSnapshotError?: string | null; systemSnapshotValid: boolean; systemSnapshotError?: string | null; onClear: () => void }) {
  const [connectionQuery, setConnectionQuery] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activityTab, setActivityTab] = useState("requests");
  const [eventQuery, setEventQuery] = useState("");
  const [eventLevel, setEventLevel] = useState("all");
  const nowUs = Date.now() * 1_000;
  const toggleConnection = (id: string) => setExpandedId((current) => current === id ? null : id);
  const filteredConnections = connections
    .slice()
    .sort((left, right) => Date.parse(right.start) - Date.parse(left.start))
    .filter((connection) => `${connection.id} ${connection.runtime} ${connection.logId ?? ""} ${connection.clashId ?? ""} ${connection.source} ${connection.destination} ${connection.host} ${connection.outbound} ${connection.network} ${connection.process ?? ""} ${connection.pid ?? ""} ${connection.state ?? ""}`.toLowerCase().includes(connectionQuery.toLowerCase()));
  const filteredLogs = logs
    .slice()
    .reverse()
    .filter((log) => eventLevel === "all" || log.level === eventLevel)
    .filter((log) => `${log.timestamp} ${log.level} ${log.message}`.toLowerCase().includes(eventQuery.toLowerCase()));

  return <div className="page-content page-stack">
    <TabList className="activity-mode-tabs" selectedValue={activityTab} onTabSelect={(_, data) => setActivityTab(String(data.value))} aria-label="活动类型">
      <Tab value="requests">请求记录</Tab>
      <Tab value="logs">运行日志</Tab>
    </TabList>
    {activityTab === "requests" && <Card className="panel activity-connections-panel">
      <div className="activity-panel-heading"><div><Text as="h2" size={400} weight="semibold">请求记录</Text><Text size={200}>何时 → 去哪里 → 当前状态 → 使用策略 → 流量和时长。</Text>{running && !hostSnapshotValid && <Text className="activity-warning-note" size={200}>Host 连接观察暂时不可用，已保留上一批记录{hostSnapshotError ? `：${hostSnapshotError}` : ""}。</Text>}{running && !guestSnapshotValid && <Text className="activity-warning-note" size={200}>Gateway guest 连接观察暂时不可用，已保留上一批记录{guestSnapshotError ? `：${guestSnapshotError}` : ""}。</Text>}{running && !systemSnapshotValid && <Text className="activity-warning-note" size={200}>系统连接观察暂时不可用，已保留上一批记录{systemSnapshotError ? `：${systemSnapshotError}` : ""}。</Text>}</div><Badge appearance="outline" color={running && (!hostSnapshotValid || !guestSnapshotValid || !systemSnapshotValid) ? "warning" : running ? "warning" : "subtle"}>{running && !hostSnapshotValid ? "Host 观察不可用" : running && !guestSnapshotValid ? "Guest 观察不可用" : running && !systemSnapshotValid ? "系统观察不可用" : `${connections.length} 条记录`}</Badge></div>
      <div className="activity-toolbar"><Input contentBefore={<SearchRegular />} value={connectionQuery} onChange={(event) => setConnectionQuery(event.target.value)} placeholder="搜索地址、客户端、策略或 ID" /></div>
      {filteredConnections.length === 0 ? <EmptyState title={running ? "暂无请求记录" : "暂无请求历史"} description={running ? "让应用通过 Mixed 代理访问网络后，请求会显示在这里。" : "启动代理接入后，请求记录会显示在这里。"} /> : <>
        <div className="activity-table-scroll" tabIndex={0} aria-label="代理请求记录">
          <Table size="small" className="data-table activity-connection-table">
            <TableHeader><TableRow><TableHeaderCell>时间</TableHeaderCell><TableHeaderCell>请求</TableHeaderCell><TableHeaderCell>来源</TableHeaderCell><TableHeaderCell>状态</TableHeaderCell><TableHeaderCell>策略</TableHeaderCell><TableHeaderCell>流量</TableHeaderCell><TableHeaderCell>时长</TableHeaderCell><TableHeaderCell>协议</TableHeaderCell></TableRow></TableHeader>
            <TableBody>{filteredConnections.map((connection) => <Fragment key={connection.id}>
              <TableRow className="activity-request-row" tabIndex={0} aria-expanded={expandedId === connection.id} onClick={() => toggleConnection(connection.id)} onKeyDown={(event) => { if (event.key === "Escape" && expandedId === connection.id) { event.preventDefault(); setExpandedId(null); } else if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggleConnection(connection.id); } }}>
                <TableCell className="activity-time-cell mono-cell">{formatConnectionTime(connection.start, connection.startUs)}</TableCell>
                <TableCell className="activity-request-cell"><div className="activity-request-address" title={connectionDisplayAddress(connection)}>{connectionDisplayAddress(connection)}</div><div className="activity-request-meta"><span className="activity-request-client" title={connection.process || connection.source || undefined}>{connection.process ? `${connection.process}${connection.pid ? ` (${connection.pid})` : ""}` : connection.source || "未知客户端"}</span><span aria-hidden="true"> · </span><span>#{connectionDisplayId(connection)}</span></div></TableCell>
                <TableCell>{connectionRuntimeLabel(connection.runtime)}</TableCell>
                <TableCell><ConnectionStatus status={connection.status} /></TableCell>
                <TableCell><span className={connection.outbound ? "activity-policy" : "activity-muted"}>{connectionOutboundLabel(connection.outbound)}</span></TableCell>
                <TableCell><ConnectionTraffic connection={connection} /></TableCell>
                <TableCell className="mono-cell">{formatConnectionDuration(connection, nowUs)}</TableCell>
                <TableCell>{connection.network ? connection.network.toUpperCase() : <span className="activity-muted">—</span>}</TableCell>
              </TableRow>
              {expandedId === connection.id && <TableRow className="activity-detail-row"><TableCell colSpan={8}><ConnectionDetails connection={connection} events={connectionEvents} /></TableCell></TableRow>}
            </Fragment>)}</TableBody>
          </Table>
        </div>
        <div className="activity-request-mobile-list" aria-label="代理请求记录列表">{filteredConnections.map((connection) => <Fragment key={connection.id}>
          <button type="button" className="activity-request-mobile" onClick={() => toggleConnection(connection.id)} onKeyDown={(event) => { if (event.key === "Escape" && expandedId === connection.id) { event.preventDefault(); setExpandedId(null); } }} aria-expanded={expandedId === connection.id}>
            <div className="activity-mobile-primary"><ConnectionStatus status={connection.status} /><strong title={connectionDisplayAddress(connection)}>{connectionDisplayAddress(connection)}</strong></div>
            <div className="activity-mobile-secondary"><span>{connectionRuntimeLabel(connection.runtime)}</span><span className={connection.outbound ? "activity-policy" : "activity-muted"}>{connectionOutboundLabel(connection.outbound)}</span><span>{connection.network ? connection.network.toUpperCase() : "—"}</span><span>{formatConnectionDuration(connection, nowUs)}</span></div>
            <div className="activity-mobile-secondary"><span>{formatConnectionTime(connection.start, connection.startUs)}</span><ConnectionTraffic connection={connection} /></div>
          </button>
          {expandedId === connection.id && <div className="activity-mobile-detail"><ConnectionDetails connection={connection} events={connectionEvents} /></div>}
        </Fragment>)}</div>
      </>}
    </Card>}
    {activityTab === "logs" && <Card className="panel activity-events-panel">
      <div className="activity-panel-heading"><div><Text as="h2" size={400} weight="semibold">运行日志</Text><Text size={200}>sing-box 与 SongsterX 的启动、停止、配置变更和错误。</Text></div><div className="activity-panel-heading-actions"><Badge appearance="outline" color="subtle">{logs.length} 条</Badge><Button appearance="subtle" onClick={onClear} disabled={logs.length === 0}>清空日志</Button></div></div>
      <div className="activity-toolbar"><Input contentBefore={<SearchRegular />} value={eventQuery} onChange={(event) => setEventQuery(event.target.value)} placeholder="搜索运行日志" /><Select value={eventLevel} onChange={(event) => setEventLevel(event.target.value)} aria-label="日志等级"><option value="all">全部等级</option><option value="info">信息</option><option value="warn">警告</option><option value="error">错误</option><option value="debug">调试</option></Select></div>
      {filteredLogs.length === 0 ? <EmptyState title={logs.length === 0 ? "暂无运行日志" : "没有匹配的日志"} description={logs.length === 0 ? "启动服务后，运行事件会显示在这里。" : "调整搜索词或日志等级后重试。"} /> : <div className="activity-event-list">{filteredLogs.map((log, index) => <ActivityRow key={`${log.timestamp}-${index}`} log={log} />)}</div>}
    </Card>}
  </div>;
}

const outboundProtocolOptions = [
  ["trojan", "Trojan"],
  ["vmess", "VMess"],
  ["vless", "VLESS"],
  ["shadowsocks", "Shadowsocks"],
  ["socks", "SOCKS"],
  ["http", "HTTP CONNECT"],
  ["wireguard", "WireGuard"],
  ["hysteria", "Hysteria"],
  ["hysteria2", "Hysteria 2"],
  ["shadowtls", "ShadowTLS"],
  ["tuic", "TUIC"],
  ["anytls", "AnyTLS"],
  ["snell", "Snell"],
  ["naive", "NaiveProxy"],
  ["ssh", "SSH"],
  ["tor", "Tor"],
] as const;

function createDefaultProxyNode(index: number): ProxyNode {
  return {
    tag: `node-${index}`,
    type: "trojan",
    server: "",
    serverPort: 443,
    serverPorts: "",
    hopInterval: "",
    hopIntervalMax: "",
    password: "",
    username: "",
    sni: "",
    network: "",
    wsPath: "",
    wsHost: "",
    transportMethod: "",
    transportServiceName: "",
    transportHeaders: "",
    transportIdleTimeout: "",
    transportPingTimeout: "",
    transportPermitWithoutStream: false,
    transportMaxEarlyData: 0,
    transportEarlyDataHeaderName: "",
    transportQuicSecurity: "none",
    transportQuicKey: "",
    insecure: false,
    tlsEnabled: true,
    tlsEngine: "",
    tlsDisableSni: false,
    tlsAlpn: "",
    tlsMinVersion: "",
    tlsMaxVersion: "",
    tlsCertificatePath: "",
    tlsCertificatePublicKeySha256: "",
    tlsHandshakeTimeout: "",
    tlsUtlFingerprint: "",
    tlsRealityPublicKey: "",
    tlsRealityShortId: "",
    uuid: "",
    method: "",
    plugin: "",
    pluginOptions: "",
    flow: "",
    packetEncoding: "",
    security: "auto",
    alterId: 0,
    // 由后端按协议填充默认版本：SOCKS=5、ShadowTLS=3、Snell=4。
    // 这样同一个节点草稿切换协议时不会把 SOCKS 的版本误带到其他协议。
    version: 0,
    privateKey: "",
    privateKeyPath: "",
    peerPublicKey: "",
    preSharedKey: "",
    localAddress: "",
    wireguardSystemInterface: false,
    wireguardInterfaceName: "",
    wireguardMtu: 0,
    wireguardWorkers: 0,
    wireguardNetwork: "",
    wireguardReserved: "",
    upMbps: 0,
    downMbps: 0,
    upBandwidth: "",
    downBandwidth: "",
    authBase64: "",
    obfs: "",
    obfsPassword: "",
    congestionControl: "cubic",
    udpRelayMode: "native",
    zeroRttHandshake: false,
    heartbeat: "",
    tuicUdpOverStream: false,
    idleSessionCheckInterval: "",
    idleSessionExpiration: "",
    minIdleSession: 0,
    psk: "",
    snellUserkey: "",
    snellReuse: false,
    snellObfsMode: "",
    snellObfsHost: "",
    snellMode: "",
    sshPrivateKey: "",
    sshPrivateKeyPassphrase: "",
    sshHostKey: "",
    sshHostKeyAlgorithms: "",
    sshClientVersion: "",
    sshCipher: "",
    sshMac: "",
    sshKexAlgorithm: "",
    executablePath: "",
    dataDirectory: "",
    torArgs: "",
    anytlsClientMetadata: "",
    detour: "",
    bindInterface: "",
    inet4BindAddress: "",
    inet6BindAddress: "",
    bindAddressNoPort: false,
    routingMark: 0,
    reuseAddr: false,
    connectTimeout: "",
    tcpFastOpen: false,
    tcpMultiPath: false,
    disableTcpKeepAlive: false,
    tcpKeepAlive: "",
    tcpKeepAliveInterval: "",
    udpFragment: false,
    domainResolver: "",
    networkStrategy: "",
    networkType: "",
    fallbackNetworkType: "",
    fallbackDelay: "",
    domainStrategy: "",
    multiplexEnabled: false,
    multiplexProtocol: "",
    multiplexMaxConnections: 0,
    multiplexMinStreams: 0,
    multiplexMaxStreams: 0,
    multiplexPadding: false,
    multiplexBrutal: "",
    extraJson: "",
  };
}

function ProxyPolicyTargetBar({ mode, target, onChange }: { mode: RuntimeSettings["gatewayPolicyMode"]; target: ProxyConfigTarget; onChange: (target: ProxyConfigTarget) => void }) {
  if (mode !== "separate") return null;
  return <section className="proxy-policy-target" aria-label="策略配置目标">
    <div className="proxy-policy-target-copy"><Text weight="semibold">策略配置目标</Text><Text size={200}>Host 与 Gateway guest 使用独立的节点、策略组、规则和规则集，请分别编辑。</Text></div>
    <TabList className="proxy-policy-target-tabs" selectedValue={target} onTabSelect={(_, data) => onChange(String(data.value) as ProxyConfigTarget)} aria-label="策略配置目标">
      <Tab value="host">Host · macOS</Tab>
      <Tab value="guest">Guest · Linux VM</Tab>
    </TabList>
  </section>;
}

function StrategyPage({ config, proxies, running, policyMode, target, onTargetChange, onSelect, onTestDelay, onTestingChange, onSave }: {
  config: ProxyConfig;
  proxies: ProxyInfo[];
  running: boolean;
  policyMode: RuntimeSettings["gatewayPolicyMode"];
  target: ProxyConfigTarget;
  onTargetChange: (target: ProxyConfigTarget) => void;
  onSelect: (group: string, name: string) => void;
  onTestDelay: (name: string) => Promise<number>;
  onTestingChange: (testing: boolean) => void;
  onSave: (config: ProxyConfig, target: ProxyConfigTarget) => Promise<void>;
}) {
  const [draft, setDraft] = useState<ProxyConfig>(config);
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const [testingNode, setTestingNode] = useState<string | null>(null);
  const [delays, setDelays] = useState<Record<string, number | null>>({});
  const [editingNode, setEditingNode] = useState<{ index: number | null; node: ProxyNode } | null>(null);
  const [editingGroup, setEditingGroup] = useState<{ index: number | null; group: PolicyGroup } | null>(null);
  useEffect(() => setDraft(config), [config]);

  const selectors = proxies.filter((p) => p.kind === "Selector" || p.kind === "Fallback" || p.kind === "URLTest");

  function openNewNode() {
    setEditingNode({ index: null, node: createDefaultProxyNode(draft.nodes.length + 1) });
  }
  function openEditNode(index: number) {
    setEditingNode({ index, node: { ...createDefaultProxyNode(index + 1), ...draft.nodes[index] } });
  }
  async function applyConfig(next: ProxyConfig): Promise<boolean> {
    setDraft(next);
    setMessage("");
    setSaving(true);
    try {
      await onSave(next, target);
      setMessage(running ? "已立即应用。" : "已保存，下次启动时生效。");
      return true;
    } catch (error) {
      setMessage(`应用失败：${String(error)}`);
      return false;
    } finally {
      setSaving(false);
    }
  }

  async function commitNode() {
    if (!editingNode) return;
    const next = editingNode.index === null
      ? { ...draft, nodes: [...draft.nodes, editingNode.node] }
      : { ...draft, nodes: draft.nodes.map((node, index) => index === editingNode.index ? editingNode.node : node) };
    if (await applyConfig(next)) setEditingNode(null);
  }
  async function removeNode(index: number) {
    await applyConfig({ ...draft, nodes: draft.nodes.filter((_, nodeIndex) => nodeIndex !== index) });
  }
  function openNewGroup() {
    setEditingGroup({ index: null, group: { name: `group-${draft.groups.length + 1}`, type: "selector", members: ["direct"], default: "direct", url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: 50, idleTimeout: "30m", interruptExistConnections: false } });
  }
  function openEditGroup(index: number) {
    const current = draft.groups[index];
    setEditingGroup({ index, group: { ...current, url: current.url || "https://www.gstatic.com/generate_204", interval: current.interval || "3m", tolerance: current.tolerance || 50, idleTimeout: current.idleTimeout || "30m", interruptExistConnections: current.interruptExistConnections ?? false } });
  }
  async function commitGroup() {
    if (!editingGroup) return;
    const next = editingGroup.index === null
      ? { ...draft, groups: [...draft.groups, editingGroup.group] }
      : { ...draft, groups: draft.groups.map((group, index) => index === editingGroup.index ? editingGroup.group : group) };
    if (await applyConfig(next)) setEditingGroup(null);
  }
  async function removeGroup(index: number) {
    await applyConfig({ ...draft, groups: draft.groups.filter((_, groupIndex) => groupIndex !== index) });
  }
  async function testNodeDelay(tag: string) {
    if (!running) {
      setMessage("请先启动服务，再测试节点延迟。");
      return;
    }
    setTestingNode(tag);
    onTestingChange(true);
    setMessage("");
    try {
      const delay = await onTestDelay(tag);
      setDelays((current) => ({ ...current, [tag]: delay }));
      setMessage(`${tag} 延迟 ${delay} ms。`);
    } catch (error) {
      setDelays((current) => ({ ...current, [tag]: null }));
      setMessage(`延迟测试失败：${String(error)}`);
    } finally {
      setTestingNode(null);
      onTestingChange(false);
    }
  }

  const allOutbounds = ["direct", ...draft.nodes.map((n) => n.tag), ...draft.groups.map((g) => g.name)];

  return (
    <div className="page-content page-stack">
      <div className="page-actions"><Text className={`save-message ${message.includes("失败") ? "error" : ""}`} size={200}>{message}</Text></div>
      <ProxyPolicyTargetBar mode={policyMode} target={target} onChange={onTargetChange} />

      {selectors.length > 0 && (
        <section className="page-section">
          <SectionHeading title="实时策略组" description="运行中的策略组，点击可立即切换出站。" />
          <div className="selector-grid">
            {selectors.map((sel) => (
              <Card key={sel.name} className="panel selector-card">
                <div className="selector-head">
                  <Text weight="semibold">{sel.name}</Text>
                  <Badge appearance="outline" color="subtle" size="small">{sel.kind}</Badge>
                </div>
                <div className="selector-now">当前：<strong>{sel.now || "—"}</strong></div>
                <div className="selector-options">
                  {sel.all.map((opt) => (
                    <button key={opt} className={`selector-option ${opt === sel.now ? "active" : ""}`} disabled={!running} onClick={() => onSelect(sel.name, opt)}>{opt}</button>
                  ))}
                </div>
              </Card>
            ))}
          </div>
        </section>
      )}

      <section className="page-section">
        <SectionHeading title="代理节点" description="配置出站节点，修改后立即应用；服务运行时可测试延迟。" action={<Button appearance="primary" onClick={openNewNode} disabled={saving}>添加节点</Button>} />
        {draft.nodes.length === 0 ? <Card className="panel"><EmptyState title="暂无节点" description="添加一个代理节点，或直接使用 DIRECT 出站。" /></Card> : <Card className="panel rule-list">{draft.nodes.map((node, index) => (
          <div key={index} className="rule-list-row">
            <span className="rule-index">{index + 1}</span>
            <div className="rule-list-main">
              <div className="rule-list-title"><Text weight="semibold">{node.tag}</Text><Badge appearance="outline" color="subtle">{node.type}</Badge></div>
              <Text className="rule-summary" size={200}>{node.server ? `${node.server}:${node.serverPort}` : "未配置服务器"}{node.sni ? ` · SNI ${node.sni}` : ""}{delays[node.tag] === undefined ? " · 未测试" : delays[node.tag] === null ? " · 测试失败" : ` · ${delays[node.tag]} ms`}</Text>
            </div>
            <div className="rule-list-actions">
              <Button appearance="subtle" onClick={() => void testNodeDelay(node.tag)} disabled={!running || saving || testingNode !== null}>{testingNode === node.tag ? "测试中…" : "测延迟"}</Button>
              <Button appearance="secondary" onClick={() => openEditNode(index)} disabled={saving}>编辑</Button>
              <Button appearance="subtle" onClick={() => void removeNode(index)} disabled={saving}>删除</Button>
            </div>
          </div>
        ))}</Card>}
      </section>

      <section className="page-section">
        <SectionHeading title="策略组" description="Selector 组可在多个出站间手动切换，修改后立即应用。" action={<Button appearance="primary" onClick={openNewGroup} disabled={saving}>添加策略组</Button>} />
        {draft.groups.length === 0 ? <Card className="panel"><EmptyState title="暂无策略组" description="添加一个策略组作为最终出站。" /></Card> : <Card className="panel rule-list">{draft.groups.map((group, index) => (
          <div key={index} className="rule-list-row">
            <span className="rule-index">{index + 1}</span>
            <div className="rule-list-main">
              <div className="rule-list-title"><Text weight="semibold">{group.name}</Text><Badge appearance="outline" color="subtle">{group.type}</Badge></div>
              <Text className="rule-summary" size={200}>{group.members.join(", ") || "无成员"} · 默认 {group.default}</Text>
            </div>
            <div className="rule-list-actions">
              <Button appearance="secondary" onClick={() => openEditGroup(index)} disabled={saving}>编辑</Button>
              <Button appearance="subtle" onClick={() => void removeGroup(index)} disabled={saving}>删除</Button>
            </div>
          </div>
        ))}</Card>}
      </section>

      {editingNode && <NodeEditorDialog node={editingNode.node} onChange={(node) => setEditingNode({ ...editingNode, node })} onCancel={() => setEditingNode(null)} onConfirm={commitNode} />}
      {editingGroup && <GroupEditorDialog group={editingGroup.group} allOutbounds={allOutbounds} onChange={(group) => setEditingGroup({ ...editingGroup, group })} onCancel={() => setEditingGroup(null)} onConfirm={commitGroup} />}
    </div>
  );
}

const tlsCapableProtocols = new Set(["trojan", "vmess", "vless", "http", "hysteria", "hysteria2", "shadowtls", "tuic", "anytls", "naive"]);
const transportProtocols = new Set(["trojan", "vmess", "vless"]);

function normalizeNodeForType(node: ProxyNode, type: string): ProxyNode {
  const defaults = createDefaultProxyNode(0);
  const next: ProxyNode = {
    ...defaults,
    tag: node.tag,
    type,
    server: node.server,
    serverPort: node.serverPort,
    tlsEnabled: tlsCapableProtocols.has(type),
  };

  // A protocol switch is a new protocol draft. Keep only connection identity;
  // credentials, transport, TLS and protocol-specific fields must not leak.
  if (transportProtocols.has(type)) {
    next.network = "";
  } else if (["hysteria", "hysteria2", "tuic", "snell"].includes(type)) {
    next.network = "";
  }
  return next;
}

function ModalFrame({ children, className = "", labelledBy, onCancel }: { children: ReactNode; className?: string; labelledBy: string; onCancel: () => void }) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const onCancelRef = useRef(onCancel);
  onCancelRef.current = onCancel;
  const titleId = useId();

  useEffect(() => {
    const previousActive = document.activeElement as HTMLElement | null;
    const surface = surfaceRef.current;
    if (!surface) return;
    const selector = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])';
    const focusables = () => Array.from(surface.querySelectorAll<HTMLElement>(selector)).filter((element) => element.offsetParent !== null);
    const initial = surface.querySelector<HTMLElement>("[data-modal-initial-focus]") ?? focusables()[0];
    initial?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancelRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const elements = focusables();
      if (elements.length === 0) return;
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (event.shiftKey && (document.activeElement === first || !surface.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !surface.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousActive?.focus?.();
    };
  }, []);

  return <div className="modal-backdrop"><div ref={surfaceRef} className={`modal-surface ${className}`.trim()} role="dialog" aria-modal="true" aria-labelledby={labelledBy} data-modal-title-id={titleId}>{children}</div></div>;
}

function NodeTlsFields({ node, onChange }: { node: ProxyNode; onChange: (node: ProxyNode) => void }) {
  return <>
    <div className="switch-field"><Switch checked={node.tlsEnabled} onChange={(e) => onChange({ ...node, tlsEnabled: e.target.checked })} label="启用 TLS" /></div>
    <Field label="TLS 引擎"><Select value={node.tlsEngine} onChange={(e) => onChange({ ...node, tlsEngine: e.target.value })}><option value="">默认</option><option value="go">Go</option><option value="apple">Apple</option><option value="windows">Windows</option></Select></Field>
    <Field label="SNI"><Input value={node.sni} onChange={(e) => onChange({ ...node, sni: e.target.value })} /></Field>
    <Field label="ALPN" hint="多个值用逗号分隔"><Input value={node.tlsAlpn} placeholder="例如 h2, http/1.1" onChange={(e) => onChange({ ...node, tlsAlpn: e.target.value })} /></Field>
    <details className="node-advanced-section node-advanced-section-inline">
      <summary>更多 TLS 设置</summary>
      <div className="node-fields node-fields-inset">
        <div className="switch-field"><Switch checked={node.insecure} onChange={(e) => onChange({ ...node, insecure: e.target.checked })} label="跳过证书验证" /></div>
        <div className="switch-field"><Switch checked={node.tlsDisableSni} onChange={(e) => onChange({ ...node, tlsDisableSni: e.target.checked })} label="禁用 SNI" /></div>
        <Field label="最低 TLS 版本"><Select value={node.tlsMinVersion} onChange={(e) => onChange({ ...node, tlsMinVersion: e.target.value })}><option value="">默认</option><option value="1.0">1.0</option><option value="1.1">1.1</option><option value="1.2">1.2</option><option value="1.3">1.3</option></Select></Field>
        <Field label="最高 TLS 版本"><Select value={node.tlsMaxVersion} onChange={(e) => onChange({ ...node, tlsMaxVersion: e.target.value })}><option value="">默认</option><option value="1.2">1.2</option><option value="1.3">1.3</option></Select></Field>
        <Field label="证书路径"><Input value={node.tlsCertificatePath} onChange={(e) => onChange({ ...node, tlsCertificatePath: e.target.value })} /></Field>
        <Field label="证书公钥 SHA256"><Input value={node.tlsCertificatePublicKeySha256} placeholder="逗号分隔" onChange={(e) => onChange({ ...node, tlsCertificatePublicKeySha256: e.target.value })} /></Field>
        <Field label="握手超时"><Input value={node.tlsHandshakeTimeout} placeholder="例如 10s" onChange={(e) => onChange({ ...node, tlsHandshakeTimeout: e.target.value })} /></Field>
        <Field label="uTLS 指纹"><Input value={node.tlsUtlFingerprint} placeholder="可选，例如 chrome" onChange={(e) => onChange({ ...node, tlsUtlFingerprint: e.target.value })} /></Field>
        <Field label="Reality 公钥"><Input value={node.tlsRealityPublicKey} onChange={(e) => onChange({ ...node, tlsRealityPublicKey: e.target.value })} /></Field>
        <Field label="Reality Short ID"><Input value={node.tlsRealityShortId} onChange={(e) => onChange({ ...node, tlsRealityShortId: e.target.value })} /></Field>
      </div>
    </details>
  </>;
}

function NodeEditorDialog({ node, onChange, onCancel, onConfirm }: { node: ProxyNode; onChange: (node: ProxyNode) => void; onCancel: () => void; onConfirm: () => void }) {
  const serverTypes = node.type !== "tor";
  const tlsCapable = tlsCapableProtocols.has(node.type);
  const transportCapable = transportProtocols.has(node.type);
  const changeType = (type: string) => {
    if (type !== node.type) onChange(normalizeNodeForType(node, type));
  };
  const commonFields = (
    <details className="node-advanced-section">
      <summary>通用 Dial 与 Multiplex 字段</summary>
      <div className="node-fields node-fields-inset">
        <Field label="Detour"><Input value={node.detour} onChange={(e) => onChange({ ...node, detour: e.target.value })} /></Field><Field label="绑定网卡"><Input value={node.bindInterface} placeholder="例如 en0" onChange={(e) => onChange({ ...node, bindInterface: e.target.value })} /></Field><Field label="IPv4 绑定地址"><Input value={node.inet4BindAddress} onChange={(e) => onChange({ ...node, inet4BindAddress: e.target.value })} /></Field><Field label="IPv6 绑定地址"><Input value={node.inet6BindAddress} onChange={(e) => onChange({ ...node, inet6BindAddress: e.target.value })} /></Field><div className="switch-field"><Switch checked={node.bindAddressNoPort} onChange={(e) => onChange({ ...node, bindAddressNoPort: e.target.checked })} label="绑定地址不占端口" /></div><Field label="Routing Mark"><Input type="number" min={0} value={String(node.routingMark)} onChange={(e) => onChange({ ...node, routingMark: Number(e.target.value) })} /></Field><div className="switch-field"><Switch checked={node.reuseAddr} onChange={(e) => onChange({ ...node, reuseAddr: e.target.checked })} label="Reuse Address" /></div><Field label="连接超时"><Input value={node.connectTimeout} placeholder="例如 10s" onChange={(e) => onChange({ ...node, connectTimeout: e.target.value })} /></Field><div className="switch-field"><Switch checked={node.tcpFastOpen} onChange={(e) => onChange({ ...node, tcpFastOpen: e.target.checked })} label="TCP Fast Open" /></div><div className="switch-field"><Switch checked={node.tcpMultiPath} onChange={(e) => onChange({ ...node, tcpMultiPath: e.target.checked })} label="TCP Multipath" /></div><div className="switch-field"><Switch checked={node.disableTcpKeepAlive} onChange={(e) => onChange({ ...node, disableTcpKeepAlive: e.target.checked })} label="禁用 TCP Keep Alive" /></div><Field label="TCP Keep Alive"><Input value={node.tcpKeepAlive} placeholder="例如 5m" onChange={(e) => onChange({ ...node, tcpKeepAlive: e.target.value })} /></Field><Field label="TCP Keep Alive Interval"><Input value={node.tcpKeepAliveInterval} placeholder="例如 75s" onChange={(e) => onChange({ ...node, tcpKeepAliveInterval: e.target.value })} /></Field><div className="switch-field"><Switch checked={node.udpFragment} onChange={(e) => onChange({ ...node, udpFragment: e.target.checked })} label="UDP Fragment" /></div><Field label="Domain Resolver"><Input value={node.domainResolver} onChange={(e) => onChange({ ...node, domainResolver: e.target.value })} /></Field><Field label="Network Strategy"><Input value={node.networkStrategy} onChange={(e) => onChange({ ...node, networkStrategy: e.target.value })} /></Field><Field label="Network Type"><Input value={node.networkType} placeholder="例如 wifi, cellular" onChange={(e) => onChange({ ...node, networkType: e.target.value })} /></Field><Field label="Fallback Network Type"><Input value={node.fallbackNetworkType} onChange={(e) => onChange({ ...node, fallbackNetworkType: e.target.value })} /></Field><Field label="Fallback Delay"><Input value={node.fallbackDelay} placeholder="例如 300ms" onChange={(e) => onChange({ ...node, fallbackDelay: e.target.value })} /></Field><Field label="Domain Strategy"><Select value={node.domainStrategy} onChange={(e) => onChange({ ...node, domainStrategy: e.target.value })}><option value="">默认</option><option value="prefer_ipv4">prefer_ipv4</option><option value="prefer_ipv6">prefer_ipv6</option><option value="ipv4_only">ipv4_only</option><option value="ipv6_only">ipv6_only</option></Select></Field><div className="switch-field"><Switch checked={node.multiplexEnabled} onChange={(e) => onChange({ ...node, multiplexEnabled: e.target.checked })} label="启用 Multiplex" /></div><Field label="Multiplex 协议"><Select value={node.multiplexProtocol} onChange={(e) => onChange({ ...node, multiplexProtocol: e.target.value })}><option value="h2mux">h2mux</option><option value="smux">smux</option><option value="yamux">yamux</option></Select></Field><Field label="最大连接数"><Input type="number" min={0} value={String(node.multiplexMaxConnections)} onChange={(e) => onChange({ ...node, multiplexMaxConnections: Number(e.target.value) })} /></Field><Field label="最小流数"><Input type="number" min={0} value={String(node.multiplexMinStreams)} onChange={(e) => onChange({ ...node, multiplexMinStreams: Number(e.target.value) })} /></Field><Field label="最大流数"><Input type="number" min={0} value={String(node.multiplexMaxStreams)} onChange={(e) => onChange({ ...node, multiplexMaxStreams: Number(e.target.value) })} /></Field><div className="switch-field"><Switch checked={node.multiplexPadding} onChange={(e) => onChange({ ...node, multiplexPadding: e.target.checked })} label="Multiplex Padding" /></div><Field label="TCP Brutal JSON" hint="例如 {&quot;enabled&quot;:true,&quot;up_mbps&quot;:100,&quot;down_mbps&quot;:100"><Input value={node.multiplexBrutal} onChange={(e) => onChange({ ...node, multiplexBrutal: e.target.value })} /></Field>
      </div>
    </details>
  );
  return <ModalFrame className="node-dialog" labelledBy="node-editor-title" onCancel={onCancel}>
      <div className="modal-header"><Text id="node-editor-title" as="h2" weight="semibold">{node.tag || "编辑节点"}</Text><Button appearance="subtle" onClick={onCancel} data-modal-initial-focus>关闭</Button></div>
      <div className="modal-body">
        <div className="node-fields">
          <Field label="标签"><Input value={node.tag} onChange={(e) => onChange({ ...node, tag: e.target.value })} /></Field>
          <Field label="类型" hint="切换协议会清理协议专属参数，只保留标签、服务器和端口。"><Select value={node.type} onChange={(e) => changeType(e.target.value)}>{outboundProtocolOptions.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</Select></Field>
          {serverTypes && <><Field label="服务器" className="field-span-2"><Input value={node.server} placeholder="example.com 或 IP" onChange={(e) => onChange({ ...node, server: e.target.value })} /></Field><Field label="端口" className="field-narrow"><Input type="number" value={String(node.serverPort)} onChange={(e) => onChange({ ...node, serverPort: Number(e.target.value) })} /></Field></>}
          {(node.type === "hysteria" || node.type === "hysteria2") && <><Field label="端口范围" hint="多个端口或范围用逗号分隔；填写后忽略单端口。"><Input value={node.serverPorts} placeholder="例如 2000:3000, 4000" onChange={(e) => onChange({ ...node, serverPorts: e.target.value })} /></Field><Field label="端口跳跃间隔"><Input value={node.hopInterval} placeholder="例如 30s" onChange={(e) => onChange({ ...node, hopInterval: e.target.value })} /></Field>{node.type === "hysteria2" && <Field label="最大跳跃间隔"><Input value={node.hopIntervalMax} placeholder="例如 60s" onChange={(e) => onChange({ ...node, hopIntervalMax: e.target.value })} /></Field>}</>}
          {node.type === "tor" && <><Field label="Tor 可执行文件" className="field-span-2"><Input value={node.executablePath} placeholder="留空：使用 PATH 中的 tor" onChange={(e) => onChange({ ...node, executablePath: e.target.value })} /></Field><Field label="数据目录" className="field-span-2"><Input value={node.dataDirectory} placeholder="可选" onChange={(e) => onChange({ ...node, dataDirectory: e.target.value })} /></Field></>}
          {(node.type === "vmess" || node.type === "vless" || node.type === "tuic") && <Field label="UUID" className="field-span-2"><Input value={node.uuid} onChange={(e) => onChange({ ...node, uuid: e.target.value })} /></Field>}
          {node.type === "vmess" && <><Field label="VMess 加密"><Select value={node.security} onChange={(e) => onChange({ ...node, security: e.target.value })}><option value="auto">auto</option><option value="none">none</option><option value="zero">zero</option><option value="aes-128-gcm">aes-128-gcm</option><option value="chacha20-poly1305">chacha20-poly1305</option></Select></Field><Field label="alterId" className="field-narrow"><Input type="number" min={0} value={String(node.alterId)} onChange={(e) => onChange({ ...node, alterId: Number(e.target.value) })} /></Field></>}
          {node.type === "vless" && <Field label="VLESS flow"><Input value={node.flow} placeholder="例如 xtls-rprx-vision" onChange={(e) => onChange({ ...node, flow: e.target.value })} /></Field>}
          {(node.type === "vmess" || node.type === "vless") && <Field label="Packet Encoding"><Select value={node.packetEncoding} onChange={(e) => onChange({ ...node, packetEncoding: e.target.value })}><option value="">默认</option><option value="packetaddr">packetaddr</option><option value="xudp">xudp</option></Select></Field>}
          {node.type === "shadowsocks" && <><Field label="加密方法" hint="例如 2022-blake3-aes-128-gcm、aes-256-gcm。"><Input value={node.method} onChange={(e) => onChange({ ...node, method: e.target.value })} /></Field><Field label="密码"><Input type="password" value={node.password} onChange={(e) => onChange({ ...node, password: e.target.value })} /></Field><Field label="Plugin"><Input value={node.plugin} placeholder="可选，例如 obfs-local" onChange={(e) => onChange({ ...node, plugin: e.target.value })} /></Field><Field label="Plugin 参数"><Input value={node.pluginOptions} placeholder="可选，例如 obfs=http;obfs-host=example.com" onChange={(e) => onChange({ ...node, pluginOptions: e.target.value })} /></Field></>}
          {node.type === "socks" && <Field label="SOCKS 版本"><Select value={String(node.version || 5)} onChange={(e) => onChange({ ...node, version: Number(e.target.value) })}><option value="4">4</option><option value="5">5</option></Select></Field>}
          {(node.type === "wireguard") && <><Field label="私钥"><Input type="password" value={node.privateKey} onChange={(e) => onChange({ ...node, privateKey: e.target.value })} /></Field><Field label="对端公钥"><Input value={node.peerPublicKey} onChange={(e) => onChange({ ...node, peerPublicKey: e.target.value })} /></Field><Field label="预共享密钥"><Input type="password" value={node.preSharedKey} onChange={(e) => onChange({ ...node, preSharedKey: e.target.value })} /></Field><Field label="本地地址" hint="多个地址用逗号分隔，例如 172.16.0.2/32。"><Input value={node.localAddress} onChange={(e) => onChange({ ...node, localAddress: e.target.value })} /></Field><Field label="使用系统网卡"><Select value={node.wireguardSystemInterface ? "true" : "false"} onChange={(e) => onChange({ ...node, wireguardSystemInterface: e.target.value === "true" })}><option value="false">否</option><option value="true">是</option></Select></Field><Field label="接口名称"><Input value={node.wireguardInterfaceName} placeholder="例如 wg0" onChange={(e) => onChange({ ...node, wireguardInterfaceName: e.target.value })} /></Field><Field label="MTU"><Input type="number" min={0} value={String(node.wireguardMtu)} onChange={(e) => onChange({ ...node, wireguardMtu: Number(e.target.value) })} /></Field><Field label="Workers"><Input type="number" min={0} value={String(node.wireguardWorkers)} onChange={(e) => onChange({ ...node, wireguardWorkers: Number(e.target.value) })} /></Field><Field label="网络"><Select value={node.wireguardNetwork} onChange={(e) => onChange({ ...node, wireguardNetwork: e.target.value })}><option value="">默认</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp,udp">TCP + UDP</option></Select></Field><Field label="Reserved"><Input value={node.wireguardReserved} placeholder="例如 0, 0, 0" onChange={(e) => onChange({ ...node, wireguardReserved: e.target.value })} /></Field></>}
          {(node.type === "hysteria" || node.type === "hysteria2") && <><Field label="上行带宽 Mbps" className="field-narrow"><Input type="number" min={0} value={String(node.upMbps)} onChange={(e) => onChange({ ...node, upMbps: Number(e.target.value) })} /></Field><Field label="下行带宽 Mbps" className="field-narrow"><Input type="number" min={0} value={String(node.downMbps)} onChange={(e) => onChange({ ...node, downMbps: Number(e.target.value) })} /></Field>{node.type === "hysteria" && <><Field label="上行带宽文本"><Input value={node.upBandwidth} placeholder="例如 100 Mbps" onChange={(e) => onChange({ ...node, upBandwidth: e.target.value })} /></Field><Field label="下行带宽文本"><Input value={node.downBandwidth} placeholder="例如 100 Mbps" onChange={(e) => onChange({ ...node, downBandwidth: e.target.value })} /></Field><Field label="认证密码 Base64"><Input value={node.authBase64} onChange={(e) => onChange({ ...node, authBase64: e.target.value })} /></Field></>}{node.type === "hysteria" ? <Field label="混淆密码" hint="Hysteria v1 的 obfs 是单独的混淆密码。"><Input type="password" value={node.obfsPassword} onChange={(e) => onChange({ ...node, obfsPassword: e.target.value })} /></Field> : <><Field label="混淆类型"><Input value={node.obfs} placeholder="例如 salamander" onChange={(e) => onChange({ ...node, obfs: e.target.value })} /></Field><Field label="混淆密码"><Input type="password" value={node.obfsPassword} onChange={(e) => onChange({ ...node, obfsPassword: e.target.value })} /></Field></>}{<Field label="网络"><Select value={node.network} onChange={(e) => onChange({ ...node, network: e.target.value })}><option value="">TCP + UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>}</>}
          {(node.type === "shadowtls" || node.type === "snell") && <Field label="版本" className="field-narrow"><Select value={String(node.version || (node.type === "snell" ? 4 : 3))} onChange={(e) => onChange({ ...node, version: Number(e.target.value) })}>{node.type === "snell" ? <><option value="4">4</option><option value="6">6</option></> : <><option value="1">1</option><option value="2">2</option><option value="3">3</option></>}</Select></Field>}
          {node.type === "shadowtls" && <Field label="ShadowTLS 密码"><Input type="password" value={node.password} onChange={(e) => onChange({ ...node, password: e.target.value })} /></Field>}
          {node.type === "naive" && <div className="switch-field"><Switch checked={node.zeroRttHandshake} onChange={(e) => onChange({ ...node, zeroRttHandshake: e.target.checked })} label="QUIC" /></div>}
          {node.type === "tor" && <Field label="Tor 参数 JSON" hint="填写字符串数组，例如 [&quot;--SocksPort&quot;,&quot;9050&quot;]"><Input value={node.torArgs} onChange={(e) => onChange({ ...node, torArgs: e.target.value })} /></Field>}
          {tlsCapable && <NodeTlsFields node={node} onChange={onChange} />}
          {(node.type === "trojan" || node.type === "vmess" || node.type === "vless") && <Field label="传输"><Select value={node.network} onChange={(e) => onChange({ ...node, network: e.target.value })}><option value="">TCP</option><option value="ws">WebSocket</option><option value="http">HTTP</option><option value="grpc">gRPC</option><option value="quic">QUIC</option><option value="httpupgrade">HTTPUpgrade</option></Select></Field>}
          {transportCapable && node.network === "ws" && <><Field label="WebSocket 路径"><Input value={node.wsPath} placeholder="/" onChange={(e) => onChange({ ...node, wsPath: e.target.value })} /></Field><Field label="WebSocket Host"><Input value={node.wsHost} onChange={(e) => onChange({ ...node, wsHost: e.target.value })} /></Field><Field label="最大早期数据"><Input type="number" min={0} value={String(node.transportMaxEarlyData)} onChange={(e) => onChange({ ...node, transportMaxEarlyData: Number(e.target.value) })} /></Field><Field label="早期数据 Header"><Input value={node.transportEarlyDataHeaderName} onChange={(e) => onChange({ ...node, transportEarlyDataHeaderName: e.target.value })} /></Field></>}
          {transportCapable && node.network === "http" && <><Field label="HTTP Host"><Input value={node.wsHost} placeholder="多个 Host 用逗号分隔" onChange={(e) => onChange({ ...node, wsHost: e.target.value })} /></Field><Field label="HTTP 路径"><Input value={node.wsPath} placeholder="/" onChange={(e) => onChange({ ...node, wsPath: e.target.value })} /></Field><Field label="HTTP 方法"><Input value={node.transportMethod} placeholder="GET" onChange={(e) => onChange({ ...node, transportMethod: e.target.value })} /></Field><Field label="空闲超时"><Input value={node.transportIdleTimeout} onChange={(e) => onChange({ ...node, transportIdleTimeout: e.target.value })} /></Field><Field label="Ping 超时"><Input value={node.transportPingTimeout} onChange={(e) => onChange({ ...node, transportPingTimeout: e.target.value })} /></Field></>}
          {transportCapable && node.network === "grpc" && <><Field label="gRPC Service Name"><Input value={node.transportServiceName} onChange={(e) => onChange({ ...node, transportServiceName: e.target.value })} /></Field><Field label="空闲超时"><Input value={node.transportIdleTimeout} onChange={(e) => onChange({ ...node, transportIdleTimeout: e.target.value })} /></Field><Field label="Ping 超时"><Input value={node.transportPingTimeout} onChange={(e) => onChange({ ...node, transportPingTimeout: e.target.value })} /></Field><div className="switch-field"><Switch checked={node.transportPermitWithoutStream} onChange={(e) => onChange({ ...node, transportPermitWithoutStream: e.target.checked })} label="Permit Without Stream" /></div></>}
          {transportCapable && node.network === "quic" && <><Field label="QUIC Security"><Input value={node.transportQuicSecurity} placeholder="none / aes-128-gcm / chacha20-poly1305" onChange={(e) => onChange({ ...node, transportQuicSecurity: e.target.value })} /></Field><Field label="QUIC Key"><Input type="password" value={node.transportQuicKey} onChange={(e) => onChange({ ...node, transportQuicKey: e.target.value })} /></Field></>}
          {transportCapable && node.network === "httpupgrade" && <><Field label="HTTPUpgrade Host"><Input value={node.wsHost} onChange={(e) => onChange({ ...node, wsHost: e.target.value })} /></Field><Field label="HTTPUpgrade 路径"><Input value={node.wsPath} placeholder="/" onChange={(e) => onChange({ ...node, wsPath: e.target.value })} /></Field></>}
          {transportCapable && ["ws", "http", "grpc", "httpupgrade"].includes(node.network) && <Field label="Transport Headers JSON" hint="例如 {&quot;Host&quot;:&quot;example.com&quot;}"><Input value={node.transportHeaders} onChange={(e) => onChange({ ...node, transportHeaders: e.target.value })} /></Field>}
          <details className="node-advanced-section node-json-section">
            <summary>高级 JSON 字段</summary>
            <div className="node-fields node-fields-inset">
              <Field label="高级 JSON 字段" hint="可填写 sing-box 该协议未在表单中展示的字段；必须是 JSON 对象。"><Input value={node.extraJson} placeholder='例如 {"multiplex":{"enabled":true}}' onChange={(e) => onChange({ ...node, extraJson: e.target.value })} /></Field>
            </div>
          </details>
          {commonFields}
        </div>
      </div>
      <div className="modal-footer"><Button appearance="secondary" onClick={onCancel}>取消</Button><Button appearance="primary" onClick={onConfirm}>确定</Button></div>
  </ModalFrame>;
}

function GroupEditorDialog({ group, allOutbounds, onChange, onCancel, onConfirm }: { group: PolicyGroup; allOutbounds: string[]; onChange: (group: PolicyGroup) => void; onCancel: () => void; onConfirm: () => void }) {
  const memberOptions = Array.from(new Set([...allOutbounds, ...group.members]));
  const toggleMember = (member: string, checked: boolean) => {
    const members = checked
      ? [...group.members.filter((current) => current !== member), member]
      : group.members.filter((current) => current !== member);
    onChange({ ...group, members });
  };

  return <ModalFrame className="group-dialog" labelledBy="group-editor-title" onCancel={onCancel}>
      <div className="modal-header"><Text id="group-editor-title" as="h2" weight="semibold">{group.name || "编辑策略组"}</Text><Button appearance="subtle" onClick={onCancel} data-modal-initial-focus>关闭</Button></div>
      <div className="modal-body">
        <div className="node-fields">
          <Field label="名称"><Input value={group.name} onChange={(e) => onChange({ ...group, name: e.target.value })} /></Field>
          <Field label="类型"><Select value={group.type} onChange={(e) => onChange({ ...group, type: e.target.value })}><option value="selector">Selector</option><option value="urltest">URLTest</option></Select></Field>
          <div className="member-picker field-span-2">
            <div className="member-picker-heading"><Text weight="semibold">成员</Text><Text size={200}>选择要加入策略组的节点、策略组或 DIRECT 出站。</Text></div>
            <div className="member-picker-grid">
              {memberOptions.map((member) => <Checkbox key={member} checked={group.members.includes(member)} label={member} onChange={(_, data) => toggleMember(member, data.checked === true)} />)}
            </div>
            <Text className="member-picker-summary" size={200}>{group.members.length > 0 ? `已选择 ${group.members.length} 个：${group.members.join("、")}` : "尚未选择成员"}</Text>
          </div>
          <Field label="默认出站"><Select value={group.default} onChange={(e) => onChange({ ...group, default: e.target.value })}>{allOutbounds.map((o) => <option key={o} value={o}>{o}</option>)}</Select></Field>
          {group.type === "urltest" && <><Field label="测速 URL" className="field-span-2"><Input value={group.url} placeholder="https://www.gstatic.com/generate_204" onChange={(e) => onChange({ ...group, url: e.target.value })} /></Field><Field label="测速间隔"><Input value={group.interval} placeholder="3m" onChange={(e) => onChange({ ...group, interval: e.target.value })} /></Field><Field label="容差百分比" className="field-narrow"><Input type="number" min={0} value={String(group.tolerance)} onChange={(e) => onChange({ ...group, tolerance: Number(e.target.value) })} /></Field><Field label="空闲超时"><Input value={group.idleTimeout} placeholder="30m" onChange={(e) => onChange({ ...group, idleTimeout: e.target.value })} /></Field></>}
          {group.type === "selector" && <div className="switch-field"><Switch checked={group.interruptExistConnections} onChange={(e) => onChange({ ...group, interruptExistConnections: e.target.checked })} label="切换时中断现有连接" /></div>}
        </div>
      </div>
      <div className="modal-footer"><Button appearance="secondary" onClick={onCancel}>取消</Button><Button appearance="primary" onClick={onConfirm}>确定</Button></div>
  </ModalFrame>;
}

function PlannedRow({ title, description }: { title: string; description: string }) {
  return <div className="planned-row"><span className="planned-mark">—</span><div><Text weight="semibold">{title}</Text><Text size={200}>{description}</Text></div><Badge appearance="outline" color="subtle" size="small">计划中</Badge></div>;
}

const ruleFieldOptions = [
  ["domain", "完整域名", "example.com"],
  ["domain_suffix", "域名后缀", "example.com"],
  ["domain_keyword", "域名关键词", "openai"],
  ["domain_regex", "域名正则", "^api\\\\."],
  ["ip_cidr", "目标 IP/CIDR", "192.168.0.0/16"],
  ["source_ip_cidr", "来源 IP/CIDR", "192.168.1.0/24"],
  ["ip_is_private", "目标是私有 IP", "true"],
  ["source_ip_is_private", "来源是私有 IP", "true"],
  ["port", "目标端口", "80, 443"],
  ["port_range", "目标端口范围", "8000:9000"],
  ["source_port", "来源端口", "1024, 65535"],
  ["source_port_range", "来源端口范围", "10000:20000"],
  ["protocol", "协议", "http, tls"],
  ["network", "网络类型", "tcp, udp"],
  ["ip_version", "IP 版本", "4 或 6"],
  ["inbound", "入站标签", "mixed-in"],
  ["auth_user", "认证用户", "user-a"],
  ["client", "Sniff 客户端", "chrome"],
  ["process_name", "进程名", "Safari"],
  ["process_path", "进程路径", "/Applications/Safari.app/Contents/MacOS/Safari"],
  ["process_path_regex", "进程路径正则", "Safari\\\\.app"],
  ["package_name", "Android 包名", "com.example.app"],
  ["user", "Linux 用户", "alice"],
  ["user_id", "Linux 用户 ID", "1000"],
  ["clash_mode", "Clash 模式", "direct"],
  ["network_type", "系统网络", "wifi"],
  ["network_is_expensive", "计费网络", "true"],
  ["network_is_constrained", "低流量模式", "true"],
  ["interface_address", "网卡地址", "en0=192.168.1.0/24"],
  ["network_interface_address", "网络接口地址", "wifi=192.168.1.0/24"],
  ["default_interface_address", "默认接口地址", "192.168.1.0/24"],
  ["wifi_ssid", "Wi-Fi SSID", "My Wi-Fi"],
  ["wifi_bssid", "Wi-Fi BSSID", "00:11:22:33:44:55"],
  ["preferred_by", "首选出站", "wireguard, tailscale"],
  ["rule_set", "规则集", "geosite-cn"],
  ["rule_set_ip_cidr_match_source", "规则集 CIDR 匹配来源", "true"],
] as const;

const booleanRuleFields = new Set(["ip_is_private", "source_ip_is_private", "network_is_expensive", "network_is_constrained", "rule_set_ip_cidr_match_source"]);
const platformRuleHints: Record<string, string> = {
  package_name: "仅 Android 图形客户端支持",
  user: "仅 Linux 支持",
  user_id: "仅 Linux 支持",
  network_type: "Apple 和 Android 图形客户端支持",
  network_is_constrained: "仅 Apple 图形客户端支持",
  interface_address: "Linux、Windows、macOS 支持",
  network_interface_address: "Linux、Windows、macOS 支持",
  default_interface_address: "Linux、Windows、macOS 支持",
  wifi_ssid: "Apple 和 Android 图形客户端支持",
  wifi_bssid: "Apple 和 Android 图形客户端支持",
};
const ruleFieldDescriptions: Record<string, string> = {
  domain: "匹配完整域名，例如 example.com。",
  domain_suffix: "匹配域名后缀，例如 example.com 会匹配其子域名。",
  domain_keyword: "匹配包含指定关键词的域名。",
  domain_regex: "使用正则表达式匹配域名。",
  ip_cidr: "匹配目标 IP 或 CIDR 网段。",
  source_ip_cidr: "匹配来源 IP 或 CIDR 网段。",
  ip_is_private: "匹配目标是否为非公开（私有）IP。",
  source_ip_is_private: "匹配来源是否为非公开（私有）IP。",
  port: "匹配目标端口，可填写多个端口。",
  port_range: "匹配目标端口范围，格式为起始端口:结束端口。",
  source_port: "匹配来源端口，可填写多个端口。",
  source_port_range: "匹配来源端口范围。",
  protocol: "匹配协议嗅探结果，例如 http、tls、quic、dns。",
  network: "匹配网络类型：tcp、udp 或 icmp。",
  ip_version: "匹配 IP 版本：4 或 6。",
  inbound: "按入站标签匹配，例如 mixed-in。",
  auth_user: "按入站认证用户名匹配。",
  client: "按协议嗅探得到的客户端类型匹配。",
  process_name: "按进程名称匹配。",
  process_path: "按进程完整路径匹配。",
  process_path_regex: "使用正则表达式匹配进程路径。",
  package_name: "按 Android 应用包名匹配。",
  user: "按 Linux 用户名匹配。",
  user_id: "按 Linux 用户 ID 匹配。",
  clash_mode: "按 Clash 模式匹配，例如 direct、global。",
  network_type: "按系统网络类型匹配：wifi、cellular、ethernet 或 other。",
  network_is_expensive: "匹配网络是否被系统标记为计费或昂贵网络。",
  network_is_constrained: "匹配网络是否处于低数据模式。",
  interface_address: "匹配网卡接口地址。",
  network_interface_address: "匹配指定网络类型对应的接口地址。",
  default_interface_address: "匹配默认网络接口地址。",
  wifi_ssid: "按 Wi-Fi SSID 匹配。",
  wifi_bssid: "按 Wi-Fi BSSID 匹配。",
  preferred_by: "匹配指定出站的首选路由。",
  rule_set: "匹配已配置规则集中的规则。",
  rule_set_ip_cidr_match_source: "让规则集中的 ip_cidr 使用来源 IP 进行匹配。",
};

function newEditorId(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

function createFieldCondition(field = "domain_suffix"): RuleCondition {
  return { id: newEditorId("condition"), type: "field", field, value: "", invert: false };
}

function createLogicalCondition(): RuleCondition {
  return { id: newEditorId("group"), type: "logical", mode: "and", invert: false, rules: [createFieldCondition()] };
}

function defaultRuleFieldValue(field: string): string {
  if (booleanRuleFields.has(field)) return "true";
  if (field === "ip_version") return "4";
  return "";
}

function fieldHint(field: string): string {
  return ruleFieldOptions.find(([value]) => value === field)?.[2] ?? "用逗号或换行分隔多个值";
}

function summarizeCondition(condition: RuleCondition): string {
  if (condition.type === "field") {
    const fieldName = condition.field ?? "domain_suffix";
    const value = (condition.value ?? "").trim();
    const text = value ? `${fieldName} = ${value.split(/[,\\n]/)[0].trim()}${value.includes(",") || value.includes("\\n") ? " …" : ""}` : `${fieldName} = <未设置>`;
    return condition.invert ? `不是 ${text}` : text;
  }
  const children = condition.rules ?? [];
  const separator = condition.mode === "or" ? " 或 " : " 且 ";
  const text = `(${children.map(summarizeCondition).join(separator)})`;
  return condition.invert ? `不满足 ${text}` : text;
}

function summarizeRuleSet(ruleSet: RuleSetConfig): string {
  const source = ruleSet.type === "remote" ? ruleSet.url || "<未设置 URL>" : ruleSet.path || "<未设置路径>";
  return `${ruleSet.type === "remote" ? "远程" : "本地"} · ${ruleSet.format} · ${source}`;
}

function conditionMatchesDns(condition: RuleCondition): boolean {
  if (condition.type === "logical") return (condition.rules ?? []).some(conditionMatchesDns);
  return condition.field === "protocol" && (condition.value ?? "").split(/[,\\n]/).some((value) => value.trim().toLowerCase() === "dns");
}

function RuleConditionEditor({ condition, onChange, onRemove, canRemove, depth = 0 }: { condition: RuleCondition; onChange: (next: RuleCondition) => void; onRemove?: () => void; canRemove: boolean; depth?: number }) {
  if (condition.type === "logical") {
    const children = condition.rules ?? [];
    return <div className="rule-node logical-node">
      <div className="rule-node-header">
        <div className="rule-node-title"><Badge appearance="tint" color="informative">{condition.mode === "or" ? "任一满足" : "全部满足"}</Badge><Text size={200}>逻辑组</Text></div>
        <div className="rule-node-actions">
          <Select value={condition.mode ?? "and"} onChange={(event) => onChange({ ...condition, mode: event.target.value as "and" | "or" })}><option value="and">全部满足</option><option value="or">任一满足</option></Select>
          <Button appearance={condition.invert ? "primary" : "subtle"} onClick={() => onChange({ ...condition, invert: !condition.invert })}>不满足</Button>
          {canRemove && onRemove && <Button appearance="subtle" onClick={onRemove}>删除组</Button>}
        </div>
      </div>
      <div className="rule-children">
        {children.map((child, index) => <RuleConditionEditor key={child.id} condition={child} depth={depth + 1} canRemove={children.length > 1} onChange={(next) => onChange({ ...condition, rules: children.map((item, childIndex) => childIndex === index ? next : item) })} onRemove={() => onChange({ ...condition, rules: children.filter((_, childIndex) => childIndex !== index) })} />)}
      </div>
      <div className="rule-node-footer"><Button appearance="subtle" onClick={() => onChange({ ...condition, rules: [...children, createFieldCondition()] })}>+ 条件</Button><Button appearance="subtle" disabled={depth >= 3} onClick={() => onChange({ ...condition, rules: [...children, createLogicalCondition()] })}>+ 条件组</Button>{depth >= 3 && <Text className="rule-depth-warning" size={200}>已达到 4 层嵌套上限</Text>}</div>
    </div>;
  }

  const field = condition.field ?? "domain_suffix";
  const visibleFields = ruleFieldOptions;
  const input = booleanRuleFields.has(field)
    ? <Select value={condition.value ?? ""} onChange={(event) => onChange({ ...condition, value: event.target.value })}><option value="true">true</option><option value="false">false</option></Select>
    : field === "ip_version"
      ? <Select value={condition.value ?? ""} onChange={(event) => onChange({ ...condition, value: event.target.value })}><option value="">选择版本</option><option value="4">IPv4</option><option value="6">IPv6</option></Select>
      : <Input value={condition.value ?? ""} placeholder={fieldHint(field)} onChange={(event) => onChange({ ...condition, value: event.target.value })} />;
  const fieldPicker = <Dropdown
    className="rule-field-picker"
    value={field}
    selectedOptions={[field]}
    onOptionSelect={(_, data) => {
      const nextField = data.optionValue ?? field;
      onChange({ ...condition, field: nextField, value: defaultRuleFieldValue(nextField) });
    }}
  >
    {visibleFields.map(([value]) => <Option key={value} value={value} text={value}>
      <span className="rule-field-option">
        <span className="rule-field-option-name">{value}</span>
        <span className="rule-field-option-description">{ruleFieldDescriptions[value] ?? "sing-box 路由规则匹配字段。"}</span>
      </span>
    </Option>)}
  </Dropdown>;
  return <div className="rule-node field-node">
    <div className="rule-node-header"><div className="rule-node-title"><Badge appearance="outline" color="subtle">匹配条件</Badge><Text size={200}>字段</Text></div><div className="rule-node-actions"><Select value={condition.invert ? "not" : "is"} onChange={(event) => onChange({ ...condition, invert: event.target.value === "not" })}><option value="is">是</option><option value="not">不是</option></Select>{canRemove && onRemove && <Button appearance="subtle" onClick={onRemove}>删除</Button>}</div></div>
    <div className="rule-field-row"><Tooltip key={field} content={ruleFieldDescriptions[field] ?? "sing-box 路由规则匹配字段。"} relationship="description" positioning="above-start">{fieldPicker}</Tooltip>{input}</div>
    <Text className="rule-field-description" size={200}>{ruleFieldDescriptions[field] ?? "sing-box 路由规则匹配字段。"}</Text>
    {platformRuleHints[field] && <Text className="rule-field-hint" size={200}>{platformRuleHints[field]}</Text>}
  </div>;
}

function createLogicalConditionFrom(condition: RuleCondition): RuleCondition {
  return { id: newEditorId("group"), type: "logical", mode: "and", invert: false, rules: [condition, createFieldCondition()] };
}

function RulesPage({ config, running, policyMode, target, onTargetChange, onSave }: { config: ProxyConfig; running: boolean; policyMode: RuntimeSettings["gatewayPolicyMode"]; target: ProxyConfigTarget; onTargetChange: (target: ProxyConfigTarget) => void; onSave: (config: ProxyConfig, target: ProxyConfigTarget) => Promise<void> }) {
  const [draft, setDraft] = useState<ProxyConfig>(config);
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const [draggedRuleIndex, setDraggedRuleIndex] = useState<number | null>(null);
  const [editing, setEditing] = useState<{ index: number | null; rule: ProxyRule } | null>(null);
  const [editingRuleSet, setEditingRuleSet] = useState<{ index: number | null; ruleSet: RuleSetConfig } | null>(null);
  useEffect(() => setDraft(config), [config]);

  const outbounds = ["direct", ...draft.nodes.map((n) => n.tag), ...draft.groups.map((g) => g.name)];

  async function applyConfig(next: ProxyConfig): Promise<boolean> {
    setDraft(next);
    setMessage("");
    setSaving(true);
    try {
      await onSave(next, target);
      setMessage(running ? "已立即应用。" : "已保存，下次启动时生效。");
      return true;
    } catch (error) {
      setMessage(`应用失败：${String(error)}`);
      return false;
    } finally {
      setSaving(false);
    }
  }

  async function updateRule(index: number, patch: Partial<ProxyRule>) {
    await applyConfig({ ...draft, rules: draft.rules.map((rule, ruleIndex) => ruleIndex === index ? { ...rule, ...patch } : rule) });
  }
  function openNewRule() {
    setEditing({ index: null, rule: { id: newEditorId("rule"), name: `规则 ${draft.rules.length + 1}`, action: "route", outbound: "direct", enabled: true, condition: createFieldCondition() } });
  }
  function openEditRule(index: number) {
    setEditing({ index, rule: { ...draft.rules[index] } });
  }
  async function commitEditing() {
    if (!editing) return;
    const next = editing.index === null
      ? { ...draft, rules: [...draft.rules, editing.rule] }
      : { ...draft, rules: draft.rules.map((rule, ruleIndex) => ruleIndex === editing.index ? editing.rule : rule) };
    if (await applyConfig(next)) setEditing(null);
  }
  async function removeRule(index: number) {
    await applyConfig({ ...draft, rules: draft.rules.filter((_, ruleIndex) => ruleIndex !== index) });
  }
  async function moveRule(index: number, delta: number) {
    const nextIndex = index + delta;
    if (nextIndex < 0 || nextIndex >= draft.rules.length) return;
    const rules = [...draft.rules];
    [rules[index], rules[nextIndex]] = [rules[nextIndex], rules[index]];
    await applyConfig({ ...draft, rules });
  }
  async function dropRule(targetIndex: number) {
    if (draggedRuleIndex === null || draggedRuleIndex === targetIndex) return;
    const rules = [...draft.rules];
    const [moved] = rules.splice(draggedRuleIndex, 1);
    rules.splice(targetIndex, 0, moved);
    setDraggedRuleIndex(null);
    await applyConfig({ ...draft, rules });
  }
  function openNewRuleSet() {
    setEditingRuleSet({ index: null, ruleSet: { type: "remote", tag: `ruleset-${draft.ruleSets.length + 1}`, format: "binary", path: "", url: "", updateInterval: "1d" } });
  }
  function openEditRuleSet(index: number) {
    setEditingRuleSet({ index, ruleSet: { ...draft.ruleSets[index] } });
  }
  async function commitRuleSet() {
    if (!editingRuleSet) return;
    const next = editingRuleSet.index === null
      ? { ...draft, ruleSets: [...draft.ruleSets, editingRuleSet.ruleSet] }
      : { ...draft, ruleSets: draft.ruleSets.map((ruleSet, ruleSetIndex) => ruleSetIndex === editingRuleSet.index ? editingRuleSet.ruleSet : ruleSet) };
    if (await applyConfig(next)) setEditingRuleSet(null);
  }
  async function moveRuleSet(index: number, delta: number) {
    const nextIndex = index + delta;
    if (nextIndex < 0 || nextIndex >= draft.ruleSets.length) return;
    const ruleSets = [...draft.ruleSets];
    [ruleSets[index], ruleSets[nextIndex]] = [ruleSets[nextIndex], ruleSets[index]];
    await applyConfig({ ...draft, ruleSets });
  }
  async function removeRuleSet(index: number) {
    await applyConfig({ ...draft, ruleSets: draft.ruleSets.filter((_, ruleSetIndex) => ruleSetIndex !== index) });
  }

  return <div className="page-content page-stack">
    <div className="page-actions"><Text className={`save-message ${message.startsWith("应用失败") ? "error" : ""}`} size={200}>{message}</Text></div>
    <ProxyPolicyTargetBar mode={policyMode} target={target} onChange={onTargetChange} />
    <section className="page-section"><SectionHeading title="规则" description="从上到下按优先级匹配，命中后停止继续匹配；未命中的流量交给默认出站。" action={<Button appearance="primary" onClick={openNewRule} disabled={saving}>添加规则</Button>} />{draft.rules.length === 0 ? <Card className="panel"><EmptyState title="尚未添加规则" description="点击上方「添加规则」开始配置。" /></Card> : <Card className="panel rule-list">{draft.rules.map((rule, index) => {
      const outboundExists = outbounds.includes(rule.outbound);
      return <div key={rule.id} className={`rule-list-row ${draggedRuleIndex === index ? "is-dragging" : ""}`} draggable onDragStart={() => setDraggedRuleIndex(index)} onDragEnd={() => setDraggedRuleIndex(null)} onDragOver={(event) => event.preventDefault()} onDrop={() => dropRule(index)}>
        <button className="rule-order-handle" title="拖动调整优先级">≡</button>
        <span className="rule-index">{index + 1}</span>
        <div className="rule-list-main">
          <div className="rule-list-title"><Text weight="semibold">{rule.name || `规则 ${index + 1}`}</Text><Badge appearance="outline" color={rule.enabled ? "success" : "subtle"}>{rule.enabled ? "启用" : "停用"}</Badge></div>
          <Text className="rule-summary" size={200}>{summarizeCondition(rule.condition)}{rule.action === "route" ? ` → action=route, outbound=${rule.outbound || "<未设置>"}` : ` → action=${rule.action}`}{!outboundExists && rule.action === "route" && <span className="rule-warning">（出站不存在）</span>}</Text>
        </div>
        <div className="rule-list-actions">
          <Button appearance="subtle" onClick={() => void moveRule(index, -1)} disabled={saving || index === 0}>上移</Button>
          <Button appearance="subtle" onClick={() => void moveRule(index, 1)} disabled={saving || index === draft.rules.length - 1}>下移</Button>
          <Button appearance="subtle" onClick={() => void updateRule(index, { enabled: !rule.enabled })} disabled={saving}>{rule.enabled ? "停用" : "启用"}</Button>
          <Button appearance="secondary" onClick={() => openEditRule(index)} disabled={saving}>编辑</Button>
          <Button appearance="subtle" onClick={() => void removeRule(index)} disabled={saving}>删除</Button>
        </div>
      </div>;
    })}</Card>}</section>
    <section className="page-section"><SectionHeading title="规则集" description="使用本地或远程 .srs/.json 规则集；规则条件中的“规则集”必须引用这里的标签。" action={<Button appearance="secondary" onClick={openNewRuleSet} disabled={saving}>添加规则集</Button>} />{draft.ruleSets.length === 0 ? <Card className="panel"><EmptyState title="暂无规则集" description="不使用规则集时可以留空。sing-box 1.13+ 使用 rule_set 替代旧的 GeoSite/GeoIP 数据库。" /></Card> : <Card className="panel rule-list">{draft.ruleSets.map((ruleSet, index) => <div key={`${ruleSet.tag}-${index}`} className="rule-list-row"><span className="rule-index">{index + 1}</span><div className="rule-list-main"><div className="rule-list-title"><Text weight="semibold">{ruleSet.tag || `规则集 ${index + 1}`}</Text><Badge appearance="outline" color={ruleSet.type === "remote" ? "informative" : "subtle"}>{ruleSet.type === "remote" ? "远程" : "本地"}</Badge></div><Text className="rule-summary" size={200}>{summarizeRuleSet(ruleSet)}</Text></div><div className="rule-list-actions"><Button appearance="subtle" onClick={() => void moveRuleSet(index, -1)} disabled={saving || index === 0}>上移</Button><Button appearance="subtle" onClick={() => void moveRuleSet(index, 1)} disabled={saving || index === draft.ruleSets.length - 1}>下移</Button><Button appearance="secondary" onClick={() => openEditRuleSet(index)} disabled={saving}>编辑</Button><Button appearance="subtle" onClick={() => void removeRuleSet(index)} disabled={saving}>删除</Button></div></div>)}</Card>}</section>

    {editing && <RuleEditorDialog rule={editing.rule} outbounds={outbounds} onChange={(rule) => setEditing({ ...editing, rule })} onCancel={() => setEditing(null)} onConfirm={commitEditing} />}
    {editingRuleSet && <RuleSetEditorDialog ruleSet={editingRuleSet.ruleSet} onChange={(ruleSet) => setEditingRuleSet({ ...editingRuleSet, ruleSet })} onCancel={() => setEditingRuleSet(null)} onConfirm={commitRuleSet} />}
  </div>;
}

function RuleEditorDialog({ rule, outbounds, onChange, onCancel, onConfirm }: { rule: ProxyRule; outbounds: string[]; onChange: (rule: ProxyRule) => void; onCancel: () => void; onConfirm: () => void }) {
  const outboundExists = outbounds.includes(rule.outbound);
  return <div className="modal-backdrop" onClick={onCancel}>
    <div className="modal-surface rule-dialog" onClick={(event) => event.stopPropagation()}>
      <div className="modal-header">
        <Text as="h2" weight="semibold">{rule.name || "编辑规则"}</Text>
        <Button appearance="subtle" onClick={onCancel}>关闭</Button>
      </div>
      <div className="modal-body">
        <div className="rule-dialog-fields">
          <Field label="规则名称"><Input value={rule.name} onChange={(event) => onChange({ ...rule, name: event.target.value })} /></Field>
          <Field label="启用"><Select value={rule.enabled ? "true" : "false"} onChange={(event) => onChange({ ...rule, enabled: event.target.value === "true" })}><option value="true">启用</option><option value="false">停用</option></Select></Field>
        </div>
        <div className="rule-dialog-section">
          <div className="rule-syntax-label"><Text size={200}>如果</Text></div>
          <RuleConditionEditor condition={rule.condition} canRemove={false} onChange={(condition) => onChange({ ...rule, condition })} />
          {rule.condition.type === "field" && <Button appearance="subtle" onClick={() => onChange({ ...rule, condition: createLogicalConditionFrom(rule.condition) })}>+ 添加条件组</Button>}
        </div>
        <div className="rule-dialog-section">
          <div className="rule-action-row"><Text size={200} weight="semibold">则</Text><Select value={rule.action} onChange={(event) => onChange({ ...rule, action: event.target.value as ProxyRule["action"] })}><option value="route">路由到出站</option><option value="reject">拒绝连接</option><option value="hijack-dns">交给 SongsterX DNS</option></Select>{rule.action === "route" && <Select value={rule.outbound} onChange={(event) => onChange({ ...rule, outbound: event.target.value })}>{!outboundExists && rule.outbound && <option value={rule.outbound}>⚠ {rule.outbound}（出站不存在）</option>}{outbounds.map((outbound) => <option key={outbound} value={outbound}>{outbound}</option>)}</Select>}{rule.action === "hijack-dns" && !conditionMatchesDns(rule.condition) && <Text className="rule-warning" size={200}>此动作只适用于 DNS 流量；建议添加“协议 = DNS”。</Text>}</div>
        </div>
      </div>
      <div className="modal-footer"><Button appearance="secondary" onClick={onCancel}>取消</Button><Button appearance="primary" onClick={onConfirm}>确定</Button></div>
    </div>
  </div>;
}

function RuleSetEditorDialog({ ruleSet, onChange, onCancel, onConfirm }: { ruleSet: RuleSetConfig; onChange: (ruleSet: RuleSetConfig) => void; onCancel: () => void; onConfirm: () => void }) {
  return <div className="modal-backdrop" onClick={onCancel}>
    <div className="modal-surface ruleset-dialog" onClick={(event) => event.stopPropagation()}>
      <div className="modal-header"><Text as="h2" weight="semibold">{ruleSet.tag || "编辑规则集"}</Text><Button appearance="subtle" onClick={onCancel}>关闭</Button></div>
      <div className="modal-body">
        <div className="node-fields ruleset-dialog-fields">
          <Field label="类型" hint="本地规则集读取文件；远程规则集按更新间隔下载。"><Select value={ruleSet.type} onChange={(event) => onChange({ ...ruleSet, type: event.target.value as RuleSetConfig["type"] })}><option value="remote">远程</option><option value="local">本地</option></Select></Field>
          <Field label="标签" hint="规则条件中的 rule_set 必须引用这个标签。"><Input value={ruleSet.tag} onChange={(event) => onChange({ ...ruleSet, tag: event.target.value })} /></Field>
          <Field label="格式" hint="source 是 JSON 源格式，binary 是 sing-box 编译后的 .srs。"><Select value={ruleSet.format} onChange={(event) => onChange({ ...ruleSet, format: event.target.value as RuleSetConfig["format"] })}><option value="binary">Binary (.srs)</option><option value="source">Source (.json)</option></Select></Field>
          {ruleSet.type === "remote" ? <><Field label="URL" hint="远程规则集下载地址。"><Input value={ruleSet.url} placeholder="https://…/rules.srs" onChange={(event) => onChange({ ...ruleSet, url: event.target.value })} /></Field><Field label="更新间隔" hint="例如 1d、12h。"><Input value={ruleSet.updateInterval} placeholder="1d" onChange={(event) => onChange({ ...ruleSet, updateInterval: event.target.value })} /></Field></> : <Field label="本地路径" hint="本地 .srs 或 .json 文件路径。"><Input value={ruleSet.path} placeholder="/path/to/rules.srs" onChange={(event) => onChange({ ...ruleSet, path: event.target.value })} /></Field>}
        </div>
      </div>
      <div className="modal-footer"><Button appearance="secondary" onClick={onCancel}>取消</Button><Button appearance="primary" onClick={onConfirm}>确定</Button></div>
    </div>
  </div>;
}

function ModulesPage({ modules, onToggleModule, onSetModuleArgument, onImportModule, onImportModuleUrl }: { modules: ModuleInfo[]; onToggleModule: (id: string, enabled: boolean) => void; onSetModuleArgument: (id: string, key: string, value: string) => Promise<void>; onImportModule: (files: File[]) => Promise<void>; onImportModuleUrl: (url: string) => Promise<void> }) {
  const verifiedCount = modules.filter((module) => module.verified).length;
  const [editingModule, setEditingModule] = useState<ModuleInfo | null>(null);
  const [showUrlImport, setShowUrlImport] = useState(false);
  const moduleInputRef = useRef<HTMLInputElement>(null);
  return <div className="page-content page-stack">
    <Card className="panel module-panel">
      <div className="module-panel-header">
        <div><Text as="h2" size={500} weight="semibold">已导入模块</Text><Text size={300}>模块及其远程依赖会在导入阶段下载并固定到本地资源。</Text></div>
        <div className="module-panel-header-actions"><Badge appearance="outline" color={verifiedCount === modules.length && modules.length > 0 ? "success" : "subtle"}>{verifiedCount}/{modules.length} 已校验</Badge><Button appearance="secondary" onClick={() => setShowUrlImport(true)}>从 URL 导入</Button><Button appearance="primary" onClick={() => moduleInputRef.current?.click()}>导入文件</Button><input ref={moduleInputRef} className="module-file-input" type="file" multiple accept=".sgmodule,.module,.js,.json,.list,.txt" onChange={(event) => { const files = Array.from(event.target.files ?? []); event.target.value = ""; if (files.length > 0) void onImportModule(files).catch(() => undefined); }} /></div>
      </div>
      <div className="module-safety-note"><Text size={200}>支持导入 .sgmodule、脚本和规则集。模块会先提取元数据、脚本引用、MITM 主机、静态规则及参数，再通过完整性校验后参与运行计划；不会自动接管流量。</Text></div>
      {modules.length === 0 ? <EmptyState title="还没有导入模块" description="点击右上角“导入文件”，选择 .sgmodule 文件；依赖的脚本或规则集可以一起多选。" /> : <div className="module-list">{modules.map((module) => <div className="module-list-row" key={module.id}>
        <div className="module-list-main"><div className="module-list-title"><Text weight="semibold">{module.name}</Text><Badge appearance="outline" color={module.verified ? "success" : "danger"}>{module.verified ? "完整性通过" : "校验失败"}</Badge></div>{module.description && <Text className="module-list-description" size={200}>{module.description}</Text>}<Text className="module-list-meta" size={200}>{module.id} · v{module.version || "未知"} · {module.sections.join(" · ")}</Text><Text className="module-list-meta" size={200}>{module.ruleCount} 条静态规则 · {module.scriptCount} 个脚本 · {module.mitmHostnames.length} 个 MITM 主机 · {module.runtimeStatus}</Text>{module.warning && <Text className="module-list-warning" size={200}>{module.warning}</Text>}</div><div className="module-list-actions"><Button appearance="subtle" disabled={!module.verified} onClick={() => setEditingModule(module)}>{module.arguments.length > 0 ? "配置" : "详情"}</Button><Button appearance={module.enabled ? "primary" : "secondary"} disabled={!module.verified} onClick={() => onToggleModule(module.id, !module.enabled)}>{module.enabled ? "已启用" : "启用模块"}</Button></div>
      </div>)}</div>}
    </Card>
    {editingModule && <ModuleArgumentsDialog module={editingModule} onSave={onSetModuleArgument} onClose={() => setEditingModule(null)} />}
    {showUrlImport && <ModuleUrlImportDialog onImport={onImportModuleUrl} onClose={() => setShowUrlImport(false)} />}
  </div>;
}

function SettingsPage({ settings, settingsDirty, running, runtimeBusy, busy, message, appearanceMode, onAppearanceChange, onChange, onSave, onReset, onStop }: { settings: RuntimeSettings; settingsDirty: boolean; running: boolean; runtimeBusy: boolean; busy: boolean; message: string; appearanceMode: AppearanceMode; onAppearanceChange: (mode: AppearanceMode) => void; onChange: (next: RuntimeSettings) => void; onSave: () => void; onReset: () => void; onStop: () => void }) {
  const [tab, setTab] = useState("entry");
  return <div className="page-content page-stack">
    <TabList className="settings-page-tabs" selectedValue={tab} onTabSelect={(_, data) => setTab(String(data.value))} aria-label="设置分类">
      <Tab value="entry">代理入口</Tab>
      <Tab value="preferences">偏好</Tab>
    </TabList>
    {tab === "entry" && <EntrySettingsPanel settings={settings} settingsDirty={settingsDirty} running={running} runtimeBusy={runtimeBusy} busy={busy} message={message} onChange={onChange} onSave={onSave} onReset={onReset} onStop={onStop} />}
    {tab === "preferences" && <Card className="panel unavailable-list"><Text as="h2" size={400} weight="semibold">偏好</Text><AppearanceSettingRow mode={appearanceMode} onChange={onAppearanceChange} /><PlannedRow title="授权与更新" description="版本与更新策略。" /></Card>}
  </div>;
}

function EntrySettingsPanel({ settings, settingsDirty, running, runtimeBusy, busy, message, onChange, onSave, onReset, onStop }: { settings: RuntimeSettings; settingsDirty: boolean; running: boolean; runtimeBusy: boolean; busy: boolean; message: string; onChange: (next: RuntimeSettings) => void; onSave: () => void; onReset: () => void; onStop: () => void }) {
  const update = (patch: Partial<RuntimeSettings>) => onChange({ ...settings, ...patch });
  const changeGateway = (enabled: boolean) => update({ mode: enabled ? "gateway" : "mixed", dnsMode: enabled ? (settings.dnsMode === "system" ? "fakeip" : settings.dnsMode) : settings.dnsMode === "fakeip" ? "system" : settings.dnsMode, gatewayDnsIp: enabled ? "198.18.0.2" : settings.gatewayDnsIp });
  const disabled = running || busy;
  const gatewayMode = settings.mode === "gateway";
    return <Card className="panel settings-panel">
    <div className="surge-settings-heading"><div><Text as="h2" size={500} weight="semibold">代理入口</Text><Text size={300}>{gatewayMode ? "Mixed 本机代理仍保留；Gateway 使用 vfkit + 极简 Linux guest，实体 LAN packet path 等待流量验证。" : "本机应用通过 Mixed 代理连接 SongsterX；局域网 Gateway 需要额外的 Linux guest 资源。"}</Text></div><span className="settings-direct-icon"><SettingsRegular /></span></div>
    {running && <div className="settings-notice"><span className="status-dot running-dot" /><Text size={300}>服务运行时不能修改入口配置。</Text><Button appearance="secondary" onClick={onStop} disabled={runtimeBusy}>{runtimeBusy ? "处理中…" : "停止服务"}</Button></div>}
    <div className="settings-fields">
      <SettingSection title="入口" description="Mixed 是本机代理入口；局域网网关是额外入口，二者可以同时运行。">
        <SettingRow label="本机 Mixed 代理" description="始终保留本地 HTTP / SOCKS5 入口；网关开启后也不会关闭。" control={<Switch checked disabled label={`启用 · ${settings.listen}:${settings.port}`} />} />
        <SettingRow label="局域网网关" description="使用 vfkit 启动极简 Linux guest；启动后用 LAN/TUN 包计数确认实体流量，客户端需手工配置网关和 DNS。" control={<Switch disabled={disabled} checked={gatewayMode} onChange={(event) => changeGateway(event.target.checked)} label={gatewayMode ? "已选择 · 待配置" : "未启用"} />} />
      </SettingSection>
      {gatewayMode && <SettingSection title="局域网网关接入（vfkit）" description="只需填写三个必填项，其余留空即可使用内置默认值。">
        <SettingRow label="物理网卡" description="承载局域网的 macOS 接口名称，例如 en0；不是 host-only 虚拟地址。" control={<Input disabled={disabled} value={settings.gatewayLanInterface} onChange={(event) => update({ gatewayLanInterface: event.target.value })} placeholder="例如 en0" />} />
        <SettingRow label="局域网网关 IP" description="客户端要填写的默认网关地址；必须在物理局域网内，且不能与现有设备冲突。" control={<Input disabled={disabled} value={settings.gatewayIp} onChange={(event) => update({ gatewayIp: event.target.value })} placeholder="例如 192.168.1.2" />} />
        <SettingRow label="上游网关" description="物理 LAN 当前的真实上游路由器地址；必须与局域网网关 IP 位于同一网段且不能相同。" control={<Input disabled={disabled} value={settings.gatewayUpstreamGateway} onChange={(event) => update({ gatewayUpstreamGateway: event.target.value })} placeholder="例如 192.168.1.1" />} />
        <SettingRow label="客户端接入策略" description="当前只支持动态学习局域网设备的 IP/MAC；指定设备策略尚未接入 Linux guest。" control={<Select disabled={disabled} value={settings.gatewayClientPolicy} onChange={(event) => update({ gatewayClientPolicy: event.target.value as RuntimeSettings["gatewayClientPolicy"] })}><option value="all">允许局域网所有设备</option><option value="allowlist" disabled>仅允许指定设备（尚未实现）</option></Select>} />
        {settings.gatewayClientPolicy === "allowlist" && <SettingRow label="指定客户端" description="每行一个 IP,MAC；只允许这些设备通过网关，例如 192.168.1.20,aa:bb:cc:dd:ee:ff。" control={<Textarea disabled={disabled} value={settings.gatewayClients} onChange={(event) => update({ gatewayClients: event.target.value })} rows={4} placeholder="192.168.1.20,aa:bb:cc:dd:ee:ff\n192.168.1.21,11:22:33:44:55:66" />} />}
        <SettingRow label="代理策略同步" description="共享：代理节点、策略组、路由规则和规则集由 Host 同步到 Gateway。分开：Gateway 使用独立策略文件，Host 修改不会覆盖它。" control={<Select disabled={disabled} value={settings.gatewayPolicyMode} onChange={(event) => update({ gatewayPolicyMode: event.target.value as RuntimeSettings["gatewayPolicyMode"] })}><option value="shared">共享策略 · Host 同步到 Gateway</option><option value="separate">Host / Gateway 分开配置</option></Select>} />
        <details className="setting-advanced-section">
          <summary><ChevronDownRegular className="setting-advanced-chevron" /><span>高级 · 虚拟机与数据面</span></summary>
          <div className="setting-advanced-body">
            <SettingRow label="局域网网段" description="根据所选物理网卡自动读取 IPv4 地址和掩码，不需要重复填写；网关 IP 必须是该网段内未占用的地址。" control={<Input disabled value={settings.gatewayCidr || "启动时自动检测"} />} />
            <SettingRow label="FakeIP DNS" description="客户端 DNS 固定为 198.18.0.2；不启动 DHCP，由你手工填写到每台客户端。" control={<Input disabled value="198.18.0.2" />} />
            <SettingRow label="vfkit 可执行文件" description="留空优先使用应用内的 arm64 vfkit；也可填写绝对路径覆盖内置版本。" control={<Input disabled={disabled} value={settings.vfkitPath} onChange={(event) => update({ vfkitPath: event.target.value })} placeholder="留空：使用应用内 vfkit" />} />
            <SettingRow label="Linux kernel" description="留空使用应用内随程序打包的 arm64 Linux kernel；填写路径可覆盖内置版本。" control={<Input disabled={disabled} value={settings.gatewayGuestKernelPath} onChange={(event) => update({ gatewayGuestKernelPath: event.target.value })} placeholder="留空：使用应用内 kernel" />} />
            <SettingRow label="Linux initrd" description="留空使用应用内包含 sing-box 与 gateway-agent 的极简 initrd；填写路径可覆盖内置版本。" control={<Input disabled={disabled} value={settings.gatewayGuestInitrdPath} onChange={(event) => update({ gatewayGuestInitrdPath: event.target.value })} placeholder="留空：使用应用内 initrd" />} />
            <SettingRow label="guest kernel cmdline" description="会追加 LAN/host-only 网络参数；不要填写 songsterx.* 保留参数或换行。" control={<Input disabled={disabled} value={settings.gatewayGuestCmdline} onChange={(event) => update({ gatewayGuestCmdline: event.target.value })} />} />
            <SettingRow label="vmnet-helper 可执行文件" description="留空使用应用内版本；旧版 macOS 仍需按 helper 文档配置权限。" control={<Input disabled={disabled} value={settings.vmnetHelperPath} onChange={(event) => update({ vmnetHelperPath: event.target.value })} placeholder="留空：使用应用内 vmnet-helper" />} />
            <SettingRow label="guest CPU / 内存" description="轻量默认 1 vCPU / 512 MiB；限制范围为 1-8 vCPU、256-16384 MiB。" control={<div className="setting-inline-controls"><Input disabled={disabled} type="number" min={1} max={8} value={String(settings.gatewayGuestCpus)} onChange={(event) => update({ gatewayGuestCpus: Number(event.target.value) })} /><Input disabled={disabled} type="number" min={256} max={16384} value={String(settings.gatewayGuestMemoryMib)} onChange={(event) => update({ gatewayGuestMemoryMib: Number(event.target.value) })} /></div>} />
            <SettingRow label="host-only 网段" description="第二张 virtio-net 只连接 macOS host 与 guest，用于 MITM/agent；默认 192.168.250.0/24。" control={<Input disabled={disabled} value={settings.gatewayHostCidr} onChange={(event) => update({ gatewayHostCidr: event.target.value })} />} />
            <SettingRow label="host / guest host-only IP" description="host IP 只绑定 host-only 网络，guest IP 由极简系统静态配置；不要填物理 LAN 地址。" control={<div className="setting-inline-controls"><Input disabled={disabled} value={settings.gatewayHostIp} onChange={(event) => update({ gatewayHostIp: event.target.value })} /><Input disabled={disabled} value={settings.gatewayGuestHostIp} onChange={(event) => update({ gatewayGuestHostIp: event.target.value })} /></div>} />
            <SettingRow label="guest LAN 网卡 selector" description="默认使用第一张 virtio-net（if:eth0）；只有需要按 MAC 或自定义接口名绑定时才修改。" control={<Input disabled={disabled} value={settings.gatewayGuestLanSelector} onChange={(event) => update({ gatewayGuestLanSelector: event.target.value })} placeholder="默认 if:eth0" />} />
            <SettingRow label="guest host-only selector" description="默认使用第二张 virtio-net（if:eth1）；只有需要按 MAC 或自定义接口名绑定时才修改，不能与 LAN selector 相同。" control={<Input disabled={disabled} value={settings.gatewayGuestHostSelector} onChange={(event) => update({ gatewayGuestHostSelector: event.target.value })} placeholder="默认 if:eth1" />} />
            <SettingRow label="guest agent 端口" description="用于下发配置、升级和 readiness；默认读取应用内 token，也可通过 SONGSTERX_GATEWAY_AGENT_TOKEN 或 *_TOKEN_FILE 覆盖。" control={<Input disabled={disabled} type="number" min={1} max={65535} value={String(settings.gatewayGuestAgentPort)} onChange={(event) => update({ gatewayGuestAgentPort: Number(event.target.value) })} />} />
            <SettingRow label="始终独立的项目" description="Host Mixed 地址/端口、host sing-box 路径与日志；Guest 的 vfkit、kernel、initrd、LAN/TUN、VM 参数和 guest-agent。" control={<Input disabled value="运行参数不共享" />} />
          </div>
        </details>
      </SettingSection>}
        <SettingSection title="监听" description={gatewayMode ? "本地 Mixed 入口仍可供本机应用或模块链路使用；Gateway 启动时连接物理网卡数据面并检查 guest readiness。" : "本地 Mixed 代理入口的基本参数。"}>
        <SettingRow label="监听地址" description="使用 127.0.0.1 仅允许本机访问。" control={<Input disabled={disabled} value={settings.listen} onChange={(event) => update({ listen: event.target.value })} />} />
        <SettingRow label="监听端口" description="修改后需要停止并重新启动服务。" control={<Input disabled={disabled} type="number" min={1} max={65535} value={String(settings.port)} onChange={(event) => update({ port: Number(event.target.value) })} />} />
      </SettingSection>
      <SettingSection title="DNS" description={gatewayMode ? "局域网客户端使用 FakeIP；手工把 198.18.0.2 设为 DNS，sing-box 负责恢复真实域名。" : "不劫持系统 DNS，只影响 sing-box 运行时配置。"}>
        <SettingRow label="解析模式" description={settings.dnsMode === "fakeip" ? "A/AAAA 查询返回 198.18.0.0/15 或 fc00::/18 的映射地址；网关连接会先恢复真实域名。" : "默认跟随系统 DNS。"} control={<Select disabled={disabled} value={settings.dnsMode} onChange={(event) => update({ dnsMode: event.target.value as RuntimeSettings["dnsMode"] })}><option value="system">系统 DNS</option><option value="custom">自定义 UDP DNS</option>{gatewayMode && <option value="fakeip">FakeIP（网关）</option>}</Select>} />
        {settings.dnsMode === "custom" && <SettingRow label="DNS 服务器" description="填写 IPv4、IPv6 或 DNS 地址。" control={<Input disabled={disabled} value={settings.dnsServer} onChange={(event) => update({ dnsServer: event.target.value })} />} />}
      </SettingSection>
      <SettingSection title="运行时" description="sing-box 进程和日志行为。">
        <SettingRow label="sing-box 可执行文件" description="留空时从当前 PATH 查找。" control={<Input disabled={disabled} value={settings.singBoxPath} onChange={(event) => update({ singBoxPath: event.target.value })} placeholder="留空：使用 PATH" />} />
        <SettingRow label="日志等级" description="下次启动 sing-box 时生效。" control={<Select disabled={disabled} value={settings.logLevel} onChange={(event) => update({ logLevel: event.target.value as RuntimeSettings["logLevel"] })}>{["trace", "debug", "info", "warn", "error"].map((level) => <option key={level} value={level}>{level}</option>)}</Select>} />
      </SettingSection>
    </div>
    <Divider />
    <div className="settings-footer">{settingsDirty && <Badge appearance="tint" color="warning">有未应用更改</Badge>}<Text className={`save-message ${message.startsWith("设置") || message.startsWith("已恢复") ? "" : "error"}`} size={200}>{message}</Text><Button appearance="secondary" disabled={disabled} onClick={onReset}>恢复默认</Button><Button appearance="primary" disabled={disabled || !settingsDirty} onClick={onSave}>{busy ? "保存中…" : "应用更改"}</Button></div>
  </Card>;
}

function SurgeSettingRow({ title, description, value, onClick }: { title: string; description: string; value: string; onClick: () => void }) {
  return <div className="surge-setting-row" role="button" tabIndex={0} onClick={onClick} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onClick(); } }}><div className="surge-setting-copy"><Text weight="semibold">{title}</Text><Text size={200}>{description}</Text></div><div className="surge-setting-value"><Text size={200}>{value}</Text><ChevronRightRegular /></div></div>;
}

function AppearanceSettingRow({ mode, onChange }: { mode: AppearanceMode; onChange: (mode: AppearanceMode) => void }) {
  return <div className="surge-setting-row appearance-setting-row"><div className="surge-setting-copy"><Text weight="semibold">外观</Text><Text size={200}>立即切换应用主题，并在下次启动时保留选择。</Text></div><div className="appearance-setting-control"><Select value={mode} aria-label="外观模式" onChange={(event) => onChange(event.target.value as AppearanceMode)}><option value="system">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></Select></div></div>;
}

function ConfigViewer({ documents, error, onRefresh, onReload }: { documents: ConfigDocument[]; error: string; onRefresh: () => Promise<void>; onReload: () => Promise<void> }) {
  const [selectedId, setSelectedId] = useState("songsterx-config");
  const [copied, setCopied] = useState(false);
  const selected = documents.find((document) => document.id === selectedId) ?? documents[0];
  const documentDescription = (document: ConfigDocument) => {
    if (document.id === "songsterx-config") return "唯一用户配置源";
    if (document.id === "sing-box-runtime") return "macOS host · Mixed 本机入口";
    if (document.id === "sing-box-gateway-guest") return "Linux guest · LAN TUN 数据面";
    return "自动生成的运行时输入";
  };
  const copy = async () => {
    if (!selected) return;
    await navigator.clipboard.writeText(selected.content);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };
  return <Card className="panel config-viewer"><div className="config-viewer-header"><div><Text as="h2" size={400} weight="semibold">配置来源</Text><Text size={300}>SongsterX.conf 保存 Host 策略；Gateway 模式会分别显示 host 和 Linux guest 两份 sing-box JSON。Guest 策略按设置选择共享或独立。</Text></div><div className="config-viewer-actions"><Button appearance="subtle" onClick={() => void onRefresh()}>刷新</Button><Button appearance="secondary" onClick={() => void onReload()}>从文件重载</Button><Button appearance="secondary" disabled={!selected} onClick={() => void copy()}>{copied ? "已复制" : "复制"}</Button></div></div>{documents.length === 0 ? <EmptyState title={error ? "配置加载失败" : "暂无配置"} description={error || "配置文件尚未生成，点击刷新后会自动创建。"} /> : <div className="config-viewer-body"><nav className="config-viewer-nav" aria-label="配置文档">{documents.map((document) => <button type="button" key={document.id} className={`config-viewer-nav-item ${document.id === selected?.id ? "is-selected" : ""}`} aria-current={document.id === selected?.id ? "page" : undefined} aria-controls="config-viewer-content" onClick={() => setSelectedId(document.id)}><span className="config-viewer-nav-mark" /><span className="config-viewer-nav-copy"><Text weight="semibold">{document.title}</Text><Text size={200}>{documentDescription(document)}</Text></span></button>)}</nav>{selected && <div id="config-viewer-content" className="config-viewer-main"><Text className="config-document-path" size={200}>{selected.path}</Text><pre>{selected.content}</pre></div>}</div>}</Card>;
}

function ModuleArgumentsDialog({ module, onSave, onClose }: { module: ModuleInfo; onSave: (id: string, key: string, value: string) => Promise<void>; onClose: () => void }) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(module.arguments.map((argument) => [argument.name, argument.value])));
  const [saving, setSaving] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const save = async () => {
    setSaving(true);
    setErrorMessage("");
    try {
      for (const argument of module.arguments) {
        const nextValue = values[argument.name] ?? "";
        if (nextValue !== argument.value) await onSave(module.id, argument.name, nextValue);
      }
      onClose();
    } catch (error) {
      setErrorMessage(String(error));
    } finally {
      setSaving(false);
    }
  };
  return <div className="modal-backdrop" onClick={onClose}>
    <div className="modal-surface module-dialog" onClick={(event) => event.stopPropagation()}>
      <div className="modal-header"><div><Text as="h2" weight="semibold">{module.arguments.length > 0 ? "配置模块" : "模块详情"}</Text><Text size={200}>{module.name} · {module.id}</Text></div><Button appearance="subtle" onClick={onClose}>关闭</Button></div>
      <div className="modal-body"><div className="module-dialog-summary"><Text size={300}>{module.description || "查看模块运行信息和可编辑参数。"}</Text><Text size={200}>{module.arguments.length} 个参数 · {module.scriptCount} 个脚本 · {module.mitmHostnames.length} 个 MITM 主机 · {module.runtimeStatus}</Text></div>{module.arguments.length === 0 ? <EmptyState title="没有可编辑参数" description="该模块通过静态规则或脚本直接运行。" /> : <div className="module-dialog-fields">{module.arguments.map((argument) => <div className="module-argument-field" key={argument.name}><Field label={argument.name} hint={`默认值：${argument.defaultValue}`}><Input value={values[argument.name] ?? ""} onChange={(event) => setValues((current) => ({ ...current, [argument.name]: event.target.value }))} /></Field>{argument.description && <Text className="module-argument-description" size={200}>{argument.description}</Text>}</div>)}</div>}{errorMessage && <Text className="module-dialog-error" size={200}>{errorMessage}</Text>}</div>
      <div className="modal-footer"><Button appearance="secondary" disabled={saving} onClick={onClose}>取消</Button>{module.arguments.length > 0 && <Button appearance="primary" disabled={saving} onClick={() => void save()}>{saving ? "保存中…" : "保存参数"}</Button>}</div>
    </div>
  </div>;
}

function ModuleUrlImportDialog({ onImport, onClose }: { onImport: (url: string) => Promise<void>; onClose: () => void }) {
  const [url, setUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const submit = async () => {
    if (!url.trim()) {
      setErrorMessage("请输入模块 URL");
      return;
    }
    setSaving(true);
    setErrorMessage("");
    try {
      await onImport(url.trim());
      onClose();
    } catch (error) {
      setErrorMessage(String(error));
    } finally {
      setSaving(false);
    }
  };
  return <div className="modal-backdrop" onClick={onClose}>
    <div className="modal-surface module-dialog" onClick={(event) => event.stopPropagation()}>
      <div className="modal-header"><div><Text as="h2" weight="semibold">从 URL 导入模块</Text><Text size={200}>导入时下载模块及其远程脚本、规则集和 Map Local 数据</Text></div><Button appearance="subtle" onClick={onClose}>关闭</Button></div>
      <div className="modal-body"><div className="module-dialog-fields"><Field label="模块 URL" hint="仅支持 http:// 或 https://；依赖会在导入阶段下载并固定哈希。"><Input autoFocus value={url} placeholder="https://example.com/example.sgmodule" onChange={(event) => setUrl(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void submit(); }} /></Field></div>{errorMessage && <Text className="module-dialog-error" size={200}>{errorMessage}</Text>}</div>
      <div className="modal-footer"><Button appearance="secondary" disabled={saving} onClick={onClose}>取消</Button><Button appearance="primary" disabled={saving} onClick={() => void submit()}>{saving ? "下载中…" : "下载并导入"}</Button></div>
    </div>
  </div>;
}

function ConnectionPage({ settings, running, runtimeBusy, busy, message, metrics, onChange, onSave, onReset, onStop }: { settings: RuntimeSettings; running: boolean; runtimeBusy: boolean; busy: boolean; message: string; metrics: RuntimeMetrics; onChange: (next: RuntimeSettings) => void; onSave: () => void; onReset: () => void; onStop: () => void }) {
  const [tab, setTab] = useState("live");
  const update = (patch: Partial<RuntimeSettings>) => onChange({ ...settings, ...patch });
  const disabled = running || busy;
  return <div className="page-content page-stack">
    <Card className="panel settings-panel">
      {running && <div className="settings-notice"><span className="status-dot running-dot" /><Text size={300}>服务运行时不能修改运行配置。</Text><Button appearance="secondary" onClick={onStop} disabled={runtimeBusy}>{runtimeBusy ? "处理中…" : "停止服务"}</Button></div>}
      <div className="page-intent-note"><Text weight="semibold">这里管理代理接入</Text><Text size={200}>“实时连接”只显示当前仍在传输的连接；请求历史和短请求请前往“活动”。</Text></div>
      <TabList selectedValue={tab} onTabSelect={(_, data) => setTab(String(data.value))} className="settings-tabs">
        <Tab value="live">实时连接</Tab><Tab value="connection">入口设置</Tab><Tab value="remote">远程访问</Tab><Tab value="advanced">高级</Tab>
      </TabList>
      {tab === "live" && <LiveConnections metrics={metrics} running={running} />}
      {tab === "connection" && <div className="settings-fields">
        <SettingSection title="代理入口" description="本地 Mixed 代理入口的基本参数。">
          <SettingRow label="监听地址" description="使用 127.0.0.1 仅允许本机访问。" control={<Input disabled={disabled} value={settings.listen} onChange={(event) => update({ listen: event.target.value })} />} />
          <SettingRow label="监听端口" description="修改后需要停止并重新启动服务。" control={<Input disabled={disabled} type="number" min={1} max={65535} value={String(settings.port)} onChange={(event) => update({ port: Number(event.target.value) })} />} />
        </SettingSection>
        <SettingSection title="DNS" description="不劫持系统 DNS，只影响 sing-box 运行时配置。">
          <SettingRow label="解析模式" description="默认跟随系统 DNS。" control={<Select disabled={disabled} value={settings.dnsMode} onChange={(event) => update({ dnsMode: event.target.value as RuntimeSettings["dnsMode"] })}><option value="system">系统 DNS</option><option value="custom">自定义 UDP DNS</option></Select>} />
          {settings.dnsMode === "custom" && <SettingRow label="DNS 服务器" description="填写 IPv4、IPv6 或 DNS 地址。" control={<Input disabled={disabled} value={settings.dnsServer} onChange={(event) => update({ dnsServer: event.target.value })} />} />}
        </SettingSection>
        <SettingSection title="运行时" description="sing-box 进程和日志行为。">
          <SettingRow label="sing-box 可执行文件" description="留空时从当前 PATH 查找。" control={<Input disabled={disabled} value={settings.singBoxPath} onChange={(event) => update({ singBoxPath: event.target.value })} placeholder="留空：使用 PATH" />} />
          <SettingRow label="日志等级" description="下次启动 sing-box 时生效。" control={<Select disabled={disabled} value={settings.logLevel} onChange={(event) => update({ logLevel: event.target.value as RuntimeSettings["logLevel"] })}>{["trace", "debug", "info", "warn", "error"].map((level) => <option key={level} value={level}>{level}</option>)}</Select>} />
        </SettingSection>
      </div>}
      {tab === "remote" && <FeatureUnavailable title="远程访问尚未接入" description="远程访问和局域网控制需要网关模式接入后开放。" compact />}
      {tab === "advanced" && <FeatureUnavailable title="高级配置尚未接入" description="高级配置编辑器将在规则引擎和模块系统稳定后开放。" compact />}
      <Divider />
      <div className="settings-footer"><Text className={`save-message ${message.startsWith("设置") || message.startsWith("已恢复") ? "" : "error"}`} size={200}>{message}</Text><Button appearance="secondary" disabled={disabled} onClick={onReset}>恢复默认</Button><Button appearance="primary" disabled={disabled} onClick={onSave}>{busy ? "保存中…" : "应用更改"}</Button></div>
    </Card>
  </div>;
}

function LiveConnections({ metrics, running }: { metrics: RuntimeMetrics; running: boolean }) {
  if (!running) {
    return <div className="settings-fields"><FeatureUnavailable title="服务未运行" description="启动服务后，这里只显示当前仍在传输的连接；请求历史请查看“活动”。" compact /></div>;
  }
  const connections = metrics.connections;
  return <div className="settings-fields"><div className="live-summary"><div className="live-stat"><Text className="stat-label" size={200}>当前连接</Text><Text className="stat-value" weight="semibold">{metrics.activeConnections}</Text></div><div className="live-stat"><Text className="stat-label" size={200}>下行</Text><Text className="stat-value mono-value" weight="semibold">{formatBytes(metrics.downloadTotal)}</Text></div><div className="live-stat"><Text className="stat-label" size={200}>上行</Text><Text className="stat-value mono-value" weight="semibold">{formatBytes(metrics.uploadTotal)}</Text></div><div className="live-stat"><Text className="stat-label" size={200}>内存</Text><Text className="stat-value mono-value" weight="semibold">{formatBytes(metrics.memory)}</Text></div></div>{connections.length === 0 ? <EmptyState title="暂无当前连接" description="通过代理访问网络后，当前仍在传输的连接会显示在这里；已完成请求请查看“活动”。" /> : <Table size="small" className="data-table"><TableHeader><TableRow><TableHeaderCell>来源</TableHeaderCell><TableHeaderCell>目标</TableHeaderCell><TableHeaderCell>主机</TableHeaderCell><TableHeaderCell>网络</TableHeaderCell><TableHeaderCell>出站</TableHeaderCell><TableHeaderCell>下行</TableHeaderCell><TableHeaderCell>上行</TableHeaderCell></TableRow></TableHeader><TableBody>{connections.map((conn) => <TableRow key={conn.id}><TableCell>{connectionRuntimeLabel(conn.runtime)}</TableCell><TableCell className="mono-cell">{conn.destination}</TableCell><TableCell>{conn.host || "—"}</TableCell><TableCell>{conn.network}</TableCell><TableCell>{conn.outbound || "—"}</TableCell><TableCell className="mono-cell">{formatBytes(conn.download)}</TableCell><TableCell className="mono-cell">{formatBytes(conn.upload)}</TableCell></TableRow>)}</TableBody></Table>}</div>;
}

function SettingSection({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return <section className="setting-section"><div className="setting-section-heading"><Text as="h2" size={400} weight="semibold">{title}</Text><Text size={200}>{description}</Text></div>{children}</section>;
}

function SettingRow({ label, description, control }: { label: string; description: string; control: ReactNode }) {
  return <Field className="setting-row" label={label} hint={description}>{control}</Field>;
}

function FeatureIcon({ icon }: { icon: ReactElement }) {
  return <span className="feature-icon">{icon}</span>;
}

function FeatureUnavailable({ title, description, compact = false }: { title: string; description: string; compact?: boolean }) {
  return <div className={`feature-unavailable ${compact ? "compact" : ""}`}><span className="empty-icon"><CircleRegular /></span><Text as="h2" size={500} weight="semibold">{title}</Text><Text size={300}>{description}</Text><Badge appearance="outline" color="subtle">未接入</Badge></div>;
}

function EmptyState({ title, description }: { title: string; description: string }) {
  return <div className="empty-state"><Text weight="semibold">{title}</Text><Text size={200}>{description}</Text></div>;
}

export default App;
