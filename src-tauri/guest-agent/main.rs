mod boot_config;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const COPY_BUFFER_SIZE: usize = 64 * 1024;
const MAX_REQUEST_LINE: usize = 64 * 1024;
const MAX_CONFIG_SIZE: u64 = 16 * 1024 * 1024;
const MAX_MODULE_PLAN_SIZE: u64 = 16 * 1024 * 1024;
const MAX_UPGRADE_SIZE: u64 = 64 * 1024 * 1024;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const SING_BOX_STARTUP_GRACE: Duration = Duration::from_millis(200);
const SESSION_READY_TIMEOUT: Duration = Duration::from_secs(14);
const GUEST_CLASH_API_ADDR: &str = "127.0.0.1:9090";
const CLASH_HTTP_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
const AGENT_CONNECTIONS_RESPONSE_LIMIT: usize = 60 * 1024;
const MAX_CONNECTIONS: usize = 256;

#[derive(Clone, Debug)]
struct AgentConfig {
    listen: String,
    state_dir: PathBuf,
    agent_version: String,
    sing_box_config: Option<PathBuf>,
    auth_token_file: PathBuf,
    auth_token: String,
    readiness_file: PathBuf,
    network_ready_file: Option<PathBuf>,
    network_control: Option<PathBuf>,
    guest_network: Option<boot_config::ResolvedGuestNetwork>,
}

struct ManagedSingBox {
    version: String,
    child: Child,
}

struct ManagedMitm {
    child: Child,
}

struct PendingSession {
    config_sha256: String,
    module_plan_sha256: String,
    previous_config: Option<Vec<u8>>,
    previous_plan: Option<Vec<u8>>,
    active_version: String,
    deadline: Instant,
}

#[derive(Default)]
struct AgentRuntime {
    sing_box: Option<ManagedSingBox>,
    mitm: Option<ManagedMitm>,
    pending_session: Option<PendingSession>,
    last_error: Option<String>,
    control_listening: bool,
    liveness_fault: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InterfaceStats {
    interface: String,
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PacketStats {
    lan: Option<InterfaceStats>,
    tun: Option<InterfaceStats>,
}

#[derive(Debug, Deserialize)]
struct Request {
    method: String,
    #[serde(default)]
    auth: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    sha256: String,
    #[serde(default, alias = "configSize")]
    config_size: u64,
    #[serde(default, alias = "configSha256")]
    config_sha256: String,
    #[serde(default, alias = "modulePlanSize")]
    module_plan_size: u64,
    #[serde(default, alias = "modulePlanSha256")]
    module_plan_sha256: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default, alias = "timeoutMs")]
    timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StagedArtifact {
    version: String,
    architecture: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StagedConfig {
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StagedModulePlan {
    size: u64,
    sha256: String,
}

impl AgentRuntime {
    fn refresh(&mut self, readiness_file: &Path) {
        let result = self
            .sing_box
            .as_mut()
            .map(|process| (process.version.clone(), process.child.try_wait()));
        match result {
            Some((version, Ok(Some(status)))) => {
                self.sing_box = None;
                remove_readiness_path(readiness_file);
                self.last_error = Some(format!(
                    "sing-box {version} 已退出，状态码 {:?}",
                    status.code()
                ));
            }
            Some((version, Err(error))) => {
                remove_readiness_path(readiness_file);
                self.liveness_fault = true;
                self.last_error = Some(format!("无法检查 sing-box {version} 状态：{error}"));
            }
            _ => {}
        }
    }

    fn refresh_mitm(&mut self, plan_path: &Path) {
        let result = self.mitm.as_mut().map(|process| process.child.try_wait());
        match result {
            Some(Ok(Some(status))) => {
                self.mitm = None;
                self.last_error = Some(format!("mitmdump 已退出，状态码 {:?}", status.code()));
                if module_plan_requires_mitm(plan_path) {
                    self.last_error = Some(format!(
                        "mitmdump 已退出，状态码 {:?}；模块 MITM 仍需要运行",
                        status.code()
                    ));
                }
            }
            Some(Err(error)) => {
                self.liveness_fault = true;
                self.last_error = Some(format!("无法检查 mitmdump 状态：{error}"));
            }
            _ => {}
        }
    }

    fn is_healthy(&mut self, version: &str, readiness_file: &Path) -> bool {
        self.refresh(readiness_file);
        self.sing_box
            .as_ref()
            .map(|process| process.version == version)
            .unwrap_or(false)
    }

    fn pid(&self) -> Option<u32> {
        self.sing_box.as_ref().map(|process| process.child.id())
    }

    fn mitm_pid(&self) -> Option<u32> {
        self.mitm.as_ref().map(|process| process.child.id())
    }

    fn mitm_healthy(&self) -> bool {
        self.mitm.is_some()
    }

    fn sing_box_ready(&self) -> bool {
        !self.liveness_fault && self.sing_box.is_some() && clash_api_ready()
    }

    fn mitm_ready(&self) -> bool {
        !self.liveness_fault && self.mitm.is_some() && tcp_listener_ready("127.0.0.1:8080")
    }

    fn stop_mitm(&mut self) -> Result<(), String> {
        if self.mitm.is_none() {
            return Ok(());
        }
        let result = self
            .mitm
            .as_mut()
            .map(|process| stop_child(&mut process.child, "mitmdump"))
            .expect("mitmdump exists");
        if result.is_ok() {
            self.mitm = None;
        } else {
            self.liveness_fault = true;
        }
        result
    }

    fn stop(&mut self, readiness_file: &Path) -> Result<(), String> {
        let mut failures = Vec::new();
        if self.mitm.is_some() {
            let result = self
                .mitm
                .as_mut()
                .map(|process| stop_child(&mut process.child, "mitmdump"))
                .expect("mitmdump exists");
            if let Err(error) = result {
                failures.push(error);
            } else {
                self.mitm = None;
            }
        }
        if self.sing_box.is_some() {
            let result = self
                .sing_box
                .as_mut()
                .map(|process| stop_child(&mut process.child, "sing-box"))
                .expect("sing-box exists");
            if let Err(error) = result {
                failures.push(error);
            } else {
                self.sing_box = None;
            }
        }
        remove_readiness_path(readiness_file);
        if failures.is_empty() {
            self.liveness_fault = false;
            Ok(())
        } else {
            self.liveness_fault = true;
            Err(failures.join("；"))
        }
    }
}

fn stop_child(child: &mut Child, label: &str) -> Result<(), String> {
    match child
        .try_wait()
        .map_err(|error| format!("检查 {label} 停止状态失败：{error}"))?
    {
        Some(_) => Ok(()),
        None => {
            child
                .kill()
                .map_err(|error| format!("停止 {label} 失败：{error}"))?;
            child
                .wait()
                .map_err(|error| format!("等待 {label} 停止失败：{error}"))?;
            Ok(())
        }
    }
}

fn tcp_listener_ready(address: &str) -> bool {
    let Ok(mut addresses) = address.to_socket_addrs() else {
        return false;
    };
    let Some(address) = addresses.next() else {
        return false;
    };
    TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
}

fn clash_api_ready() -> bool {
    let Ok(mut addresses) = GUEST_CLASH_API_ADDR.to_socket_addrs() else {
        return false;
    };
    let Some(address) = addresses.next() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_millis(100)))
            .is_err()
    {
        return false;
    }
    if stream
        .write_all(b"GET /proxies HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .and_then(|_| stream.flush())
        .is_err()
    {
        return false;
    }
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    if reader.read_line(&mut status_line).is_err() {
        return false;
    }
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .is_some_and(|status| (200..300).contains(&status))
}

fn main() {
    let config = parse_args(std::env::args().skip(1)).unwrap_or_else(|error| {
        eprintln!("gateway-agent: {error}");
        std::process::exit(2);
    });
    if let Err(error) = run(config) {
        eprintln!("gateway-agent: {error}");
        std::process::exit(1);
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<AgentConfig, String> {
    let mut listen = "0.0.0.0:38291".to_string();
    let mut state_dir = PathBuf::from("/var/lib/songsterx");
    let mut agent_version = "0.1.0".to_string();
    let mut sing_box_config = None;
    let mut auth_token_file = None;
    let mut readiness_file = None;
    let mut network_ready_file = None;
    let mut network_control = None;
    while let Some(argument) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{argument} 缺少参数"));
        match argument.as_str() {
            "--listen" => listen = value()?,
            "--state-dir" => state_dir = value()?.into(),
            "--agent-version" => agent_version = value()?,
            "--sing-box-config" => sing_box_config = Some(value()?.into()),
            "--auth-token-file" => auth_token_file = Some(value()?.into()),
            "--readiness-file" => readiness_file = Some(value()?.into()),
            "--network-ready-file" => network_ready_file = Some(value()?.into()),
            "--network-control" => network_control = Some(value()?.into()),
            "--help" | "-h" => {
                println!(
                    "用法：songsterx-gateway-agent [--listen IP:PORT] [--state-dir PATH] [--agent-version VERSION] [--sing-box-config PATH] [--auth-token-file PATH] [--readiness-file PATH] [--network-ready-file PATH] [--network-control PATH]"
                );
                std::process::exit(0);
            }
            _ => return Err(format!("未知参数：{argument}")),
        }
    }
    if listen.trim().is_empty() || agent_version.trim().is_empty() {
        return Err("listen 和 agent-version 不能为空".into());
    }
    let auth_token_file = auth_token_file.unwrap_or_else(|| state_dir.join("agent.token"));
    let readiness_file = readiness_file.unwrap_or_else(|| state_dir.join("ready"));
    if let Some(path) = network_ready_file.as_deref() {
        validate_absolute_runtime_path(path, "network-ready-file")?;
    }
    if let Some(path) = network_control.as_deref() {
        validate_absolute_runtime_path(path, "network-control")?;
    }
    Ok(AgentConfig {
        listen,
        state_dir,
        agent_version,
        sing_box_config,
        auth_token_file,
        auth_token: String::new(),
        readiness_file,
        network_ready_file,
        network_control,
        guest_network: None,
    })
}

fn run(mut config: AgentConfig) -> Result<(), String> {
    config.auth_token = read_auth_token(&config.auth_token_file)?;
    remove_readiness(&config);
    if config.network_ready_file.is_some() {
        if !guest_network_ready(&config) {
            return Err("guest network 尚未就绪，拒绝启动 guest-agent data plane".into());
        }
        config.guest_network = Some(load_guest_network()?);
    }
    fs::create_dir_all(versions_dir(&config.state_dir))
        .map_err(|error| format!("无法创建 guest agent 状态目录：{error}"))?;

    // Bind management before starting sing-box so readiness includes control-plane availability.
    let listener = TcpListener::bind(&config.listen)
        .map_err(|error| format!("无法监听 guest agent {}：{error}", config.listen))?;
    let mut runtime = AgentRuntime::default();
    runtime.control_listening = true;
    if let Err(error) = start_active(&config, &mut runtime) {
        runtime.last_error = Some(error.clone());
        eprintln!("gateway-agent: {error}");
    }
    eprintln!("gateway-agent listening on {}", config.listen);
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, &config, &mut runtime) {
                    eprintln!("gateway-agent request failed: {error}");
                }
            }
            Err(error) => eprintln!("gateway-agent accept failed: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(
    stream: TcpStream,
    config: &AgentConfig,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(REQUEST_READ_TIMEOUT))
        .map_err(|error| format!("设置请求读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(REQUEST_READ_TIMEOUT))
        .map_err(|error| format!("设置响应写入超时失败：{error}"))?;
    let mut reader = BufReader::new(stream);
    let line = read_request_line(&mut reader)?;
    if line.is_empty() {
        return Ok(());
    }
    let request: Request =
        serde_json::from_slice(&line).map_err(|error| format!("请求不是有效 JSON：{error}"))?;
    if request.auth != config.auth_token {
        return respond(&mut reader, error_response("guest agent 认证失败".into()));
    }
    match request.method.as_str() {
        "status" => respond(&mut reader, status_response(config, runtime)?),
        "connections" => respond(&mut reader, connections_response()?),
        "proxies" => respond(&mut reader, proxies_response()?),
        "select_proxy" => select_proxy(&mut reader, &request),
        "test_proxy_delay" => test_proxy_delay(&mut reader, &request),
        "stage_upgrade" => stage_upgrade(&mut reader, config, &request),
        "stage_config" => stage_config(&mut reader, config, &request),
        "stage_module_plan" => stage_module_plan(&mut reader, config, &request),
        "activate_upgrade" => activate_upgrade(&mut reader, config, &request, runtime),
        "activate_session" => activate_session(&mut reader, config, &request, runtime),
        "activate_config" | "activate_module_plan" => respond(
            &mut reader,
            error_response("Gateway 只允许通过 activate_session 同时激活配置和模块计划".into()),
        ),
        "rollback" => rollback(&mut reader, config, runtime),
        "stop_runtime" => stop_guest_runtime(&mut reader, config, runtime),
        method => respond(
            &mut reader,
            error_response(format!("不支持的 guest agent 方法：{method}")),
        ),
    }
}

fn connections_response() -> Result<Value, String> {
    let address = GUEST_CLASH_API_ADDR
        .to_socket_addrs()
        .map_err(|error| format!("无法解析 guest sing-box Clash API 地址：{error}"))?
        .next()
        .ok_or_else(|| "guest sing-box Clash API 地址没有可用解析结果".to_string())?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .map_err(|error| format!("无法连接 guest sing-box Clash API：{error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("无法设置 guest Clash API 读取超时：{error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("无法设置 guest Clash API 写入超时：{error}"))?;
    stream
        .write_all(b"GET /connections HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .map_err(|error| format!("请求 guest Clash API 失败：{error}"))?;
    stream
        .flush()
        .map_err(|error| format!("刷新 guest Clash API 请求失败：{error}"))?;

    let response = read_http_response(&mut stream)?;
    let metrics: Value = serde_json::from_slice(&response)
        .map_err(|error| format!("guest Clash API 返回不是有效 JSON：{error}"))?;
    compact_connections_response(metrics)
}

fn proxies_response() -> Result<Value, String> {
    let body = clash_http_request("GET", "/proxies", None)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|error| format!("guest Clash API 代理响应不是有效 JSON：{error}"))?;
    Ok(json!({
        "ok": true,
        "state": "ready",
        "metrics": value,
    }))
}

fn select_proxy(reader: &mut BufReader<TcpStream>, request: &Request) -> Result<(), String> {
    if request.group.trim().is_empty() || request.name.trim().is_empty() {
        return respond(reader, error_response("策略组和节点名称不能为空".into()));
    }
    let body = serde_json::to_vec(&json!({ "name": request.name.trim() }))
        .map_err(|error| format!("序列化 guest 策略切换请求失败：{error}"))?;
    let path = format!("/proxies/{}", percent_encode_segment(request.group.trim()));
    clash_http_request("PUT", &path, Some(&body))?;
    respond(reader, json!({ "ok": true, "state": "ready" }))
}

fn test_proxy_delay(reader: &mut BufReader<TcpStream>, request: &Request) -> Result<(), String> {
    if request.name.trim().is_empty() {
        return respond(reader, error_response("节点名称不能为空".into()));
    }
    let timeout_ms = request.timeout_ms.clamp(1_000, 60_000);
    let url = if request.url.trim().is_empty() {
        "http://www.gstatic.com/generate_204"
    } else {
        request.url.trim()
    };
    let path = format!(
        "/proxies/{}/delay?timeout={timeout_ms}&url={}",
        percent_encode_segment(request.name.trim()),
        percent_encode_segment(url),
    );
    let body = clash_http_request("GET", &path, None)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|error| format!("guest Clash API 延迟响应不是有效 JSON：{error}"))?;
    let delay = value["delay"]
        .as_u64()
        .ok_or_else(|| "guest Clash API 未返回有效 delay".to_string())?;
    respond(
        reader,
        json!({ "ok": true, "state": "ready", "delay": delay }),
    )
}

fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn clash_http_request(method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>, String> {
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err("guest Clash API 路径无效".into());
    }
    let address = GUEST_CLASH_API_ADDR
        .to_socket_addrs()
        .map_err(|error| format!("无法解析 guest sing-box Clash API 地址：{error}"))?
        .next()
        .ok_or_else(|| "guest sing-box Clash API 地址没有可用解析结果".to_string())?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .map_err(|error| format!("无法连接 guest sing-box Clash API：{error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("无法设置 guest Clash API 读取超时：{error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("无法设置 guest Clash API 写入超时：{error}"))?;
    let payload = body.unwrap_or_default();
    let header = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(payload))
        .map_err(|error| format!("请求 guest Clash API 失败：{error}"))?;
    stream
        .flush()
        .map_err(|error| format!("刷新 guest Clash API 请求失败：{error}"))?;
    read_http_response(&mut stream)
}

fn read_http_response(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("读取 guest Clash API 响应失败：{error}"))?;
        if read == 0 {
            break;
        }
        if response.len() + read > CLASH_HTTP_RESPONSE_LIMIT {
            return Err("guest Clash API 响应超过 2 MiB 限制".into());
        }
        response.extend_from_slice(&buffer[..read]);
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "guest Clash API 响应缺少 HTTP header 结束标记".to_string())?;
    let headers = &response[..header_end];
    let status_line = headers
        .split(|value| *value == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default()
        .trim_end_matches('\r');
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "guest Clash API 返回缺少 HTTP 状态码".to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!("guest Clash API 返回 HTTP {status}"));
    }
    let body = &response[header_end + 4..];
    let headers_lower = String::from_utf8_lossy(headers).to_ascii_lowercase();
    if headers_lower.contains("transfer-encoding: chunked") {
        decode_chunked_body(body)
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "guest Clash API chunked 响应缺少长度行".to_string())?;
        let size_text = std::str::from_utf8(&body[..line_end])
            .map_err(|error| format!("guest Clash API chunk 长度无效：{error}"))?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| format!("guest Clash API chunk 长度无效：{error}"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if size > body.len() || body.get(size..size + 2) != Some(b"\r\n") {
            return Err("guest Clash API chunk 内容不完整".into());
        }
        if decoded.len() + size > CLASH_HTTP_RESPONSE_LIMIT {
            return Err("guest Clash API 解码后响应超过 2 MiB 限制".into());
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

fn compact_connections_response(value: Value) -> Result<Value, String> {
    let source = value
        .as_object()
        .ok_or_else(|| "guest Clash API 响应必须是 JSON object".to_string())?;
    let source_connections = source
        .get("connections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let start = source_connections.len().saturating_sub(MAX_CONNECTIONS);
    let connections = source_connections[start..]
        .iter()
        .map(compact_connection)
        .collect::<Vec<_>>();
    let mut metrics = json!({
        "uploadTotal": source.get("uploadTotal").and_then(Value::as_u64).unwrap_or(0),
        "downloadTotal": source.get("downloadTotal").and_then(Value::as_u64).unwrap_or(0),
        "memory": source.get("memory").and_then(Value::as_u64).unwrap_or(0),
        "connections": connections,
    });
    loop {
        let envelope = json!({"ok": true, "state": "ready", "metrics": &metrics});
        let encoded = serde_json::to_vec(&envelope)
            .map_err(|error| format!("序列化 guest connections 响应失败：{error}"))?;
        if encoded.len() < AGENT_CONNECTIONS_RESPONSE_LIMIT {
            return Ok(envelope);
        }
        let items = metrics
            .get_mut("connections")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "guest connections 响应缺少 connections 数组".to_string())?;
        if items.is_empty() {
            return Err("guest connections 响应无法压缩到控制协议限制内".into());
        }
        items.remove(0);
    }
}

fn compact_connection(value: &Value) -> Value {
    let metadata = value.get("metadata").cloned().unwrap_or_else(|| json!({}));
    let chains = value
        .get("chains")
        .and_then(Value::as_array)
        .and_then(|items| items.last())
        .and_then(Value::as_str)
        .map(|chain| json!([chain]))
        .unwrap_or_else(|| json!([]));
    json!({
        "id": value.get("id").cloned().unwrap_or(Value::Null),
        "metadata": {
            "sourceIP": metadata.get("sourceIP").and_then(Value::as_str).unwrap_or(""),
            "sourcePort": metadata.get("sourcePort").and_then(Value::as_str).unwrap_or(""),
            "destinationIP": metadata.get("destinationIP").and_then(Value::as_str).unwrap_or(""),
            "destinationPort": metadata.get("destinationPort").and_then(Value::as_str).unwrap_or(""),
            "host": metadata.get("host").and_then(Value::as_str).unwrap_or(""),
            "network": metadata.get("network").and_then(Value::as_str).unwrap_or(""),
        },
        "chains": chains,
        "upload": value.get("upload").and_then(Value::as_u64).unwrap_or(0),
        "download": value.get("download").and_then(Value::as_u64).unwrap_or(0),
        "start": value.get("start").and_then(Value::as_str).unwrap_or(""),
    })
}

fn read_request_line(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, String> {
    let mut line = Vec::with_capacity(1024);
    loop {
        let mut byte = [0_u8; 1];
        let size = reader
            .read(&mut byte)
            .map_err(|error| format!("读取请求失败：{error}"))?;
        if size == 0 {
            return Ok(line);
        }
        line.push(byte[0]);
        if line.len() > MAX_REQUEST_LINE {
            return Err("请求超过 64 KiB 限制".into());
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
}

fn stop_guest_runtime(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    let mut failures = Vec::new();
    if let Err(error) = abort_pending_session_for_stop(config, runtime) {
        failures.push(error);
    }
    if let Err(error) = stop_network_forwarding(config) {
        failures.push(error);
    }
    if failures.is_empty() {
        runtime.last_error = None;
        respond(
            reader,
            json!({
                "ok": true,
                "state": "stopped",
                "healthy": false,
                "ready": false,
                "networkReady": guest_network_ready(config),
            }),
        )
    } else {
        let message = failures.join("；");
        runtime.last_error = Some(message.clone());
        respond(reader, error_response(message))
    }
}

fn stop_network_forwarding(config: &AgentConfig) -> Result<(), String> {
    let Some(control) = config.network_control.as_deref() else {
        return Ok(());
    };
    validate_absolute_runtime_path(control, "network-control")?;
    if !control.is_file() {
        return Err(format!(
            "guest network controller 不存在：{}",
            control.display()
        ));
    }
    let output = Command::new(control)
        .arg("stop-forwarding")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("执行 guest network forwarding cleanup 失败：{error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(512)
        .collect::<String>();
    if detail.is_empty() {
        Err(format!(
            "guest network forwarding cleanup 失败，状态码 {:?}",
            output.status.code()
        ))
    } else {
        Err(format!("guest network forwarding cleanup 失败：{detail}"))
    }
}

fn stage_upgrade(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    request: &Request,
) -> Result<(), String> {
    validate_artifact_request(request)?;
    let directory = version_dir(&config.state_dir, &request.version)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建版本目录：{error}"))?;
    let temporary = directory.join("sing-box.incoming");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("无法创建升级临时文件：{error}"))?;
    respond(reader, json!({"ok": true, "state": "ready_for_upload"}))?;

    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut remaining = request.size;
    while remaining > 0 {
        let wanted = usize::try_from(remaining)
            .unwrap_or(COPY_BUFFER_SIZE)
            .min(COPY_BUFFER_SIZE);
        let read = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| format!("读取升级文件失败：{error}"))?;
        if read == 0 {
            return Err("升级文件在达到声明大小前断开".into());
        }
        file.write_all(&buffer[..read])
            .map_err(|error| format!("写入升级文件失败：{error}"))?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    file.sync_all()
        .map_err(|error| format!("同步升级文件失败：{error}"))?;
    let actual_sha256 = format!("{:x}", digest.finalize());
    if actual_sha256 != request.sha256 {
        let _ = fs::remove_file(&temporary);
        return respond(reader, error_response("升级文件 SHA-256 校验失败".into()));
    }
    let artifact = directory.join("sing-box");
    fs::rename(&temporary, &artifact).map_err(|error| format!("提交升级文件失败：{error}"))?;
    set_executable(&artifact)?;
    write_staged(
        &config.state_dir,
        &StagedArtifact {
            version: request.version.clone(),
            architecture: request.architecture.clone(),
            size: request.size,
            sha256: actual_sha256,
        },
    )?;
    respond(reader, json!({"ok": true, "state": "staged"}))
}

fn stage_config(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    request: &Request,
) -> Result<(), String> {
    validate_config_request(request)?;
    let incoming = config_incoming_path(config);
    if let Some(parent) = incoming.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("无法创建 sing-box 配置目录：{error}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&incoming)
        .map_err(|error| format!("无法创建配置临时文件：{error}"))?;
    respond(reader, json!({"ok": true, "state": "ready_for_upload"}))?;

    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut remaining = request.config_size;
    while remaining > 0 {
        let wanted = usize::try_from(remaining)
            .unwrap_or(COPY_BUFFER_SIZE)
            .min(COPY_BUFFER_SIZE);
        let read = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| format!("读取 sing-box 配置失败：{error}"))?;
        if read == 0 {
            return Err("sing-box 配置在达到声明大小前断开".into());
        }
        file.write_all(&buffer[..read])
            .map_err(|error| format!("写入 sing-box 配置失败：{error}"))?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    file.sync_all()
        .map_err(|error| format!("同步 sing-box 配置失败：{error}"))?;
    let actual_sha256 = format!("{:x}", digest.finalize());
    if actual_sha256 != request.config_sha256 {
        let _ = fs::remove_file(&incoming);
        return respond(
            reader,
            error_response("sing-box 配置 SHA-256 校验失败".into()),
        );
    }
    write_staged_config(
        config,
        &StagedConfig {
            size: request.config_size,
            sha256: actual_sha256,
        },
    )?;
    respond(reader, json!({"ok": true, "state": "staged"}))
}

fn stage_module_plan(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    request: &Request,
) -> Result<(), String> {
    validate_module_plan_request(request)?;
    let incoming = module_plan_incoming_path(config);
    if let Some(parent) = incoming.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("无法创建模块运行计划目录：{error}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&incoming)
        .map_err(|error| format!("无法创建模块运行计划临时文件：{error}"))?;
    respond(reader, json!({"ok": true, "state": "ready_for_upload"}))?;

    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut remaining = request.module_plan_size;
    while remaining > 0 {
        let wanted = usize::try_from(remaining)
            .unwrap_or(COPY_BUFFER_SIZE)
            .min(COPY_BUFFER_SIZE);
        let read = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| format!("读取模块运行计划失败：{error}"))?;
        if read == 0 {
            return Err("模块运行计划在达到声明大小前断开".into());
        }
        file.write_all(&buffer[..read])
            .map_err(|error| format!("写入模块运行计划失败：{error}"))?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    file.sync_all()
        .map_err(|error| format!("同步模块运行计划失败：{error}"))?;
    let actual_sha256 = format!("{:x}", digest.finalize());
    if actual_sha256 != request.module_plan_sha256 {
        let _ = fs::remove_file(&incoming);
        return respond(
            reader,
            error_response("模块运行计划 SHA-256 校验失败".into()),
        );
    }
    write_staged_module_plan(
        config,
        &StagedModulePlan {
            size: request.module_plan_size,
            sha256: actual_sha256,
        },
    )?;
    respond(reader, json!({"ok": true, "state": "staged"}))
}

fn activate_upgrade(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    request: &Request,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    let staged =
        read_staged(&config.state_dir)?.ok_or_else(|| "没有可激活的 sing-box 版本".to_string())?;
    if staged.version != request.version || staged.sha256 != request.sha256 {
        return respond(
            reader,
            error_response("待激活版本与 staged 元数据不匹配".into()),
        );
    }
    let artifact = version_dir(&config.state_dir, &staged.version)?.join("sing-box");
    if !artifact.is_file() {
        return respond(reader, error_response("staged sing-box 文件不存在".into()));
    }

    let current = read_pointer(&active_path(&config.state_dir), "active")?;
    if let Err(error) = runtime.stop(&config.readiness_file) {
        return respond(
            reader,
            error_response(format!("停止当前 sing-box 失败：{error}")),
        );
    }
    if let Err(start_error) = start_version(config, runtime, &staged.version) {
        let recovery_message = match runtime.stop(&config.readiness_file) {
            Ok(()) => restart_version(config, runtime, current.as_deref())
                .err()
                .map(|error| format!("；旧版本恢复失败：{error}"))
                .unwrap_or_default(),
            Err(error) => format!("；候选 sing-box 停止失败，未重启旧版本：{error}"),
        };
        runtime.last_error = Some(format!("{start_error}{recovery_message}"));
        return respond(
            reader,
            error_response(format!(
                "sing-box 新版本启动失败：{start_error}{recovery_message}"
            )),
        );
    }

    if let Err(pointer_error) = write_pointer(&previous_path(&config.state_dir), current.as_deref())
        .and_then(|_| write_pointer(&active_path(&config.state_dir), Some(&staged.version)))
    {
        let recovery_message = match runtime.stop(&config.readiness_file) {
            Ok(()) => restart_version(config, runtime, current.as_deref())
                .err()
                .map(|error| format!("；旧版本恢复失败：{error}"))
                .unwrap_or_default(),
            Err(error) => format!("；候选 sing-box 停止失败，未重启旧版本：{error}"),
        };
        runtime.last_error = Some(format!("{pointer_error}{recovery_message}"));
        return respond(
            reader,
            error_response(format!(
                "提交 sing-box 版本指针失败：{pointer_error}{recovery_message}"
            )),
        );
    }

    respond(
        reader,
        json!({
            "ok": true,
            "state": "active",
            "version": staged.version,
            "healthy": true,
            "ready": runtime_ready(config, runtime),
            "networkReady": guest_network_ready(config),
            "pid": runtime.pid(),
        }),
    )
}

/// Atomically activate the sing-box configuration and Module Engine plan as
/// one data-plane session.  Both artifacts are validated before the current
/// runtime is stopped, and `start_version` then starts sing-box and mitmdump
/// exactly once from the final pair of files.
fn activate_session(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    request: &Request,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    // A lost response must be safe to reconcile. If the requested pair is
    // already active and operational, return success without requiring the
    // staged files or restarting either child.
    let current_config_matches =
        file_sha256(&sing_box_config_path(config)).ok() == Some(request.config_sha256.clone());
    let current_plan_matches =
        file_sha256(&module_plan_path(config)).ok() == Some(request.module_plan_sha256.clone());
    if current_config_matches && current_plan_matches && runtime_ready(config, runtime) {
        return respond(
            reader,
            json!({
                "ok": true,
                "state": "active",
                "configSha256": request.config_sha256,
                "modulePlanSha256": request.module_plan_sha256,
                "healthy": true,
                "ready": true,
                "networkReady": guest_network_ready(config),
                "packetStats": config.guest_network.as_ref().map(|network| PacketStats {
                    lan: read_interface_stats(&network.lan_interface),
                    tun: read_interface_stats("tun0"),
                }),
                "pid": runtime.pid(),
                "mitmHealthy": runtime.mitm_healthy(),
                "mitmReady": runtime.mitm_ready(),
                "mitmPid": runtime.mitm_pid(),
                "mitmCertificatePem": read_mitm_certificate(config),
            }),
        );
    }
    let staged_config =
        read_staged_config(config)?.ok_or_else(|| "没有可激活的 sing-box 配置".to_string())?;
    if staged_config.size != request.config_size || staged_config.sha256 != request.config_sha256 {
        return respond(
            reader,
            error_response("待激活配置与 staged 元数据不匹配".into()),
        );
    }
    let staged_module_plan =
        read_staged_module_plan(config)?.ok_or_else(|| "没有可激活的模块运行计划".to_string())?;
    if staged_module_plan.size != request.module_plan_size
        || staged_module_plan.sha256 != request.module_plan_sha256
    {
        return respond(
            reader,
            error_response("待激活模块运行计划与 staged 元数据不匹配".into()),
        );
    }

    let config_incoming = config_incoming_path(config);
    let plan_incoming = module_plan_incoming_path(config);
    if !config_incoming.is_file() {
        return respond(reader, error_response("staged sing-box 配置不存在".into()));
    }
    if !plan_incoming.is_file() {
        return respond(reader, error_response("staged 模块运行计划不存在".into()));
    }
    let candidate_config = fs::read(&config_incoming)
        .map_err(|error| format!("读取 staged sing-box 配置失败：{error}"))?;
    serde_json::from_slice::<Value>(&candidate_config)
        .map_err(|error| format!("staged sing-box 配置不是有效 JSON：{error}"))?;
    let candidate_plan = fs::read(&plan_incoming)
        .map_err(|error| format!("读取 staged 模块运行计划失败：{error}"))?;
    let candidate_plan_value: Value = serde_json::from_slice(&candidate_plan)
        .map_err(|error| format!("staged 模块运行计划不是有效 JSON：{error}"))?;

    let active = read_pointer(&active_path(&config.state_dir), "active")?
        .ok_or_else(|| "没有可运行的 sing-box 版本".to_string())?;
    let artifact = version_dir(&config.state_dir, &active)?.join("sing-box");
    if !artifact.is_file() {
        return respond(reader, error_response("active sing-box 文件不存在".into()));
    }
    check_sing_box(&artifact, &config_incoming)?;

    let config_path = sing_box_config_path(config);
    let plan_path = module_plan_path(config);
    let previous_config = read_optional_file(&config_path, "当前 sing-box 配置")?;
    let previous_plan = read_optional_file(&plan_path, "当前模块运行计划")?;
    if let Some(previous) = previous_config.as_deref() {
        write_atomic_bytes(&config_previous_path(config), previous)?;
    }

    if let Err(error) = runtime.stop(&config.readiness_file) {
        return respond(
            reader,
            error_response(format!("停止当前 Gateway data plane 失败：{error}")),
        );
    }

    let activation = (|| {
        write_atomic_bytes(&config_path, &candidate_config)?;
        write_atomic_bytes(&plan_path, &candidate_plan)?;
        start_version(config, runtime, &active)
    })();
    if let Err(start_error) = activation {
        let stop_error = runtime.stop(&config.readiness_file).err();
        let config_restore = restore_config(config, previous_config.as_deref());
        let plan_restore = restore_file(&plan_path, previous_plan.as_deref(), "模块运行计划");
        let config_verify =
            verify_restored_file(&config_path, previous_config.as_deref(), "sing-box 配置");
        let plan_verify =
            verify_restored_file(&plan_path, previous_plan.as_deref(), "模块运行计划");
        let rollback_error = [
            stop_error,
            config_restore.err(),
            plan_restore.err(),
            config_verify.err(),
            plan_verify.err(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if !rollback_error.is_empty() {
            let details = rollback_error.into_iter().collect::<Vec<_>>().join("；");
            let message = format!(
                "{start_error}；Gateway session 回滚失败，data plane 已保持停止：{details}"
            );
            runtime.last_error = Some(message.clone());
            return respond(reader, error_response(message));
        }
        let recovery = restart_version(config, runtime, Some(&active));
        let recovery_error = recovery.err().or_else(|| {
            (!runtime_ready(config, runtime)).then_some("旧 Gateway session 探针未就绪".into())
        });
        if let Some(error) = recovery_error {
            let stop_error = runtime.stop(&config.readiness_file).err();
            let details = stop_error
                .map(|stop_error| format!("；停止残留 data plane 失败：{stop_error}"))
                .unwrap_or_default();
            let message = format!("{start_error}；旧 Gateway session 恢复失败：{error}{details}");
            runtime.last_error = Some(message.clone());
            return respond(reader, error_response(message));
        }
        let message = format!("{start_error}；旧 Gateway session 已恢复");
        runtime.last_error = Some(message.clone());
        return respond(reader, error_response(message));
    }

    runtime.pending_session = Some(PendingSession {
        config_sha256: request.config_sha256.clone(),
        module_plan_sha256: request.module_plan_sha256.clone(),
        previous_config,
        previous_plan,
        active_version: active.clone(),
        deadline: Instant::now() + SESSION_READY_TIMEOUT,
    });
    progress_pending_session(config, runtime);
    let activating = runtime.pending_session.is_some();
    let mitm_certificate_pem = if module_plan_requires_mitm_value(&candidate_plan_value) {
        read_mitm_certificate(config)
    } else {
        None
    };
    respond(
        reader,
        json!({
            "ok": true,
            "state": if activating { "activating" } else { "active" },
            "configSha256": request.config_sha256,
            "modulePlanSha256": request.module_plan_sha256,
            "healthy": runtime.sing_box_ready(),
            "ready": runtime_ready(config, runtime),
            "networkReady": guest_network_ready(config),
            "packetStats": config.guest_network.as_ref().map(|network| PacketStats {
                lan: read_interface_stats(&network.lan_interface),
                tun: read_interface_stats("tun0"),
            }),
            "pid": runtime.pid(),
            "mitmHealthy": runtime.mitm_healthy(),
            "mitmReady": runtime.mitm_ready(),
            "mitmPid": runtime.mitm_pid(),
            "mitmCertificatePem": mitm_certificate_pem,
        }),
    )
}

#[allow(dead_code)]
fn activate_config(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    request: &Request,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    let staged =
        read_staged_config(config)?.ok_or_else(|| "没有可激活的 sing-box 配置".to_string())?;
    if staged.size != request.config_size || staged.sha256 != request.config_sha256 {
        return respond(
            reader,
            error_response("待激活配置与 staged 元数据不匹配".into()),
        );
    }
    let incoming = config_incoming_path(config);
    if !incoming.is_file() {
        return respond(reader, error_response("staged sing-box 配置不存在".into()));
    }
    let candidate =
        fs::read(&incoming).map_err(|error| format!("读取 staged sing-box 配置失败：{error}"))?;
    serde_json::from_slice::<Value>(&candidate)
        .map_err(|error| format!("staged sing-box 配置不是有效 JSON：{error}"))?;

    let active = match read_pointer(&active_path(&config.state_dir), "active")? {
        Some(value) => value,
        None => return respond(reader, error_response("没有可运行的 sing-box 版本".into())),
    };
    let artifact = version_dir(&config.state_dir, &active)?.join("sing-box");
    if !artifact.is_file() {
        return respond(reader, error_response("active sing-box 文件不存在".into()));
    }
    check_sing_box(&artifact, &incoming)?;
    let config_path = sing_box_config_path(config);
    let previous = match fs::read(&config_path) {
        Ok(value) => Some(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("读取当前 sing-box 配置失败：{error}")),
    };
    if let Some(previous) = previous.as_deref() {
        write_atomic_bytes(&config_previous_path(config), previous)?;
    }
    if let Err(error) = runtime.stop(&config.readiness_file) {
        return respond(
            reader,
            error_response(format!("停止当前 sing-box 失败：{error}")),
        );
    }
    if let Err(error) = write_atomic_bytes(&config_path, &candidate) {
        let _ = restore_config(config, previous.as_deref());
        let _ = restart_version(config, runtime, Some(&active));
        return respond(
            reader,
            error_response(format!("提交 sing-box 配置失败：{error}")),
        );
    }
    if let Err(start_error) = start_version(config, runtime, &active) {
        let stop_error = runtime.stop(&config.readiness_file).err();
        let restore_error = restore_config(config, previous.as_deref());
        let recovery = if stop_error.is_none() && restore_error.is_ok() {
            restart_version(config, runtime, Some(&active))
        } else {
            Ok(())
        };
        let details = [
            stop_error.map(|error| format!("；候选 sing-box 停止失败，未重启旧版本：{error}")),
            restore_error
                .err()
                .map(|error| format!("；旧配置恢复失败：{error}")),
            recovery
                .err()
                .map(|error| format!("；旧配置恢复启动失败：{error}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("");
        runtime.last_error = Some(format!("{start_error}{details}"));
        return respond(
            reader,
            error_response(format!("sing-box 新配置启动失败：{start_error}{details}")),
        );
    }
    let _ = fs::remove_file(&incoming);
    let _ = fs::remove_file(config_staged_path(config));
    let config_sha256 = file_sha256(&config_path)?;
    let packet_stats = config.guest_network.as_ref().map(|network| PacketStats {
        lan: read_interface_stats(&network.lan_interface),
        tun: read_interface_stats("tun0"),
    });
    respond(
        reader,
        json!({
            "ok": true,
            "state": "active",
            "configSha256": config_sha256,
            "healthy": true,
            "ready": runtime_ready(config, runtime),
            "networkReady": guest_network_ready(config),
            "packetStats": packet_stats,
            "pid": runtime.pid(),
        }),
    )
}

#[allow(dead_code)]
fn activate_module_plan(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    request: &Request,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    let staged =
        read_staged_module_plan(config)?.ok_or_else(|| "没有可激活的模块运行计划".to_string())?;
    if staged.size != request.module_plan_size || staged.sha256 != request.module_plan_sha256 {
        return respond(
            reader,
            error_response("待激活模块运行计划与 staged 元数据不匹配".into()),
        );
    }
    let incoming = module_plan_incoming_path(config);
    if !incoming.is_file() {
        return respond(reader, error_response("staged 模块运行计划不存在".into()));
    }
    let candidate =
        fs::read(&incoming).map_err(|error| format!("读取 staged 模块运行计划失败：{error}"))?;
    let value: Value = serde_json::from_slice(&candidate)
        .map_err(|error| format!("staged 模块运行计划不是有效 JSON：{error}"))?;
    if let Err(error) = runtime.stop_mitm() {
        return respond(
            reader,
            error_response(format!("停止旧 Module Engine 失败：{error}")),
        );
    }
    write_atomic_bytes(&module_plan_path(config), &candidate)?;
    let _ = fs::remove_file(&incoming);
    let _ = fs::remove_file(module_plan_staged_path(config));
    if module_plan_requires_mitm_value(&value) {
        if let Err(error) = start_mitm(config, runtime) {
            runtime.last_error = Some(error.clone());
            return respond(
                reader,
                error_response(format!("启动 guest Module Engine 失败：{error}")),
            );
        }
    }
    let mitm_certificate_pem = if module_plan_requires_mitm_value(&value) {
        read_mitm_certificate(config)
    } else {
        None
    };
    respond(
        reader,
        json!({
            "ok": true,
            "state": "active",
            "modulePlanSha256": request.module_plan_sha256,
            "mitmHealthy": runtime.mitm_healthy(),
            "mitmReady": runtime.mitm_ready(),
            "mitmPid": runtime.mitm_pid(),
            "mitmCertificatePem": mitm_certificate_pem,
        }),
    )
}

fn rollback(
    reader: &mut BufReader<TcpStream>,
    config: &AgentConfig,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    let previous = match read_pointer(&previous_path(&config.state_dir), "previous")? {
        Some(value) => value,
        None => return respond(reader, error_response("没有可回滚的 sing-box 版本".into())),
    };
    let artifact = version_dir(&config.state_dir, &previous)?.join("sing-box");
    if !artifact.is_file() {
        return respond(reader, error_response("回滚版本文件不存在".into()));
    }
    let current = read_pointer(&active_path(&config.state_dir), "active")?;
    if let Err(error) = runtime.stop(&config.readiness_file) {
        return respond(
            reader,
            error_response(format!("停止当前 sing-box 失败：{error}")),
        );
    }
    if let Err(start_error) = start_version(config, runtime, &previous) {
        let recovery_message = match runtime.stop(&config.readiness_file) {
            Ok(()) => restart_version(config, runtime, current.as_deref())
                .err()
                .map(|error| format!("；当前版本恢复失败：{error}"))
                .unwrap_or_default(),
            Err(error) => format!("；候选 sing-box 停止失败，未重启当前版本：{error}"),
        };
        runtime.last_error = Some(format!("{start_error}{recovery_message}"));
        return respond(
            reader,
            error_response(format!(
                "sing-box 回滚版本启动失败：{start_error}{recovery_message}"
            )),
        );
    }
    if let Err(pointer_error) = write_pointer(&previous_path(&config.state_dir), current.as_deref())
        .and_then(|_| write_pointer(&active_path(&config.state_dir), Some(&previous)))
    {
        let recovery_message = match runtime.stop(&config.readiness_file) {
            Ok(()) => restart_version(config, runtime, current.as_deref())
                .err()
                .map(|error| format!("；当前版本恢复失败：{error}"))
                .unwrap_or_default(),
            Err(error) => format!("；候选 sing-box 停止失败，未重启当前版本：{error}"),
        };
        runtime.last_error = Some(format!("{pointer_error}{recovery_message}"));
        return respond(
            reader,
            error_response(format!(
                "提交回滚版本指针失败：{pointer_error}{recovery_message}"
            )),
        );
    }

    respond(
        reader,
        json!({
            "ok": true,
            "state": "rolled_back",
            "version": previous,
            "healthy": runtime.sing_box_ready(),
            "ready": runtime_ready(config, runtime),
            "networkReady": guest_network_ready(config),
            "pid": runtime.pid(),
        }),
    )
}

fn status_response(config: &AgentConfig, runtime: &mut AgentRuntime) -> Result<Value, String> {
    runtime.refresh(&config.readiness_file);
    runtime.refresh_mitm(&module_plan_path(config));
    progress_pending_session(config, runtime);
    let active_version =
        read_pointer(&active_path(&config.state_dir), "active")?.unwrap_or_default();
    let staged_version = read_staged(&config.state_dir)?.map(|value| value.version);
    let config_sha256 = file_sha256(&sing_box_config_path(config)).ok();
    let mitm_required = module_plan_requires_mitm(&module_plan_path(config));
    let sing_box_ready = runtime.sing_box_ready();
    let mitm_ready =
        !mitm_required || (runtime.mitm_ready() && read_mitm_certificate(config).is_some());
    let mitm_healthy = !mitm_required || runtime.mitm_healthy();
    let healthy = !active_version.is_empty()
        && runtime.is_healthy(&active_version, &config.readiness_file)
        && sing_box_ready
        && mitm_healthy
        && mitm_ready;
    let network_ready = guest_network_ready(config);
    let control_listening = !config.network_ready_file.is_some() || runtime.control_listening;
    let probes_ready = healthy && network_ready && control_listening;
    if probes_ready && !config.readiness_file.is_file() {
        if let Err(error) = write_readiness(config, runtime) {
            runtime.last_error = Some(error);
        }
    }
    let ready = probes_ready && config.readiness_file.is_file();
    let gateway_lan_ip = config
        .guest_network
        .as_ref()
        .map(|network| network.lan_ip.to_string());
    let upstream_interface = config
        .guest_network
        .as_ref()
        .map(|network| network.lan_interface.clone());
    let packet_stats = config.guest_network.as_ref().map(|network| PacketStats {
        lan: read_interface_stats(&network.lan_interface),
        tun: read_interface_stats("tun0"),
    });
    Ok(json!({
        "ok": true,
        "state": "ready",
        "status": {
            "agentVersion": config.agent_version,
            "singBoxVersion": active_version,
            "activeVersion": active_version,
            "stagedVersion": staged_version,
            "configSha256": config_sha256,
            "healthy": healthy,
            "ready": ready,
            "singBoxReady": sing_box_ready,
            "networkReady": network_ready,
            "gatewayLanIp": gateway_lan_ip,
            "upstreamInterface": upstream_interface,
            "packetStats": packet_stats,
            "lastError": runtime.last_error,
            "pid": runtime.pid(),
            "mitmHealthy": runtime.mitm_healthy(),
            "mitmReady": mitm_ready,
            "mitmPid": runtime.mitm_pid(),
            "modulePlanSha256": file_sha256(&module_plan_path(config)).ok(),
            "mitmCertificatePem": read_mitm_certificate(config),
        }
    }))
}

fn read_interface_stats(interface: &str) -> Option<InterfaceStats> {
    let base = Path::new("/sys/class/net")
        .join(interface)
        .join("statistics");
    let read_counter = |name: &str| -> Option<u64> {
        fs::read_to_string(base.join(name))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    Some(InterfaceStats {
        interface: interface.to_string(),
        rx_packets: read_counter("rx_packets")?,
        tx_packets: read_counter("tx_packets")?,
        rx_bytes: read_counter("rx_bytes")?,
        tx_bytes: read_counter("tx_bytes")?,
    })
}

fn runtime_ready(config: &AgentConfig, runtime: &AgentRuntime) -> bool {
    dataplane_probes_ready(config, runtime) && config.readiness_file.is_file()
}

fn dataplane_probes_ready(config: &AgentConfig, runtime: &AgentRuntime) -> bool {
    runtime.sing_box_ready()
        && (!module_plan_requires_mitm(&module_plan_path(config))
            || (runtime.mitm_ready() && read_mitm_certificate(config).is_some()))
        && guest_network_ready(config)
        && (!config.network_ready_file.is_some() || runtime.control_listening)
}

fn progress_pending_session(config: &AgentConfig, runtime: &mut AgentRuntime) {
    let Some(pending) = runtime.pending_session.as_ref() else {
        return;
    };
    let config_matches = file_sha256(&sing_box_config_path(config))
        .map(|sha256| sha256 == pending.config_sha256)
        .unwrap_or(false);
    let plan_matches = file_sha256(&module_plan_path(config))
        .map(|sha256| sha256 == pending.module_plan_sha256)
        .unwrap_or(false);
    let ready = config_matches && plan_matches && dataplane_probes_ready(config, runtime);
    let child_failed = runtime.liveness_fault
        || runtime.sing_box.is_none()
        || (module_plan_requires_mitm(&module_plan_path(config)) && runtime.mitm.is_none());
    if ready {
        match write_readiness(config, runtime) {
            Ok(()) => {
                remove_session_artifacts(config);
                runtime.pending_session = None;
                runtime.last_error = None;
            }
            Err(error) => runtime.last_error = Some(error),
        }
        return;
    }
    if !child_failed && Instant::now() < pending.deadline {
        return;
    }

    let pending = runtime
        .pending_session
        .take()
        .expect("pending session exists");
    rollback_pending_session(
        config,
        runtime,
        pending,
        if child_failed {
            "Gateway session data plane 在 ready 前退出"
        } else {
            "Gateway session 在 ready 前超时"
        },
    );
}

fn rollback_pending_session(
    config: &AgentConfig,
    runtime: &mut AgentRuntime,
    pending: PendingSession,
    reason: &str,
) {
    let stop_error = runtime.stop(&config.readiness_file).err();
    let config_path = sing_box_config_path(config);
    let plan_path = module_plan_path(config);
    let config_restore = restore_config(config, pending.previous_config.as_deref());
    let plan_restore = restore_file(&plan_path, pending.previous_plan.as_deref(), "模块运行计划");
    let config_verify = verify_restored_file(
        &config_path,
        pending.previous_config.as_deref(),
        "sing-box 配置",
    );
    let plan_verify =
        verify_restored_file(&plan_path, pending.previous_plan.as_deref(), "模块运行计划");
    remove_session_artifacts(config);
    let failures = [
        stop_error,
        config_restore.err(),
        plan_restore.err(),
        config_verify.err(),
        plan_verify.err(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if !failures.is_empty() {
        let message = format!(
            "{reason}；Gateway session 回滚失败，data plane 已保持停止：{}",
            failures.join("；")
        );
        let _ = runtime.stop(&config.readiness_file);
        runtime.last_error = Some(message);
        return;
    }

    match restart_version(config, runtime, Some(&pending.active_version)) {
        Ok(()) => {
            runtime.last_error = Some(format!(
                "{reason}；旧 Gateway session 已恢复，等待旧 data plane 就绪"
            ));
        }
        Err(error) => {
            let stop_error = runtime.stop(&config.readiness_file).err();
            let suffix = stop_error
                .map(|value| format!("；停止残留 data plane 失败：{value}"))
                .unwrap_or_default();
            runtime.last_error = Some(format!(
                "{reason}；旧 Gateway session 恢复失败：{error}{suffix}"
            ));
        }
    }
}

fn remove_session_artifacts(config: &AgentConfig) {
    let _ = fs::remove_file(config_incoming_path(config));
    let _ = fs::remove_file(config_staged_path(config));
    let _ = fs::remove_file(module_plan_incoming_path(config));
    let _ = fs::remove_file(module_plan_staged_path(config));
}

fn abort_pending_session_for_stop(
    config: &AgentConfig,
    runtime: &mut AgentRuntime,
) -> Result<(), String> {
    let Some(pending) = runtime.pending_session.take() else {
        return runtime.stop(&config.readiness_file);
    };

    // Stop is an explicit abort, not a failed activation.  Restore the
    // previous pair without restarting it; the caller asked for a stopped
    // data plane and the next start may then use the last committed state.
    let stop_error = runtime.stop(&config.readiness_file).err();
    let config_path = sing_box_config_path(config);
    let plan_path = module_plan_path(config);
    let config_restore = restore_config(config, pending.previous_config.as_deref());
    let plan_restore = restore_file(&plan_path, pending.previous_plan.as_deref(), "模块运行计划");
    let config_verify = verify_restored_file(
        &config_path,
        pending.previous_config.as_deref(),
        "sing-box 配置",
    );
    let plan_verify =
        verify_restored_file(&plan_path, pending.previous_plan.as_deref(), "模块运行计划");
    remove_session_artifacts(config);
    let failures = [
        stop_error,
        config_restore.err(),
        plan_restore.err(),
        config_verify.err(),
        plan_verify.err(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        // Keep the data plane fail-closed.  A retained child handle can be
        // retried here if kill/wait had a transient failure; never restart a
        // candidate or the previous session from an explicit Stop.
        let retry_stop_error = runtime.stop(&config.readiness_file).err();
        let details = failures
            .into_iter()
            .chain(retry_stop_error)
            .collect::<Vec<_>>();
        Err(format!(
            "显式停止 Gateway session 失败，data plane 已保持停止：{}",
            details.join("；")
        ))
    }
}

fn start_active(config: &AgentConfig, runtime: &mut AgentRuntime) -> Result<(), String> {
    let Some(version) = read_pointer(&active_path(&config.state_dir), "active")? else {
        return Ok(());
    };
    start_version(config, runtime, &version)
}

fn restart_version(
    config: &AgentConfig,
    runtime: &mut AgentRuntime,
    version: Option<&str>,
) -> Result<(), String> {
    let Some(version) = version else {
        return Ok(());
    };
    start_version(config, runtime, version)
}

fn start_version(
    config: &AgentConfig,
    runtime: &mut AgentRuntime,
    version: &str,
) -> Result<(), String> {
    if config.network_ready_file.is_some() {
        if !guest_network_ready(config) {
            return Err("guest network 尚未就绪，拒绝启动 sing-box data plane".into());
        }
        if !runtime.control_listening {
            return Err("guest agent control listener 尚未就绪，拒绝启动 sing-box".into());
        }
    }
    if runtime.sing_box.is_some() || runtime.mitm.is_some() || runtime.liveness_fault {
        return Err("已有 Gateway data-plane ownership，必须先成功停止后才能启动".into());
    }
    remove_readiness(config);
    runtime.liveness_fault = false;
    validate_version(version)?;
    let artifact = version_dir(&config.state_dir, version)?.join("sing-box");
    if !artifact.is_file() {
        return Err(format!("sing-box 版本文件不存在：{}", artifact.display()));
    }
    let config_path = sing_box_config_path(config);
    if !config_path.is_file() {
        return Err(format!(
            "sing-box 配置文件不存在：{}",
            config_path.display()
        ));
    }
    check_sing_box(&artifact, &config_path)?;
    let mut child = Command::new(&artifact)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        // Keep data-plane diagnostics on the guest console so a runtime
        // failure is actionable instead of being reduced to exit code 1.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("启动 sing-box {version} 失败：{error}"))?;
    thread::sleep(SING_BOX_STARTUP_GRACE);
    let status = match child.try_wait() {
        Ok(status) => status,
        Err(error) => {
            runtime.sing_box = Some(ManagedSingBox {
                version: version.to_string(),
                child,
            });
            runtime.liveness_fault = true;
            return Err(format!("检查 sing-box {version} 启动状态失败：{error}"));
        }
    };
    match status {
        Some(status) => Err(format!(
            "sing-box {version} 启动后退出，状态码 {:?}",
            status.code()
        )),
        None => {
            runtime.sing_box = Some(ManagedSingBox {
                version: version.to_string(),
                child,
            });
            runtime.last_error = None;
            if module_plan_requires_mitm(&module_plan_path(config)) {
                if let Err(error) = start_mitm(config, runtime) {
                    let _ = runtime.stop(&config.readiness_file);
                    return Err(error);
                }
            }
            if runtime.sing_box_ready()
                && (!module_plan_requires_mitm(&module_plan_path(config))
                    || (runtime.mitm_ready() && read_mitm_certificate(config).is_some()))
            {
                if let Err(error) = write_readiness(config, runtime) {
                    let _ = runtime.stop(&config.readiness_file);
                    return Err(error);
                }
            } else {
                // The control request must return promptly. The host can poll
                // status while Clash API or mitmproxy finishes booting instead
                // of blocking the single control loop on a multi-second wait.
                remove_readiness(config);
            }
            Ok(())
        }
    }
}

fn start_mitm(config: &AgentConfig, runtime: &mut AgentRuntime) -> Result<(), String> {
    if runtime.liveness_fault {
        return Err("Gateway data-plane liveness fault 尚未清除，拒绝启动 Module Engine".into());
    }
    if runtime.mitm_healthy() {
        return Ok(());
    }
    let plan_path = module_plan_path(config);
    if !module_plan_requires_mitm(&plan_path) {
        return Ok(());
    }
    let binary = Path::new("/usr/bin/mitmdump");
    let addon = Path::new("/usr/lib/songsterx/mitm_minimal_addon.py");
    let runtime_module = Path::new("/usr/lib/songsterx/surge_js_runtime.py");
    if !binary.is_file() {
        return Err(format!("guest mitmdump 不存在：{}", binary.display()));
    }
    if !addon.is_file() || !runtime_module.is_file() {
        return Err("guest Module Engine addon/runtime 文件不完整".into());
    }
    if !plan_path.is_file() {
        return Err(format!("guest 模块运行计划不存在：{}", plan_path.display()));
    }
    let confdir = config.state_dir.join("mitmproxy");
    fs::create_dir_all(&confdir)
        .map_err(|error| format!("无法创建 guest mitmproxy 配置目录：{error}"))?;
    let module_plan: Value = serde_json::from_slice(
        &fs::read(&plan_path).map_err(|error| format!("读取 guest 模块运行计划失败：{error}"))?,
    )
    .map_err(|error| format!("guest 模块运行计划不是有效 JSON：{error}"))?;
    if let Some(ca_pem) = module_plan.get("mitmCaPem").and_then(Value::as_str) {
        if !ca_pem.contains("PRIVATE KEY") || !ca_pem.contains("CERTIFICATE") {
            return Err("guest 模块运行计划中的 MITM CA 不完整".into());
        }
        write_atomic_bytes(&confdir.join("mitmproxy-ca.pem"), ca_pem.as_bytes())?;
    }
    let mut child = Command::new(binary)
        .arg("--listen-host")
        .arg("127.0.0.1")
        .arg("--listen-port")
        .arg("8080")
        .arg("--set")
        .arg(format!("confdir={}", confdir.display()))
        .arg("-s")
        .arg(addon)
        .env("SONGSTERX_MODULE_PLAN", &plan_path)
        .env("PYTHONPATH", "/usr/lib/songsterx")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("启动 guest mitmdump 失败：{error}"))?;
    thread::sleep(SING_BOX_STARTUP_GRACE);
    let status = match child.try_wait() {
        Ok(status) => status,
        Err(error) => {
            runtime.mitm = Some(ManagedMitm { child });
            runtime.liveness_fault = true;
            return Err(format!("检查 guest mitmdump 启动状态失败：{error}"));
        }
    };
    match status {
        Some(status) => Err(format!(
            "guest mitmdump 启动后退出，状态码 {:?}",
            status.code()
        )),
        None => {
            runtime.mitm = Some(ManagedMitm { child });
            // Do not wait for the listener or CA here. Returning releases the
            // control loop so status/stop can be handled while mitmproxy
            // finishes initialization; readiness is published only by the
            // real probes in status_response/write_readiness.
            Ok(())
        }
    }
}

fn read_mitm_certificate(config: &AgentConfig) -> Option<String> {
    let path = config
        .state_dir
        .join("mitmproxy")
        .join("mitmproxy-ca-cert.pem");
    let certificate = fs::read_to_string(path).ok()?;
    if certificate.contains("BEGIN CERTIFICATE") {
        Some(certificate)
    } else {
        None
    }
}

fn module_plan_requires_mitm(path: &Path) -> bool {
    let Ok(content) = fs::read(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&content) else {
        return false;
    };
    module_plan_requires_mitm_value(&value)
}

fn module_plan_requires_mitm_value(value: &Value) -> bool {
    [
        "mitmHostnames",
        "urlRewrites",
        "mapLocals",
        "headerRewrites",
    ]
    .iter()
    .any(|key| {
        value
            .get(*key)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    })
}

fn write_readiness(config: &AgentConfig, runtime: &AgentRuntime) -> Result<(), String> {
    if config.network_ready_file.is_some() {
        if !guest_network_ready(config) {
            return Err("guest network 尚未就绪，禁止写入 guest readiness".into());
        }
        if !runtime.control_listening {
            return Err("guest agent control listener 尚未就绪，禁止写入 guest readiness".into());
        }
    }
    if runtime.sing_box.is_none() {
        return Err("sing-box 尚未运行，禁止写入 guest readiness".into());
    }
    if !runtime.sing_box_ready() {
        return Err("sing-box Clash API 尚未就绪，禁止写入 guest readiness".into());
    }
    if module_plan_requires_mitm(&module_plan_path(config))
        && (!runtime.mitm_ready() || read_mitm_certificate(config).is_none())
    {
        return Err(
            "guest Module Engine 尚未完成监听和 CA 初始化，禁止写入 guest readiness".into(),
        );
    }
    if let Some(parent) = config.readiness_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("无法创建 guest readiness 目录：{error}"))?;
    }
    let mut file = File::create(&config.readiness_file)
        .map_err(|error| format!("无法写入 guest readiness 文件：{error}"))?;
    file.write_all(b"ready\n")
        .map_err(|error| format!("无法写入 guest readiness 标记：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("同步 guest readiness 文件失败：{error}"))
}

fn remove_readiness(config: &AgentConfig) {
    remove_readiness_path(&config.readiness_file);
}

fn remove_readiness_path(path: &Path) {
    let _ = fs::remove_file(path);
}

fn guest_network_ready(config: &AgentConfig) -> bool {
    config
        .network_ready_file
        .as_ref()
        .map(|path| path.is_file())
        .unwrap_or(true)
}

fn load_guest_network() -> Result<boot_config::ResolvedGuestNetwork, String> {
    let cmdline = fs::read_to_string("/proc/cmdline")
        .map_err(|error| format!("无法读取 Linux kernel cmdline：{error}"))?;
    let boot = boot_config::parse_cmdline(&cmdline)?;
    let interfaces = boot_config::read_interface_inventory(Path::new("/sys/class/net"))?;
    boot_config::resolve_interfaces(&boot, &interfaces)
}

fn validate_absolute_runtime_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} 必须使用绝对路径：{}", path.display()));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(format!(
            "{label} 不允许包含 . 或 .. 路径组件：{}",
            path.display()
        ));
    }
    if path == Path::new("/") {
        return Err(format!("{label} 不能指向根目录"));
    }
    Ok(())
}

fn check_sing_box(binary: &Path, config_path: &Path) -> Result<(), String> {
    let output = Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(config_path)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("执行 sing-box check 失败：{error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = command_output_detail(&output);
    if detail.is_empty() {
        Err(format!(
            "sing-box check 失败，状态码 {:?}",
            output.status.code()
        ))
    } else {
        Err(format!("sing-box check 失败：{detail}"))
    }
}

fn command_output_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    detail.chars().take(512).collect()
}

fn sing_box_config_path(config: &AgentConfig) -> PathBuf {
    config
        .sing_box_config
        .clone()
        .unwrap_or_else(|| config.state_dir.join("sing-box.json"))
}

fn config_incoming_path(config: &AgentConfig) -> PathBuf {
    sing_box_config_path(config).with_extension("incoming")
}

fn config_previous_path(config: &AgentConfig) -> PathBuf {
    sing_box_config_path(config).with_extension("previous")
}

fn config_staged_path(config: &AgentConfig) -> PathBuf {
    sing_box_config_path(config).with_extension("staged.json")
}

fn module_plan_path(config: &AgentConfig) -> PathBuf {
    config.state_dir.join("module-plan.json")
}

fn module_plan_incoming_path(config: &AgentConfig) -> PathBuf {
    config.state_dir.join("module-plan.incoming")
}

fn module_plan_staged_path(config: &AgentConfig) -> PathBuf {
    config.state_dir.join("module-plan.staged.json")
}

fn read_staged_config(config: &AgentConfig) -> Result<Option<StagedConfig>, String> {
    match fs::read_to_string(config_staged_path(config)) {
        Ok(value) => serde_json::from_str(&value)
            .map(Some)
            .map_err(|error| format!("staged sing-box 配置元数据无效：{error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("读取 staged sing-box 配置元数据失败：{error}")),
    }
}

fn write_staged_config(config: &AgentConfig, value: &StagedConfig) -> Result<(), String> {
    let content = serde_json::to_vec(value)
        .map_err(|error| format!("序列化 staged sing-box 配置失败：{error}"))?;
    write_atomic_bytes(&config_staged_path(config), &content)
}

fn read_staged_module_plan(config: &AgentConfig) -> Result<Option<StagedModulePlan>, String> {
    match fs::read_to_string(module_plan_staged_path(config)) {
        Ok(value) => serde_json::from_str(&value)
            .map(Some)
            .map_err(|error| format!("staged 模块运行计划元数据无效：{error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("读取 staged 模块运行计划元数据失败：{error}")),
    }
}

fn write_staged_module_plan(config: &AgentConfig, value: &StagedModulePlan) -> Result<(), String> {
    let content = serde_json::to_vec(value)
        .map_err(|error| format!("序列化 staged 模块运行计划失败：{error}"))?;
    write_atomic_bytes(&module_plan_staged_path(config), &content)
}

fn restore_config(config: &AgentConfig, previous: Option<&[u8]>) -> Result<(), String> {
    match previous {
        Some(previous) => write_atomic_bytes(&sing_box_config_path(config), previous),
        None => match fs::remove_file(sing_box_config_path(config)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("删除失败的 sing-box 配置失败：{error}")),
        },
    }
}

fn read_optional_file(path: &Path, label: &str) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("读取 {label} 失败：{error}")),
    }
}

fn restore_file(path: &Path, previous: Option<&[u8]>, label: &str) -> Result<(), String> {
    match previous {
        Some(previous) => write_atomic_bytes(path, previous),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("删除失败的 {label} 文件失败：{error}")),
        },
    }
}

fn verify_restored_file(path: &Path, expected: Option<&[u8]>, label: &str) -> Result<(), String> {
    match (expected, fs::read(path)) {
        (Some(expected), Ok(actual)) if actual == expected => Ok(()),
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        (Some(_), Ok(_)) => Err(format!("恢复后的 {label} 内容校验失败")),
        (_, Err(error)) => Err(format!("读取恢复后的 {label} 失败：{error}")),
        (None, Ok(_)) => Err(format!("恢复后的 {label} 不应存在")),
    }
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let file =
        File::open(path).map_err(|error| format!("无法打开文件 {}：{error}", path.display()))?;
    sha256_reader(file)
}

fn sha256_reader(mut file: File) -> Result<String, String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("计算文件 SHA-256 失败：{error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn read_pointer(path: &Path, label: &str) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            validate_version(value).map_err(|error| format!("{label} 版本指针无效：{error}"))?;
            Ok(Some(value.to_string()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("读取 {label} 版本指针失败：{error}")),
    }
}

fn write_pointer(path: &Path, version: Option<&str>) -> Result<(), String> {
    match version {
        Some(version) => {
            validate_version(version)?;
            write_atomic(path, version)
        }
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("删除空版本指针失败：{error}")),
        },
    }
}

fn validate_artifact_request(request: &Request) -> Result<(), String> {
    validate_version(&request.version)?;
    if request.architecture.trim().is_empty()
        || request.architecture.contains('/')
        || request.architecture.contains('\\')
    {
        return Err("升级架构标识无效".into());
    }
    if request.size == 0 {
        return Err("升级文件不能为空".into());
    }
    if request.size > MAX_UPGRADE_SIZE {
        return Err("升级文件不能超过 64 MiB".into());
    }
    if request.sha256.len() != 64
        || !request
            .sha256
            .chars()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err("升级文件 SHA-256 无效".into());
    }
    Ok(())
}

fn validate_config_request(request: &Request) -> Result<(), String> {
    if request.config_size == 0 || request.config_size > MAX_CONFIG_SIZE {
        return Err("sing-box 配置大小必须在 1-16777216 字节之间".into());
    }
    if request.config_sha256.len() != 64
        || !request
            .config_sha256
            .chars()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err("sing-box 配置 SHA-256 无效".into());
    }
    Ok(())
}

fn validate_module_plan_request(request: &Request) -> Result<(), String> {
    if request.module_plan_size == 0 || request.module_plan_size > MAX_MODULE_PLAN_SIZE {
        return Err("模块运行计划大小必须在 1-16777216 字节之间".into());
    }
    if request.module_plan_sha256.len() != 64
        || !request
            .module_plan_sha256
            .chars()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err("模块运行计划 SHA-256 无效".into());
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > 128
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        return Err("升级版本标识无效".into());
    }
    Ok(())
}

fn respond(reader: &mut BufReader<TcpStream>, value: Value) -> Result<(), String> {
    let mut line =
        serde_json::to_vec(&value).map_err(|error| format!("序列化响应失败：{error}"))?;
    line.push(b'\n');
    let stream = reader.get_mut();
    stream
        .write_all(&line)
        .map_err(|error| format!("发送响应失败：{error}"))?;
    stream
        .flush()
        .map_err(|error| format!("刷新响应失败：{error}"))
}

fn error_response(message: String) -> Value {
    json!({"ok": false, "state": "failed", "message": message})
}

fn read_auth_token(path: &Path) -> Result<String, String> {
    let token = fs::read_to_string(path).map_err(|error| {
        format!(
            "无法读取 guest agent token 文件 {}：{error}",
            path.display()
        )
    })?;
    let token = token.trim();
    if token.len() < 32 || token.len() > 256 || !token.bytes().all(|value| value.is_ascii_graphic())
    {
        return Err("guest agent token 必须是 32-256 个 ASCII 可打印字符".into());
    }
    Ok(token.to_string())
}

fn versions_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("versions")
}

fn version_dir(state_dir: &Path, version: &str) -> Result<PathBuf, String> {
    validate_version(version)?;
    Ok(versions_dir(state_dir).join(version))
}

fn active_path(state_dir: &Path) -> PathBuf {
    state_dir.join("active")
}

fn previous_path(state_dir: &Path) -> PathBuf {
    state_dir.join("previous")
}

fn staged_path(state_dir: &Path) -> PathBuf {
    state_dir.join("staged.json")
}

fn read_staged(state_dir: &Path) -> Result<Option<StagedArtifact>, String> {
    match fs::read_to_string(staged_path(state_dir)) {
        Ok(value) => serde_json::from_str(&value)
            .map(Some)
            .map_err(|error| format!("staged 元数据无效：{error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("读取 staged 元数据失败：{error}")),
    }
}

fn write_staged(state_dir: &Path, value: &StagedArtifact) -> Result<(), String> {
    let content =
        serde_json::to_vec(value).map_err(|error| format!("序列化 staged 元数据失败：{error}"))?;
    write_atomic_bytes(&staged_path(state_dir), &content)
}

fn write_atomic(path: &Path, value: &str) -> Result<(), String> {
    write_atomic_bytes(path, format!("{value}\n").as_bytes())
}

fn write_atomic_bytes(path: &Path, value: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("创建临时状态文件失败：{error}"))?;
    file.write_all(value)
        .map_err(|error| format!("写入临时状态文件失败：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("同步临时状态文件失败：{error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("提交状态文件失败：{error}"))
}

fn set_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)
            .map_err(|error| format!("读取升级文件权限失败：{error}"))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)
            .map_err(|error| format!("设置升级文件可执行权限失败：{error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_paths_reject_traversal() {
        assert!(version_dir(Path::new("/tmp"), "../escape").is_err());
        assert!(version_dir(Path::new("/tmp"), "1.14.0").is_ok());
    }

    #[test]
    fn artifact_requests_require_integrity_metadata() {
        let request = Request {
            method: "stage_upgrade".into(),
            auth: "a".repeat(32),
            version: "1.14.0".into(),
            architecture: "arm64".into(),
            size: 10,
            sha256: "a".repeat(64),
            config_size: 0,
            config_sha256: String::new(),
            module_plan_size: 0,
            module_plan_sha256: String::new(),
            group: String::new(),
            name: String::new(),
            url: String::new(),
            timeout_ms: 0,
        };
        assert!(validate_artifact_request(&request).is_ok());
        assert!(validate_artifact_request(&Request { size: 0, ..request }).is_err());
    }

    #[test]
    fn artifact_requests_have_a_total_size_limit() {
        let request = Request {
            method: "stage_upgrade".into(),
            auth: "a".repeat(32),
            version: "1.14.0".into(),
            architecture: "arm64".into(),
            size: MAX_UPGRADE_SIZE + 1,
            sha256: "a".repeat(64),
            config_size: 0,
            config_sha256: String::new(),
            module_plan_size: 0,
            module_plan_sha256: String::new(),
            group: String::new(),
            name: String::new(),
            url: String::new(),
            timeout_ms: 0,
        };
        assert!(validate_artifact_request(&request).is_err());
    }

    #[test]
    fn config_request_accepts_host_camel_case_metadata() {
        let request: Request = serde_json::from_str(
            r#"{"method":"stage_config","auth":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","configSize":7,"configSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
        )
        .unwrap();
        assert_eq!(request.config_size, 7);
        assert_eq!(request.config_sha256.len(), 64);
    }

    #[test]
    fn guest_connections_response_is_compact_and_bounded() {
        let connections = (0..400)
            .map(|index| {
                json!({
                    "id": format!("guest-{index}"),
                    "metadata": {
                        "sourceIP": "192.168.250.2",
                        "sourcePort": "40000",
                        "destinationIP": "203.0.113.8",
                        "destinationPort": "443",
                        "host": format!("service-{index}.example.test"),
                        "network": "tcp"
                    },
                    "chains": ["proxy"],
                    "upload": 12,
                    "download": 34,
                    "start": "2026-08-19T10:25:57Z"
                })
            })
            .collect::<Vec<_>>();
        let response = compact_connections_response(json!({
            "uploadTotal": 12,
            "downloadTotal": 34,
            "memory": 56,
            "connections": connections
        }))
        .unwrap();
        let encoded = serde_json::to_vec(&response).unwrap();
        assert!(encoded.len() < AGENT_CONNECTIONS_RESPONSE_LIMIT);
        assert!(response["metrics"]["connections"].as_array().unwrap().len() <= MAX_CONNECTIONS);
        assert_eq!(
            response["metrics"]["connections"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()["id"],
            "guest-399"
        );
    }

    #[test]
    fn chunked_guest_clash_api_body_is_decoded() {
        assert_eq!(
            decode_chunked_body(b"4\r\ntest\r\n0\r\n\r\n").unwrap(),
            b"test"
        );
        assert!(decode_chunked_body(b"5\r\nnope\r\n").is_err());
    }

    #[test]
    fn auth_token_file_requires_a_long_printable_token() {
        let path = std::env::temp_dir().join(format!(
            "songsterx-gateway-agent-token-{}",
            std::process::id()
        ));
        fs::write(&path, "a".repeat(32)).unwrap();
        assert_eq!(read_auth_token(&path).unwrap(), "a".repeat(32));
        fs::write(&path, "too-short").unwrap();
        assert!(read_auth_token(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rollback_verification_detects_mismatch_and_unexpected_file() {
        let path = std::env::temp_dir().join(format!(
            "songsterx-gateway-agent-rollback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"old-plan").unwrap();
        assert!(verify_restored_file(&path, Some(b"old-plan"), "模块运行计划").is_ok());
        assert!(verify_restored_file(&path, Some(b"new-plan"), "模块运行计划").is_err());
        fs::remove_file(&path).unwrap();
        assert!(verify_restored_file(&path, None, "模块运行计划").is_ok());
        fs::write(&path, b"unexpected").unwrap();
        assert!(verify_restored_file(&path, None, "模块运行计划").is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn explicit_stop_cancels_pending_session_and_discards_staged_artifacts() {
        let root = std::env::temp_dir().join(format!(
            "songsterx-gateway-agent-stop-pending-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("sing-box.json");
        let config = AgentConfig {
            listen: "127.0.0.1:38292".into(),
            state_dir: root.clone(),
            agent_version: "test".into(),
            sing_box_config: Some(config_path),
            auth_token_file: root.join("agent.token"),
            auth_token: "a".repeat(32),
            readiness_file: root.join("ready"),
            network_ready_file: None,
            network_control: None,
            guest_network: None,
        };
        for path in [
            config_incoming_path(&config),
            config_staged_path(&config),
            module_plan_incoming_path(&config),
            module_plan_staged_path(&config),
        ] {
            fs::write(path, b"staged").unwrap();
        }
        let mut runtime = AgentRuntime {
            pending_session: Some(PendingSession {
                config_sha256: "candidate-config".into(),
                module_plan_sha256: "candidate-plan".into(),
                previous_config: Some(b"old-config".to_vec()),
                previous_plan: Some(b"old-plan".to_vec()),
                active_version: "1.14.0".into(),
                deadline: Instant::now() + SESSION_READY_TIMEOUT,
            }),
            ..AgentRuntime::default()
        };

        abort_pending_session_for_stop(&config, &mut runtime).unwrap();
        assert!(runtime.pending_session.is_none());
        assert_eq!(
            fs::read(sing_box_config_path(&config)).unwrap(),
            b"old-config"
        );
        assert_eq!(fs::read(module_plan_path(&config)).unwrap(), b"old-plan");
        assert!(!config_incoming_path(&config).exists());
        assert!(!config_staged_path(&config).exists());
        assert!(!module_plan_incoming_path(&config).exists());
        assert!(!module_plan_staged_path(&config).exists());
        abort_pending_session_for_stop(&config, &mut runtime).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn liveness_fault_blocks_new_data_plane_ownership() {
        let root = std::env::temp_dir().join(format!(
            "songsterx-gateway-agent-liveness-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = AgentConfig {
            listen: "127.0.0.1:38293".into(),
            state_dir: root.clone(),
            agent_version: "test".into(),
            sing_box_config: Some(root.join("sing-box.json")),
            auth_token_file: root.join("agent.token"),
            auth_token: "a".repeat(32),
            readiness_file: root.join("ready"),
            network_ready_file: None,
            network_control: None,
            guest_network: None,
        };
        let mut runtime = AgentRuntime {
            liveness_fault: true,
            ..AgentRuntime::default()
        };

        assert!(start_version(&config, &mut runtime, "1.14.0").is_err());
        assert!(start_mitm(&config, &mut runtime).is_err());
        assert!(runtime.sing_box.is_none());
        assert!(runtime.mitm.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sing_box_process_is_checked_started_and_stopped() {
        let root = std::env::temp_dir().join(format!(
            "songsterx-gateway-agent-process-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let version_dir = root.join("versions/1.14.0");
        fs::create_dir_all(&version_dir).unwrap();
        let config_path = root.join("sing-box.json");
        fs::write(&config_path, "{}\n").unwrap();
        let binary = version_dir.join("sing-box");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"$1\" = \"check\" ]; then test -f \"$3\"; exit $?; fi\nif [ \"$1\" = \"run\" ]; then exec /bin/sleep 30; fi\nexit 1\n",
        )
        .unwrap();
        set_executable(&binary).unwrap();

        let config = AgentConfig {
            listen: "127.0.0.1:38291".into(),
            state_dir: root.clone(),
            agent_version: "test".into(),
            sing_box_config: Some(config_path),
            auth_token_file: root.join("agent.token"),
            auth_token: "a".repeat(32),
            readiness_file: root.join("ready"),
            network_ready_file: None,
            network_control: None,
            guest_network: None,
        };
        let mut runtime = AgentRuntime::default();
        start_version(&config, &mut runtime, "1.14.0").unwrap();
        assert!(runtime.is_healthy("1.14.0", &config.readiness_file));
        assert!(config.readiness_file.is_file());
        assert!(runtime.pid().is_some());
        let child = &mut runtime
            .sing_box
            .as_mut()
            .expect("managed sing-box should exist")
            .child;
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!runtime.is_healthy("1.14.0", &config.readiness_file));
        assert!(!config.readiness_file.exists());
        runtime.stop(&config.readiness_file).unwrap();
        assert!(!runtime.is_healthy("1.14.0", &config.readiness_file));
        assert!(!config.readiness_file.exists());
        let _ = fs::remove_dir_all(root);
    }
}
