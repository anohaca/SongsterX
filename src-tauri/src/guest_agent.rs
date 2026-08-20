use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

const CONTROL_LINE_LIMIT: usize = 64 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const STARTUP_IO_SLICE: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestAgentEndpoint {
    pub host: String,
    pub port: u16,
    pub auth_token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestInterfaceStats {
    pub interface: String,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestPacketStats {
    pub lan: Option<GuestInterfaceStats>,
    pub tun: Option<GuestInterfaceStats>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestAgentStatus {
    pub agent_version: String,
    pub sing_box_version: String,
    pub active_version: String,
    pub staged_version: Option<String>,
    pub healthy: bool,
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub network_ready: bool,
    #[serde(default)]
    pub gateway_lan_ip: Option<String>,
    #[serde(default)]
    pub upstream_interface: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub config_sha256: Option<String>,
    #[serde(default)]
    pub packet_stats: Option<GuestPacketStats>,
}

pub(crate) fn status_is_ready(status: &GuestAgentStatus) -> bool {
    status.healthy && status.ready && status.network_ready
}

/// The agent deliberately stays available before the host has uploaded the
/// session config. Authentication plus guest network readiness is enough to
/// enter that bootstrap phase; full data-plane readiness is checked after
/// config activation with `status_is_ready`.
pub(crate) fn status_is_bootstrap_ready(status: &GuestAgentStatus) -> bool {
    !status.agent_version.trim().is_empty() && status.network_ready
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestUpgradeResult {
    pub version: String,
    pub sha256: String,
    pub size: u64,
    pub activated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestConfigResult {
    pub sha256: String,
    pub size: u64,
    pub activated: bool,
    pub packet_stats: Option<GuestPacketStats>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactMetadata {
    version: String,
    architecture: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigMetadata {
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct AgentResponse {
    ok: bool,
    #[serde(default)]
    state: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    status: Option<GuestAgentStatus>,
    #[serde(default)]
    healthy: bool,
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    metrics: Option<Value>,
    #[serde(default)]
    delay: Option<u64>,
    #[serde(default, rename = "packetStats")]
    packet_stats: Option<GuestPacketStats>,
}

impl GuestAgentEndpoint {
    pub(crate) fn address(&self) -> String {
        format!("{}:{}", self.host.trim(), self.port)
    }

    fn connect(&self, timeout: Duration) -> Result<TcpStream, String> {
        if self.host.trim().is_empty() || self.port == 0 {
            return Err("guest agent endpoint 无效".into());
        }
        validate_auth_token(&self.auth_token)?;
        let address = (self.host.trim(), self.port)
            .to_socket_addrs()
            .map_err(|error| format!("无法解析 guest agent 地址 {}：{error}", self.address()))?
            .next()
            .ok_or_else(|| format!("guest agent 地址没有可用解析结果：{}", self.address()))?;
        let stream = TcpStream::connect_timeout(&address, timeout)
            .map_err(|error| format!("无法连接 guest agent {}：{error}", self.address()))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("无法设置 guest agent 读取超时：{error}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| format!("无法设置 guest agent 写入超时：{error}"))?;
        Ok(stream)
    }

    fn connect_cancellable(
        &self,
        timeout: Duration,
        cancellation: &(dyn Fn() -> bool + Sync),
    ) -> Result<TcpStream, String> {
        if cancellation() {
            return Err("启动已取消".into());
        }
        let stream = self.connect(timeout.min(STARTUP_IO_SLICE))?;
        if cancellation() {
            return Err("启动已取消".into());
        }
        Ok(stream)
    }
}

pub(crate) fn sync_config(
    endpoint: &GuestAgentEndpoint,
    config_path: &Path,
    timeout: Duration,
) -> Result<GuestConfigResult, String> {
    fn never_cancelled() -> bool {
        false
    }

    sync_config_with_cancellation(endpoint, config_path, timeout, &never_cancelled)
}

pub(crate) fn sync_config_with_cancellation(
    endpoint: &GuestAgentEndpoint,
    config_path: &Path,
    timeout: Duration,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<GuestConfigResult, String> {
    if cancellation() {
        return Err("启动已取消".into());
    }
    let deadline = Instant::now() + timeout;
    let metadata = config_metadata(config_path)?;
    loop {
        if cancellation() {
            return Err("启动已取消".into());
        }
        match stage_config_and_upload(
            endpoint,
            config_path,
            &metadata,
            remaining_timeout(deadline)?,
            cancellation,
        ) {
            Ok(()) => break,
            Err(error) if is_retryable_io_timeout(&error) => continue,
            Err(error) => return Err(error),
        }
    }

    loop {
        if cancellation() {
            return Err("启动已取消".into());
        }
        let mut activate_stream =
            endpoint.connect_cancellable(remaining_timeout(deadline)?, cancellation)?;
        match request(
            endpoint,
            &mut activate_stream,
            &activate_config_request(&metadata),
        ) {
            Ok(response)
                if response.ok
                    && response.state == "active"
                    && response.healthy
                    && response.ready =>
            {
                return Ok(GuestConfigResult {
                    sha256: metadata.sha256.clone(),
                    size: metadata.size,
                    activated: true,
                    packet_stats: response.packet_stats,
                });
            }
            Ok(response) => {
                return resolve_config_failure(
                    endpoint,
                    &metadata,
                    remaining_timeout(deadline)?,
                    cancellation,
                    if response.message.is_empty() {
                        "guest sing-box 配置激活失败".to_string()
                    } else {
                        format!("guest sing-box 配置激活失败：{}", response.message)
                    },
                );
            }
            Err(error) if is_retryable_io_timeout(&error) => continue,
            Err(error) => {
                return resolve_config_failure(
                    endpoint,
                    &metadata,
                    remaining_timeout(deadline)?,
                    cancellation,
                    format!("guest sing-box 配置激活请求失败：{error}"),
                );
            }
        }
    }
}

fn remaining_timeout(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| "guest agent 配置操作超时".into())
}

fn is_retryable_io_timeout(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("timed out")
        || error.contains("would block")
        || error.contains("resource temporarily unavailable")
}

fn resolve_config_failure(
    endpoint: &GuestAgentEndpoint,
    metadata: &ConfigMetadata,
    timeout: Duration,
    cancellation: &(dyn Fn() -> bool + Sync),
    message: String,
) -> Result<GuestConfigResult, String> {
    if cancellation() {
        return Err("启动已取消".into());
    }
    let status = endpoint
        .connect_cancellable(timeout, cancellation)
        .and_then(|mut stream| {
            let response = request(endpoint, &mut stream, &json!({ "method": "status" }))?;
            if !response.ok {
                return Err(agent_error("status", &response));
            }
            response
                .status
                .ok_or_else(|| "guest agent status 响应缺少 status 字段".into())
        })
        .map_err(|error| format!("{message}；无法确认 guest 当前配置：{error}"))?;
    if status.config_sha256.as_deref() == Some(metadata.sha256.as_str()) && status_is_ready(&status)
    {
        return Ok(GuestConfigResult {
            sha256: metadata.sha256.clone(),
            size: metadata.size,
            activated: true,
            packet_stats: status.packet_stats,
        });
    }
    Err(format!("{message}；guest 未激活目标配置"))
}

pub(crate) fn query_status(
    endpoint: &GuestAgentEndpoint,
    timeout: Duration,
) -> Result<GuestAgentStatus, String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(endpoint, &mut stream, &json!({ "method": "status" }))?;
    if !response.ok {
        return Err(agent_error("status", &response));
    }
    response
        .status
        .ok_or_else(|| "guest agent status 响应缺少 status 字段".into())
}

pub(crate) fn query_connections(
    endpoint: &GuestAgentEndpoint,
    timeout: Duration,
) -> Result<Value, String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(endpoint, &mut stream, &json!({ "method": "connections" }))?;
    if !response.ok {
        return Err(agent_error("connections", &response));
    }
    response
        .metrics
        .ok_or_else(|| "guest agent connections 响应缺少 metrics 字段".into())
}

pub(crate) fn query_proxies(
    endpoint: &GuestAgentEndpoint,
    timeout: Duration,
) -> Result<Value, String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(endpoint, &mut stream, &json!({ "method": "proxies" }))?;
    if !response.ok {
        return Err(agent_error("proxies", &response));
    }
    response
        .metrics
        .ok_or_else(|| "guest agent proxies 响应缺少 metrics 字段".into())
}

pub(crate) fn select_proxy(
    endpoint: &GuestAgentEndpoint,
    group: &str,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(
        endpoint,
        &mut stream,
        &json!({ "method": "select_proxy", "group": group, "name": name }),
    )?;
    if response.ok {
        Ok(())
    } else {
        Err(agent_error("select_proxy", &response))
    }
}

pub(crate) fn test_proxy_delay(
    endpoint: &GuestAgentEndpoint,
    name: &str,
    url: &str,
    timeout_ms: u64,
    timeout: Duration,
) -> Result<u64, String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(
        endpoint,
        &mut stream,
        &json!({
            "method": "test_proxy_delay",
            "name": name,
            "url": url,
            "timeoutMs": timeout_ms,
        }),
    )?;
    if !response.ok {
        return Err(agent_error("test_proxy_delay", &response));
    }
    response
        .delay
        .ok_or_else(|| "guest agent 延迟响应缺少 delay 字段".into())
}

pub(crate) fn stop_guest_runtime(
    endpoint: &GuestAgentEndpoint,
    timeout: Duration,
) -> Result<(), String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(endpoint, &mut stream, &json!({ "method": "stop_runtime" }))?;
    if response.ok && response.state == "stopped" {
        Ok(())
    } else {
        Err(agent_error("stop_runtime", &response))
    }
}

pub(crate) fn upgrade_sing_box(
    endpoint: &GuestAgentEndpoint,
    artifact_path: &Path,
    version: &str,
    architecture: &str,
    timeout: Duration,
) -> Result<GuestUpgradeResult, String> {
    let metadata = artifact_metadata(artifact_path, version, architecture)?;
    stage_and_upload(endpoint, artifact_path, &metadata, timeout)?;

    let mut activate_stream = endpoint.connect(timeout)?;
    let activated = request(endpoint, &mut activate_stream, &activate_request(&metadata));
    match activated {
        Ok(response)
            if response.ok && response.state == "active" && response.healthy && response.ready =>
        {
            Ok(GuestUpgradeResult {
                version: metadata.version,
                sha256: metadata.sha256,
                size: metadata.size,
                activated: true,
            })
        }
        Ok(response) => resolve_activation_failure(
            endpoint,
            &metadata,
            timeout,
            if response.message.is_empty() {
                "guest sing-box 激活失败".to_string()
            } else {
                format!("guest sing-box 激活失败：{}", response.message)
            },
        ),
        Err(error) => resolve_activation_failure(
            endpoint,
            &metadata,
            timeout,
            format!("guest sing-box 激活请求失败：{error}"),
        ),
    }
}

fn resolve_activation_failure(
    endpoint: &GuestAgentEndpoint,
    metadata: &ArtifactMetadata,
    timeout: Duration,
    message: String,
) -> Result<GuestUpgradeResult, String> {
    let status = query_status(endpoint, timeout)
        .map_err(|error| format!("{message}；无法确认 guest 当前版本，未自动回滚：{error}"))?;
    if status.active_version != metadata.version {
        return Err(format!(
            "{message}；guest 当前仍是 {}，未重复回滚",
            if status.active_version.is_empty() {
                "未激活版本"
            } else {
                &status.active_version
            }
        ));
    }
    if status_is_ready(&status) {
        return Ok(GuestUpgradeResult {
            version: metadata.version.clone(),
            sha256: metadata.sha256.clone(),
            size: metadata.size,
            activated: true,
        });
    }
    let rollback_message = rollback(endpoint, timeout)
        .err()
        .map(|error| format!("；回滚也失败：{error}"))
        .unwrap_or_default();
    Err(format!("{message}；新版本不健康{rollback_message}"))
}

fn stage_and_upload(
    endpoint: &GuestAgentEndpoint,
    artifact_path: &Path,
    metadata: &ArtifactMetadata,
    timeout: Duration,
) -> Result<(), String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(endpoint, &mut stream, &stage_request(metadata))?;
    if !response.ok || response.state != "ready_for_upload" {
        return Err(agent_error("stage_upgrade", &response));
    }

    let mut artifact = File::open(artifact_path).map_err(|error| {
        format!(
            "无法打开 sing-box 升级文件 {}：{error}",
            artifact_path.display()
        )
    })?;
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut sent = 0_u64;
    loop {
        let read = artifact
            .read(&mut buffer)
            .map_err(|error| format!("读取 sing-box 升级文件失败：{error}"))?;
        if read == 0 {
            break;
        }
        stream
            .write_all(&buffer[..read])
            .map_err(|error| format!("上传 sing-box 升级文件失败：{error}"))?;
        sent += read as u64;
    }
    if sent != metadata.size {
        return Err(format!(
            "sing-box 升级文件大小在上传期间发生变化：预期 {}，实际 {}",
            metadata.size, sent
        ));
    }
    stream
        .flush()
        .map_err(|error| format!("刷新 sing-box 升级上传失败：{error}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|error| format!("复制 guest agent 读取连接失败：{error}"))?,
    );
    let response = read_response(&mut reader)?;
    if response.ok && response.state == "staged" {
        Ok(())
    } else {
        Err(agent_error("upload_upgrade", &response))
    }
}

fn stage_config_and_upload(
    endpoint: &GuestAgentEndpoint,
    config_path: &Path,
    metadata: &ConfigMetadata,
    timeout: Duration,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    let mut stream = endpoint.connect_cancellable(timeout, cancellation)?;
    if cancellation() {
        return Err("启动已取消".into());
    }
    let response = request(endpoint, &mut stream, &stage_config_request(metadata))?;
    if !response.ok || response.state != "ready_for_upload" {
        return Err(agent_error("stage_config", &response));
    }
    upload_file_with_cancellation(
        &mut stream,
        config_path,
        metadata.size,
        "sing-box 配置",
        cancellation,
    )?;
    stream
        .flush()
        .map_err(|error| format!("刷新 sing-box 配置上传失败：{error}"))?;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|error| format!("复制 guest agent 配置读取连接失败：{error}"))?,
    );
    let response = read_response(&mut reader)?;
    if response.ok && response.state == "staged" {
        Ok(())
    } else {
        Err(agent_error("upload_config", &response))
    }
}

fn upload_file_with_cancellation(
    stream: &mut TcpStream,
    path: &Path,
    expected_size: u64,
    label: &str,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    let mut file = File::open(path)
        .map_err(|error| format!("无法打开 {label} {}：{error}", path.display()))?;
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut sent = 0_u64;
    loop {
        if cancellation() {
            return Err("启动已取消".into());
        }
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("读取 {label} 失败：{error}"))?;
        if read == 0 {
            break;
        }
        stream
            .write_all(&buffer[..read])
            .map_err(|error| format!("上传 {label} 失败：{error}"))?;
        sent += read as u64;
    }
    if sent != expected_size {
        return Err(format!(
            "{label} 大小在上传期间发生变化：预期 {expected_size}，实际 {sent}"
        ));
    }
    Ok(())
}

fn rollback(endpoint: &GuestAgentEndpoint, timeout: Duration) -> Result<(), String> {
    let mut stream = endpoint.connect(timeout)?;
    let response = request(endpoint, &mut stream, &json!({ "method": "rollback" }))?;
    if response.ok {
        Ok(())
    } else {
        Err(agent_error("rollback", &response))
    }
}

fn request(
    endpoint: &GuestAgentEndpoint,
    stream: &mut TcpStream,
    value: &Value,
) -> Result<AgentResponse, String> {
    let line = serialize_authenticated_request(value, &endpoint.auth_token)?;
    stream
        .write_all(&line)
        .map_err(|error| format!("发送 guest agent 请求失败：{error}"))?;
    stream
        .flush()
        .map_err(|error| format!("刷新 guest agent 请求失败：{error}"))?;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|error| format!("复制 guest agent 读取连接失败：{error}"))?,
    );
    read_response(&mut reader)
}

fn stage_request(metadata: &ArtifactMetadata) -> Value {
    json!({
        "method": "stage_upgrade",
        "version": metadata.version,
        "architecture": metadata.architecture,
        "size": metadata.size,
        "sha256": metadata.sha256,
    })
}

fn stage_config_request(metadata: &ConfigMetadata) -> Value {
    json!({
        "method": "stage_config",
        "configSize": metadata.size,
        "configSha256": metadata.sha256,
    })
}

fn activate_request(metadata: &ArtifactMetadata) -> Value {
    json!({
        "method": "activate_upgrade",
        "version": metadata.version,
        "sha256": metadata.sha256,
    })
}

fn activate_config_request(metadata: &ConfigMetadata) -> Value {
    json!({
        "method": "activate_config",
        "configSize": metadata.size,
        "configSha256": metadata.sha256,
    })
}

fn serialize_request(value: &Value) -> Result<Vec<u8>, String> {
    let mut line = serde_json::to_vec(value)
        .map_err(|error| format!("序列化 guest agent 请求失败：{error}"))?;
    line.push(b'\n');
    if line.len() > CONTROL_LINE_LIMIT {
        return Err("guest agent 请求超过 64 KiB 限制".into());
    }
    Ok(line)
}

fn serialize_authenticated_request(value: &Value, auth_token: &str) -> Result<Vec<u8>, String> {
    validate_auth_token(auth_token)?;
    let object = value
        .as_object()
        .ok_or_else(|| "guest agent 请求必须是 JSON object".to_string())?;
    let mut authenticated = object.clone();
    authenticated.insert("auth".into(), Value::String(auth_token.into()));
    serialize_request(&Value::Object(authenticated))
}

fn validate_auth_token(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.len() < 32 || value.len() > 256 || !value.bytes().all(|item| item.is_ascii_graphic()) {
        return Err("guest agent token 必须是 32-256 个 ASCII 可打印字符".into());
    }
    Ok(())
}

fn read_response(reader: &mut BufReader<TcpStream>) -> Result<AgentResponse, String> {
    let mut line = Vec::new();
    let size = reader
        .read_until(b'\n', &mut line)
        .map_err(|error| format!("读取 guest agent 响应失败：{error}"))?;
    if size == 0 {
        return Err("guest agent 在返回响应前关闭了连接".into());
    }
    if size > CONTROL_LINE_LIMIT {
        return Err("guest agent 响应超过 64 KiB 限制".into());
    }
    serde_json::from_slice(&line).map_err(|error| format!("guest agent 响应不是有效 JSON：{error}"))
}

fn agent_error(method: &str, response: &AgentResponse) -> String {
    if response.message.is_empty() {
        format!("guest agent {method} 请求失败")
    } else {
        format!("guest agent {method} 请求失败：{}", response.message)
    }
}

fn artifact_metadata(
    path: &Path,
    version: &str,
    architecture: &str,
) -> Result<ArtifactMetadata, String> {
    validate_version(version)?;
    if architecture.trim().is_empty() || architecture.contains('/') || architecture.contains('\\') {
        return Err("sing-box 升级架构标识无效".into());
    }
    let file = File::open(path)
        .map_err(|error| format!("无法打开 sing-box 升级文件 {}：{error}", path.display()))?;
    let size = file
        .metadata()
        .map_err(|error| format!("无法读取 sing-box 升级文件大小：{error}"))?
        .len();
    if size == 0 {
        return Err("sing-box 升级文件不能为空".into());
    }
    let sha256 = sha256_file(file)?;
    Ok(ArtifactMetadata {
        version: version.trim().into(),
        architecture: architecture.trim().into(),
        size,
        sha256,
    })
}

fn config_metadata(path: &Path) -> Result<ConfigMetadata, String> {
    let file = File::open(path)
        .map_err(|error| format!("无法打开 sing-box 配置 {}：{error}", path.display()))?;
    let size = file
        .metadata()
        .map_err(|error| format!("无法读取 sing-box 配置大小：{error}"))?
        .len();
    if size == 0 || size > 16 * 1024 * 1024 {
        return Err("sing-box 配置大小必须在 1-16777216 字节之间".into());
    }
    Ok(ConfigMetadata {
        size,
        sha256: sha256_file(file)?,
    })
}

fn sha256_file(mut file: File) -> Result<String, String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("计算 sing-box 升级文件 SHA-256 失败：{error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_version(version: &str) -> Result<(), String> {
    let version = version.trim();
    if version.is_empty() || version.len() > 128 || version.contains('/') || version.contains('\\')
    {
        return Err("sing-box 升级版本标识无效".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_file(contents: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "songsterx-sing-box-upgrade-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn artifact_metadata_is_streamed_and_hashed() {
        let fixture = b"sing-box-test-binary";
        let path = temp_file(fixture);
        let metadata = artifact_metadata(&path, "1.14.0", "arm64").unwrap();
        assert_eq!(metadata.size, fixture.len() as u64);
        assert_eq!(metadata.architecture, "arm64");
        assert_eq!(metadata.sha256.len(), 64);
        assert!(artifact_metadata(&path, "../bad", "arm64").is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn endpoint_address_is_stable() {
        let endpoint = GuestAgentEndpoint {
            host: "192.168.250.2".into(),
            port: 38291,
            auth_token: "a".repeat(32),
        };
        assert_eq!(endpoint.address(), "192.168.250.2:38291");
    }

    #[test]
    fn readiness_requires_both_healthy_and_ready() {
        let mut status = GuestAgentStatus {
            agent_version: "1".into(),
            sing_box_version: "1".into(),
            active_version: "1".into(),
            staged_version: None,
            healthy: true,
            ready: false,
            network_ready: false,
            gateway_lan_ip: None,
            upstream_interface: None,
            last_error: None,
            config_sha256: None,
            packet_stats: None,
        };
        assert!(!status_is_ready(&status));
        status.ready = true;
        status.network_ready = true;
        assert!(status_is_ready(&status));
        status.healthy = false;
        assert!(!status_is_ready(&status));
    }

    #[test]
    fn bootstrap_readiness_allows_missing_session_config() {
        let status = GuestAgentStatus {
            agent_version: "0.1.0".into(),
            sing_box_version: String::new(),
            active_version: String::new(),
            staged_version: None,
            healthy: false,
            ready: false,
            network_ready: true,
            gateway_lan_ip: Some("192.168.1.2".into()),
            upstream_interface: Some("eth0".into()),
            last_error: Some("sing-box 配置文件不存在".into()),
            config_sha256: None,
            packet_stats: None,
        };
        assert!(status_is_bootstrap_ready(&status));
        assert!(!status_is_ready(&status));
    }

    #[test]
    fn upgrade_requests_are_line_delimited_and_include_integrity_metadata() {
        let path = temp_file(b"small-sing-box-binary");
        let metadata = artifact_metadata(&path, "1.14.0", "arm64").unwrap();
        let stage = serialize_request(&stage_request(&metadata)).unwrap();
        let activate = serialize_request(&activate_request(&metadata)).unwrap();
        assert_eq!(stage.last(), Some(&b'\n'));
        assert_eq!(activate.last(), Some(&b'\n'));
        let stage = String::from_utf8(stage).unwrap();
        let activate = String::from_utf8(activate).unwrap();
        assert!(stage.contains("\"method\":\"stage_upgrade\""));
        assert!(stage.contains("\"architecture\":\"arm64\""));
        assert!(stage.contains(&format!("\"sha256\":\"{}\"", metadata.sha256)));
        assert!(activate.contains("\"method\":\"activate_upgrade\""));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn authenticated_requests_include_the_shared_token() {
        let token = "a".repeat(32);
        let request =
            serialize_authenticated_request(&json!({ "method": "status" }), &token).unwrap();
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains(&format!("\"auth\":\"{token}\"")));
        assert!(serialize_authenticated_request(&json!({ "method": "status" }), "short").is_err());
    }

    #[test]
    fn config_requests_include_size_and_integrity_metadata() {
        let metadata = ConfigMetadata {
            size: 12,
            sha256: "b".repeat(64),
        };
        let stage = serialize_request(&stage_config_request(&metadata)).unwrap();
        let activate = serialize_request(&activate_config_request(&metadata)).unwrap();
        let stage = String::from_utf8(stage).unwrap();
        let activate = String::from_utf8(activate).unwrap();
        assert!(stage.contains("\"method\":\"stage_config\""));
        assert!(stage.contains("\"configSize\":12"));
        assert!(stage.contains(&format!("\"configSha256\":\"{}\"", metadata.sha256)));
        assert!(activate.contains("\"method\":\"activate_config\""));
    }

    #[test]
    fn startup_io_slice_errors_are_retryable_but_protocol_errors_are_not() {
        assert!(is_retryable_io_timeout(
            "读取 guest agent 响应失败：timed out"
        ));
        assert!(is_retryable_io_timeout(
            "读取 guest agent 响应失败：Resource temporarily unavailable"
        ));
        assert!(!is_retryable_io_timeout("guest sing-box 配置激活失败"));
    }
}
