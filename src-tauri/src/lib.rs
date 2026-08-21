use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{path::BaseDirectory, AppHandle, Emitter, Manager, State};

// The supervisor owns the Gateway process graph. The data-plane acceptance
// state is tracked separately and only becomes ready after post-start LAN and
// tun0 counter deltas are observed.
#[allow(dead_code)]
mod gateway_runtime;
mod guest_agent;
// Readiness dimensions include the guest packet-path acceptance state.
#[allow(dead_code)]
mod packet_path;
// Process-group ownership is exercised by unit tests before real Gateway launch is enabled.
#[allow(dead_code)]
mod process_group;
mod vfkit;

const SONGSTERX_CONFIG_FILE: &str = "songsterx.conf";
const RUNTIME_CONFIG_FILE: &str = "sing-box.runtime.json";
const GATEWAY_GUEST_RUNTIME_CONFIG_FILE: &str = "sing-box.gateway-guest.json";
const GATEWAY_GUEST_PROXY_CONFIG_FILE: &str = "proxy-config.gateway-guest.json";
const MODULE_RUNTIME_PLAN_FILE: &str = "module-runtime-plan.json";
const IMPORTED_MODULES_FILE: &str = "imported-modules.json";
const IMPORTED_ASSETS_FILE: &str = "imported-module-assets.json";
const IMPORTED_MODULES_DIR: &str = "modules";
const CLASH_API_ADDR: &str = "127.0.0.1:9090";
const DEFAULT_MODULE_PROXY_PORT: u16 = 8080;
const FALLBACK_MODULE_PROXY_PORT_START: u16 = 18080;
const FALLBACK_MODULE_PROXY_PORT_END: u16 = 18089;
const GATEWAY_AGENT_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const GATEWAY_CONFIG_SYNC_TIMEOUT: Duration = Duration::from_secs(15);
const GATEWAY_AGENT_STOP_TIMEOUT: Duration = Duration::from_millis(250);
const MITM_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Release gate for the IPv4 VM guest packet path.
///
/// The supervisor may start after validating its runtime prerequisites. The
/// runtime status remains in a waiting state until a real LAN client produces
/// traffic through both the guest LAN interface and tun0.
const GATEWAY_GUEST_PACKET_PATH_RELEASE_GATE: bool = true;
const GATEWAY_PACKET_PATH_UNAVAILABLE: &str =
    "局域网 Gateway 数据面等待验收：请让 LAN 客户端访问一次网络，确认 LAN 与 tun0 都出现新增流量";

pub struct RuntimeState {
    child: Mutex<Option<Child>>,
    mitm_child: Mutex<Option<Child>>,
    gateway_transition: Mutex<()>,
    lifecycle_phase: Mutex<LifecyclePhase>,
    lifecycle_generation: Arc<AtomicU64>,
    gateway_runtime: Mutex<Option<gateway_runtime::GatewayRuntime>>,
    gateway_readiness: Mutex<packet_path::GatewayReadiness>,
    gateway_packet_baseline: Mutex<Option<guest_agent::GuestPacketStats>>,
    system_connections: Mutex<SystemConnectionSample>,
    metrics_session: Mutex<Option<MetricsSession>>,
    status: Mutex<RuntimeStatus>,
    metrics_generation: Arc<AtomicU64>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
            mitm_child: Mutex::new(None),
            gateway_transition: Mutex::new(()),
            lifecycle_phase: Mutex::new(LifecyclePhase::Stopped),
            lifecycle_generation: Arc::new(AtomicU64::new(0)),
            gateway_runtime: Mutex::new(None),
            gateway_readiness: Mutex::new(packet_path::GatewayReadiness::default()),
            gateway_packet_baseline: Mutex::new(None),
            system_connections: Mutex::new(SystemConnectionSample::default()),
            metrics_session: Mutex::new(None),
            status: Mutex::new(RuntimeStatus::default()),
            metrics_generation: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LifecyclePhase {
    Stopped,
    Starting,
    Running,
    Stopping,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub state: String,
    pub healthy: bool,
    #[serde(rename = "canStop")]
    pub can_stop: bool,
    pub mode: String,
    pub listen: String,
    pub dns: String,
    #[serde(rename = "vmGatewayIp")]
    pub gateway_ip: Option<String>,
    #[serde(rename = "vmGatewayDnsIp")]
    pub gateway_dns_ip: Option<String>,
    #[serde(rename = "gatewayPacketPathReady")]
    pub gateway_packet_path_ready: bool,
    pub pid: Option<u32>,
    pub module_proxy: Option<String>,
    pub message: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSettings {
    pub mode: String,
    pub listen: String,
    pub port: u16,
    pub dns_mode: String,
    pub dns_server: String,
    pub sing_box_path: String,
    pub vmnet_helper_path: String,
    #[serde(default)]
    pub vfkit_path: String,
    #[serde(default)]
    pub gateway_guest_kernel_path: String,
    #[serde(default)]
    pub gateway_guest_initrd_path: String,
    #[serde(default)]
    pub gateway_guest_cmdline: String,
    #[serde(default = "default_gateway_guest_cpus")]
    pub gateway_guest_cpus: u8,
    #[serde(default = "default_gateway_guest_memory_mib")]
    pub gateway_guest_memory_mib: u32,
    #[serde(default = "default_gateway_host_ip")]
    pub gateway_host_ip: String,
    #[serde(default = "default_gateway_guest_host_ip")]
    pub gateway_guest_host_ip: String,
    #[serde(default = "default_gateway_host_cidr")]
    pub gateway_host_cidr: String,
    #[serde(default = "default_gateway_guest_agent_port")]
    pub gateway_guest_agent_port: u16,
    #[serde(default)]
    pub gateway_guest_lan_selector: String,
    #[serde(default)]
    pub gateway_guest_host_selector: String,
    #[serde(default)]
    pub gateway_upstream_gateway: String,
    pub gateway_lan_interface: String,
    pub gateway_ip: String,
    pub gateway_cidr: String,
    pub gateway_dns_ip: String,
    #[serde(default)]
    pub gateway_clients: String,
    #[serde(default = "default_gateway_client_policy")]
    pub gateway_client_policy: String,
    #[serde(default = "default_gateway_policy_mode")]
    pub gateway_policy_mode: String,
    #[serde(default)]
    pub mitm_ca_dir: String,
    pub log_level: String,
}

fn default_gateway_client_policy() -> String {
    "all".into()
}

fn default_gateway_policy_mode() -> String {
    "shared".into()
}

fn default_gateway_guest_cpus() -> u8 {
    vfkit::DEFAULT_GATEWAY_GUEST_CPUS
}

fn default_gateway_guest_memory_mib() -> u32 {
    vfkit::DEFAULT_GATEWAY_GUEST_MEMORY_MIB
}

fn default_gateway_host_ip() -> String {
    vfkit::DEFAULT_GATEWAY_HOST_IP.into()
}

fn default_gateway_guest_host_ip() -> String {
    vfkit::DEFAULT_GATEWAY_GUEST_HOST_IP.into()
}

fn default_gateway_host_cidr() -> String {
    vfkit::DEFAULT_GATEWAY_HOST_CIDR.into()
}

fn default_gateway_guest_agent_port() -> u16 {
    vfkit::DEFAULT_GATEWAY_GUEST_AGENT_PORT
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            mode: "mixed".into(),
            listen: "127.0.0.1".into(),
            port: 2080,
            dns_mode: "system".into(),
            dns_server: "223.5.5.5".into(),
            sing_box_path: String::new(),
            vmnet_helper_path: String::new(),
            vfkit_path: String::new(),
            gateway_guest_kernel_path: String::new(),
            gateway_guest_initrd_path: String::new(),
            gateway_guest_cmdline: "console=hvc0 quiet".into(),
            gateway_guest_cpus: vfkit::DEFAULT_GATEWAY_GUEST_CPUS,
            gateway_guest_memory_mib: vfkit::DEFAULT_GATEWAY_GUEST_MEMORY_MIB,
            gateway_host_ip: vfkit::DEFAULT_GATEWAY_HOST_IP.into(),
            gateway_guest_host_ip: vfkit::DEFAULT_GATEWAY_GUEST_HOST_IP.into(),
            gateway_host_cidr: vfkit::DEFAULT_GATEWAY_HOST_CIDR.into(),
            gateway_guest_agent_port: vfkit::DEFAULT_GATEWAY_GUEST_AGENT_PORT,
            gateway_guest_lan_selector: vfkit::DEFAULT_GATEWAY_GUEST_LAN_SELECTOR.into(),
            gateway_guest_host_selector: vfkit::DEFAULT_GATEWAY_GUEST_HOST_SELECTOR.into(),
            gateway_upstream_gateway: String::new(),
            gateway_lan_interface: String::new(),
            gateway_ip: String::new(),
            gateway_cidr: String::new(),
            gateway_dns_ip: String::new(),
            gateway_clients: String::new(),
            gateway_client_policy: default_gateway_client_policy(),
            gateway_policy_mode: default_gateway_policy_mode(),
            mitm_ca_dir: String::new(),
            log_level: "info".into(),
        }
    }
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            state: "stopped".into(),
            healthy: false,
            can_stop: false,
            mode: "mixed direct".into(),
            listen: "127.0.0.1:2080".into(),
            dns: "系统 DNS".into(),
            gateway_ip: None,
            gateway_dns_ip: None,
            gateway_packet_path_ready: false,
            pid: None,
            module_proxy: None,
            message: "尚未启动".into(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeLog {
    timestamp: String,
    timestamp_us: u64,
    level: String,
    message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeMetrics {
    upload_total: u64,
    download_total: u64,
    active_connections: usize,
    memory: u64,
    connections: Vec<ConnectionInfo>,
    host_snapshot_valid: bool,
    host_snapshot_error: Option<String>,
    guest_snapshot_valid: bool,
    guest_snapshot_error: Option<String>,
    system_snapshot_valid: bool,
    system_snapshot_error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleInfo {
    id: String,
    name: String,
    description: String,
    version: String,
    local_file: String,
    source: String,
    sha256: String,
    verified: bool,
    enabled: bool,
    sections: Vec<String>,
    script_assets: Vec<String>,
    mitm_hostnames: Vec<String>,
    rule_count: usize,
    script_count: usize,
    runtime_status: String,
    warning: String,
    arguments: Vec<ModuleArgumentInfo>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleArgumentInfo {
    name: String,
    default_value: String,
    value: String,
    description: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MitmCertificateInfo {
    available: bool,
    path: String,
    client_note: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ModulePreference {
    id: String,
    enabled: bool,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct ModulePreferences {
    modules: Vec<ModulePreference>,
    #[serde(default)]
    argument_values: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct ModuleManifestEntry {
    id: String,
    source: String,
    local_file: String,
    sha256: String,
    sections: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ImportedFile {
    name: String,
    content: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigDocument {
    id: String,
    title: String,
    path: String,
    content: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigReloadResult {
    settings: RuntimeSettings,
    proxy_config: ProxyConfig,
    modules: Vec<ModuleInfo>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ModuleAssetManifest {
    assets: Vec<ModuleAssetEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ModuleAssetEntry {
    kind: String,
    module: String,
    source: String,
    local_file: String,
    sha256: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ModuleRuntimePlan {
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mitm_ca_pem: Option<String>,
    enabled_modules: Vec<String>,
    module_files: Vec<serde_json::Value>,
    mitm_hostnames: Vec<String>,
    static_rules: Vec<serde_json::Value>,
    url_rewrites: Vec<serde_json::Value>,
    map_locals: Vec<serde_json::Value>,
    header_rewrites: Vec<serde_json::Value>,
    disabled_sections: Vec<String>,
    disabled_scripts: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionInfo {
    id: String,
    runtime: String,
    source: String,
    destination: String,
    host: String,
    network: String,
    outbound: String,
    upload: Option<u64>,
    download: Option<u64>,
    start: String,
    #[serde(default)]
    process: String,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    state: String,
    #[serde(rename = "systemSocketKey", skip_serializing_if = "Option::is_none")]
    system_socket_key: Option<String>,
}

#[derive(Clone, Default)]
#[allow(dead_code)]
struct SystemConnectionSample {
    connections: Vec<ConnectionInfo>,
    valid: bool,
    error: Option<String>,
}

#[derive(Default)]
struct SystemConnectionIdentityState {
    active_instances: HashMap<String, String>,
    next_generation: u64,
}

fn default_tls_enabled() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ProxyNode {
    tag: String,
    #[serde(rename = "type")]
    kind: String,
    server: String,
    server_port: u16,
    #[serde(default)]
    server_ports: String,
    #[serde(default)]
    hop_interval: String,
    #[serde(default)]
    hop_interval_max: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    ws_path: String,
    #[serde(default)]
    ws_host: String,
    #[serde(default)]
    transport_method: String,
    #[serde(default)]
    transport_service_name: String,
    #[serde(default)]
    transport_headers: String,
    #[serde(default)]
    transport_idle_timeout: String,
    #[serde(default)]
    transport_ping_timeout: String,
    #[serde(default)]
    transport_permit_without_stream: bool,
    #[serde(default)]
    transport_max_early_data: u32,
    #[serde(default)]
    transport_early_data_header_name: String,
    #[serde(default)]
    transport_quic_security: String,
    #[serde(default)]
    transport_quic_key: String,
    #[serde(default = "default_tls_enabled")]
    tls_enabled: bool,
    #[serde(default)]
    tls_engine: String,
    #[serde(default)]
    tls_disable_sni: bool,
    #[serde(default)]
    tls_alpn: String,
    #[serde(default)]
    tls_min_version: String,
    #[serde(default)]
    tls_max_version: String,
    #[serde(default)]
    tls_certificate_path: String,
    #[serde(default)]
    tls_certificate_public_key_sha256: String,
    #[serde(default)]
    tls_handshake_timeout: String,
    #[serde(default)]
    tls_utl_fingerprint: String,
    #[serde(default)]
    tls_reality_public_key: String,
    #[serde(default)]
    tls_reality_short_id: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    plugin: String,
    #[serde(default)]
    plugin_options: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    packet_encoding: String,
    #[serde(default)]
    security: String,
    #[serde(default)]
    alter_id: u16,
    #[serde(default)]
    version: u8,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    private_key_path: String,
    #[serde(default)]
    peer_public_key: String,
    #[serde(default)]
    pre_shared_key: String,
    #[serde(default)]
    local_address: String,
    #[serde(default)]
    wireguard_system_interface: bool,
    #[serde(default)]
    wireguard_interface_name: String,
    #[serde(default)]
    wireguard_mtu: u16,
    #[serde(default)]
    wireguard_workers: u16,
    #[serde(default)]
    wireguard_network: String,
    #[serde(default)]
    wireguard_reserved: String,
    #[serde(default)]
    up_mbps: u32,
    #[serde(default)]
    down_mbps: u32,
    #[serde(default)]
    up_bandwidth: String,
    #[serde(default)]
    down_bandwidth: String,
    #[serde(default)]
    auth_base64: String,
    #[serde(default)]
    obfs: String,
    #[serde(default)]
    obfs_password: String,
    #[serde(default)]
    congestion_control: String,
    #[serde(default)]
    udp_relay_mode: String,
    #[serde(default)]
    zero_rtt_handshake: bool,
    #[serde(default)]
    heartbeat: String,
    #[serde(default)]
    tuic_udp_over_stream: bool,
    #[serde(default)]
    idle_session_check_interval: String,
    #[serde(default)]
    idle_session_expiration: String,
    #[serde(default)]
    min_idle_session: u16,
    #[serde(default)]
    psk: String,
    #[serde(default)]
    snell_userkey: String,
    #[serde(default)]
    snell_reuse: bool,
    #[serde(default)]
    snell_obfs_mode: String,
    #[serde(default)]
    snell_obfs_host: String,
    #[serde(default)]
    snell_mode: String,
    #[serde(default)]
    ssh_private_key: String,
    #[serde(default)]
    ssh_private_key_passphrase: String,
    #[serde(default)]
    ssh_host_key: String,
    #[serde(default)]
    ssh_host_key_algorithms: String,
    #[serde(default)]
    ssh_client_version: String,
    #[serde(default)]
    ssh_cipher: String,
    #[serde(default)]
    ssh_mac: String,
    #[serde(default)]
    ssh_kex_algorithm: String,
    #[serde(default)]
    executable_path: String,
    #[serde(default)]
    data_directory: String,
    #[serde(default)]
    tor_args: String,
    #[serde(default)]
    anytls_client_metadata: String,
    #[serde(default)]
    detour: String,
    #[serde(default)]
    bind_interface: String,
    #[serde(default)]
    inet4_bind_address: String,
    #[serde(default)]
    inet6_bind_address: String,
    #[serde(default)]
    bind_address_no_port: bool,
    #[serde(default)]
    routing_mark: u32,
    #[serde(default)]
    reuse_addr: bool,
    #[serde(default)]
    connect_timeout: String,
    #[serde(default)]
    tcp_fast_open: bool,
    #[serde(default)]
    tcp_multi_path: bool,
    #[serde(default)]
    disable_tcp_keep_alive: bool,
    #[serde(default)]
    tcp_keep_alive: String,
    #[serde(default)]
    tcp_keep_alive_interval: String,
    #[serde(default)]
    udp_fragment: bool,
    #[serde(default)]
    domain_resolver: String,
    #[serde(default)]
    network_strategy: String,
    #[serde(default)]
    network_type: String,
    #[serde(default)]
    fallback_network_type: String,
    #[serde(default)]
    fallback_delay: String,
    #[serde(default)]
    domain_strategy: String,
    #[serde(default)]
    multiplex_enabled: bool,
    #[serde(default)]
    multiplex_protocol: String,
    #[serde(default)]
    multiplex_max_connections: u16,
    #[serde(default)]
    multiplex_min_streams: u16,
    #[serde(default)]
    multiplex_max_streams: u16,
    #[serde(default)]
    multiplex_padding: bool,
    #[serde(default)]
    multiplex_brutal: String,
    #[serde(default)]
    extra_json: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PolicyGroup {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    members: Vec<String>,
    #[serde(default)]
    default: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    interval: String,
    #[serde(default)]
    tolerance: u16,
    #[serde(default)]
    idle_timeout: String,
    #[serde(default)]
    interrupt_exist_connections: bool,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RuleCondition {
    #[serde(default)]
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    field: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    invert: bool,
    #[serde(default)]
    rules: Vec<RuleCondition>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RuleSetConfig {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
    #[serde(default)]
    format: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    update_interval: String,
}

fn default_true() -> bool {
    true
}

fn default_route_action() -> String {
    "route".into()
}

fn default_direct_outbound() -> String {
    "direct".into()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyRule {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_route_action")]
    action: String,
    #[serde(default = "default_direct_outbound")]
    outbound: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition: Option<RuleCondition>,
    // Legacy flat-rule fields. They are read for migration and omitted when
    // the normalized tree is serialized again.
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    legacy_kind: String,
    #[serde(rename = "value", default, skip_serializing_if = "String::is_empty")]
    legacy_value: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyConfig {
    nodes: Vec<ProxyNode>,
    groups: Vec<PolicyGroup>,
    rules: Vec<ProxyRule>,
    #[serde(default)]
    rule_sets: Vec<RuleSetConfig>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            nodes: vec![],
            groups: vec![PolicyGroup {
                name: "Final".into(),
                kind: "selector".into(),
                members: vec!["direct".into()],
                default: "direct".into(),
                ..Default::default()
            }],
            rules: vec![],
            rule_sets: vec![],
        }
    }
}

fn now_timestamp() -> (String, u64) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_micros() as u64)
        .unwrap_or_default();
    let seconds = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    (format!("unix:{seconds}.{fraction:06}"), micros)
}

fn emit_log(app: &AppHandle, level: &str, message: impl Into<String>) {
    let (timestamp, timestamp_us) = now_timestamp();
    let _ = app.emit(
        "runtime-log",
        RuntimeLog {
            timestamp,
            timestamp_us,
            level: level.into(),
            message: message.into(),
        },
    );
}

fn update_status(state: &RuntimeState, next: RuntimeStatus) {
    if let Ok(mut status) = state.status.lock() {
        *status = next;
    }
}

fn lock_gateway_transition(state: &RuntimeState) -> MutexGuard<'_, ()> {
    state
        .gateway_transition
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn current_status(state: &RuntimeState) -> Result<RuntimeStatus, String> {
    state
        .status
        .lock()
        .map(|status| status.clone())
        .map_err(|_| "状态锁不可用".to_string())
}

fn lifecycle_cancelled(state: &RuntimeState, generation: u64) -> bool {
    state.lifecycle_generation.load(Ordering::SeqCst) != generation
        || state
            .lifecycle_phase
            .lock()
            .map(|phase| *phase != LifecyclePhase::Starting)
            .unwrap_or(true)
}

fn lifecycle_starting_status(settings: &RuntimeSettings) -> RuntimeStatus {
    let gateway_mode = settings.mode == "gateway";
    RuntimeStatus {
        state: "starting".into(),
        healthy: false,
        can_stop: false,
        mode: if gateway_mode {
            "lan-gateway no-dhcp"
        } else {
            "mixed direct"
        }
        .into(),
        listen: format!("{}:{}", settings.listen.trim(), settings.port),
        dns: dns_status(settings),
        gateway_ip: gateway_mode.then(|| settings.gateway_ip.trim().to_string()),
        gateway_dns_ip: gateway_mode.then(|| {
            if settings.gateway_dns_ip.trim().is_empty() {
                if settings.dns_mode == "fakeip" {
                    "198.18.0.2".into()
                } else {
                    settings.gateway_ip.trim().into()
                }
            } else {
                settings.gateway_dns_ip.trim().into()
            }
        }),
        gateway_packet_path_ready: false,
        pid: None,
        module_proxy: None,
        message: if gateway_mode {
            "正在启动 Mixed + 局域网网关（无 DHCP）".into()
        } else {
            "正在启动 Mixed 直连".into()
        },
    }
}

fn begin_lifecycle_start(state: &RuntimeState) -> Result<Option<u64>, String> {
    let mut phase = state
        .lifecycle_phase
        .lock()
        .map_err(|_| "Gateway 生命周期锁不可用".to_string())?;
    match *phase {
        LifecyclePhase::Starting | LifecyclePhase::Stopping => return Ok(None),
        LifecyclePhase::Running => return Ok(None),
        LifecyclePhase::Stopped => {
            *phase = LifecyclePhase::Starting;
        }
    }
    Ok(Some(
        state.lifecycle_generation.fetch_add(1, Ordering::SeqCst) + 1,
    ))
}

fn mark_lifecycle_phase(state: &RuntimeState, phase: LifecyclePhase) {
    if let Ok(mut current) = state.lifecycle_phase.lock() {
        *current = phase;
    }
}

fn runtime_owns_resources(state: &RuntimeState) -> bool {
    state
        .gateway_runtime
        .lock()
        .map(|slot| slot.is_some())
        .unwrap_or(true)
        || state
            .mitm_child
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(true)
        || state
            .child
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(true)
}

fn complete_start_success(state: &RuntimeState, generation: u64, next: RuntimeStatus) -> bool {
    let Ok(mut phase) = state.lifecycle_phase.lock() else {
        return false;
    };
    if *phase != LifecyclePhase::Starting
        || state.lifecycle_generation.load(Ordering::SeqCst) != generation
    {
        return false;
    }
    *phase = LifecyclePhase::Running;
    update_status(state, next);
    true
}

fn finish_cancelled_start(state: &RuntimeState) {
    let Ok(mut phase) = state.lifecycle_phase.lock() else {
        return;
    };
    if *phase == LifecyclePhase::Starting {
        *phase = LifecyclePhase::Stopped;
        update_status(state, set_stopped(state, "启动已取消"));
    }
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|error| format!("无法定位应用数据目录：{error}"))
}

fn module_root(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(root) = env::var("SONGSTERX_MODULE_ROOT") {
        let path = PathBuf::from(root);
        if path.is_dir() {
            return Ok(path);
        }
    }
    let root = app_data_dir(app)?.join(IMPORTED_MODULES_DIR);
    fs::create_dir_all(&root)
        .map_err(|error| format!("无法创建模块目录 {}：{error}", root.display()))?;
    Ok(root)
}

fn mitm_certificate_path(app: &AppHandle) -> Result<PathBuf, String> {
    let settings = load_settings(app).unwrap_or_default();
    let directory = mitmproxy_confdir(app, &settings)?;
    for filename in ["mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem"] {
        let path = directory.join(filename);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(format!(
        "SongsterX MITM 根证书尚未生成：{}",
        directory.display()
    ))
}

fn load_mitm_ca_for_guest(app: &AppHandle) -> Result<Option<String>, String> {
    let settings = load_settings(app).unwrap_or_default();
    let configured = settings.mitm_ca_dir.trim();
    let directory = if configured.is_empty() {
        app_data_dir(app)?.join("mitmproxy")
    } else {
        PathBuf::from(configured)
    };
    let ca_path = directory.join("mitmproxy-ca.pem");
    match fs::read_to_string(&ca_path) {
        Ok(ca_pem) => {
            if !ca_pem.contains("PRIVATE KEY") || !ca_pem.contains("CERTIFICATE") {
                return Err(format!(
                    "{} 必须同时包含 MITM CA 证书和私钥",
                    ca_path.display()
                ));
            }
            Ok(Some(ca_pem))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && configured.is_empty() => Ok(None),
        Err(error) => Err(format!(
            "无法读取用于 guest Module Engine 的 MITM CA {}：{}",
            ca_path.display(),
            error
        )),
    }
}

fn persist_guest_mitm_certificate(app: &AppHandle, certificate_pem: &str) -> Result<(), String> {
    if !certificate_pem.contains("BEGIN CERTIFICATE") {
        return Err("guest Module Engine 返回的 MITM 证书格式无效".into());
    }
    let settings = load_settings(app).unwrap_or_default();
    let directory = if settings.mitm_ca_dir.trim().is_empty() {
        app_data_dir(app)?.join("mitmproxy")
    } else {
        PathBuf::from(settings.mitm_ca_dir.trim())
    };
    fs::create_dir_all(&directory)
        .map_err(|error| format!("无法创建 MITM 证书目录 {}：{error}", directory.display()))?;
    let path = directory.join("mitmproxy-ca-cert.pem");
    write_private_file(&path, certificate_pem.as_bytes())
        .map_err(|error| format!("无法保存 guest MITM 根证书 {}：{error}", path.display()))
}

fn mitmproxy_confdir(app: &AppHandle, settings: &RuntimeSettings) -> Result<PathBuf, String> {
    let configured = settings.mitm_ca_dir.trim();
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        if !path.is_dir() {
            return Err(format!(
                "已有 MITM CA 目录不存在或不是目录：{}",
                path.display()
            ));
        }
        let ca_path = path.join("mitmproxy-ca.pem");
        let ca = fs::read_to_string(&ca_path).map_err(|error| {
            format!(
                "已有 MITM CA 目录缺少 mitmproxy-ca.pem：{} ({error})",
                ca_path.display()
            )
        })?;
        if !ca.contains("PRIVATE KEY") || !ca.contains("CERTIFICATE") {
            return Err(format!(
                "{} 必须同时包含 CA 证书和私钥；只有 .cer/.crt 公钥证书不能用于 MITM",
                ca_path.display()
            ));
        }
        return Ok(path);
    }
    let directory = app_data_dir(app)?.join("mitmproxy");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("无法创建 mitmproxy 配置目录：{error}"))?;
    Ok(directory)
}

fn imported_modules_manifest_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(IMPORTED_MODULES_FILE))
}

fn imported_assets_manifest_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(IMPORTED_ASSETS_FILE))
}

fn load_imported_manifest(app: &AppHandle) -> Result<Vec<ModuleManifestEntry>, String> {
    let path = imported_modules_manifest_path(app)?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取导入模块清单 {}：{error}", path.display()))?;
    serde_json::from_str(&content).map_err(|error| format!("导入模块清单格式错误：{error}"))
}

fn persist_imported_manifest(
    app: &AppHandle,
    manifest: &[ModuleManifestEntry],
) -> Result<(), String> {
    let directory = app_data_dir(app)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let path = imported_modules_manifest_path(app)?;
    let content = serde_json::to_string_pretty(manifest)
        .map_err(|error| format!("无法序列化导入模块清单：{error}"))?;
    write_private_file(&path, format!("{content}\n").as_bytes())
        .map_err(|error| format!("无法保存导入模块清单 {}：{error}", path.display()))
}

fn load_imported_assets(app: &AppHandle) -> Result<Vec<ModuleAssetEntry>, String> {
    let path = imported_assets_manifest_path(app)?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取导入模块资源清单 {}：{error}", path.display()))?;
    let manifest: ModuleAssetManifest = serde_json::from_str(&content)
        .map_err(|error| format!("导入模块资源清单格式错误：{error}"))?;
    Ok(manifest.assets)
}

fn persist_imported_assets(app: &AppHandle, assets: &[ModuleAssetEntry]) -> Result<(), String> {
    let directory = app_data_dir(app)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let path = imported_assets_manifest_path(app)?;
    let manifest = ModuleAssetManifest {
        assets: assets.to_vec(),
    };
    let content = serde_json::to_string_pretty(&manifest)
        .map_err(|error| format!("无法序列化导入模块资源清单：{error}"))?;
    write_private_file(&path, format!("{content}\n").as_bytes())
        .map_err(|error| format!("无法保存导入模块资源清单 {}：{error}", path.display()))
}

#[cfg(test)]
fn manifest_value(line: &str, key: &str) -> Option<String> {
    line.trim()
        .strip_prefix(&format!("{key}:"))
        .map(|value| value.trim().trim_matches('"').to_string())
}

#[cfg(test)]
fn parse_sections(value: &str) -> Vec<String> {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(test)]
fn parse_module_manifest(path: &PathBuf) -> Result<Vec<ModuleManifestEntry>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("无法读取模块清单 {}：{error}", path.display()))?;
    let mut entries = Vec::new();
    let mut current: Option<ModuleManifestEntry> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(id) = trimmed.strip_prefix("- id:") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = Some(ModuleManifestEntry {
                id: id.trim().to_string(),
                ..Default::default()
            });
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        if let Some(value) = manifest_value(trimmed, "source") {
            entry.source = value;
        } else if let Some(value) = manifest_value(trimmed, "local_file") {
            entry.local_file = value;
        } else if let Some(value) = manifest_value(trimmed, "sha256") {
            entry.sha256 = value;
        } else if let Some(value) = manifest_value(trimmed, "sections") {
            entry.sections = parse_sections(&value);
        }
    }
    if let Some(entry) = current {
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err("模块清单为空".into());
    }
    Ok(entries)
}

fn sha256_file(path: &PathBuf) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("无法读取 {}：{error}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn parse_module_source(
    content: &str,
) -> (
    String,
    String,
    String,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    usize,
    usize,
) {
    let mut name = String::new();
    let mut description = String::new();
    let mut version = String::new();
    let mut section = String::new();
    let mut sections = Vec::new();
    let mut script_sources = Vec::new();
    let mut hostnames = Vec::new();
    let mut rule_count = 0;
    let mut script_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("#!name") {
            name = value.trim_start_matches([' ', '=']).trim().to_string();
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("#!desc") {
            description = value
                .trim_start_matches([' ', '='])
                .trim()
                .replace("\\n", "\n");
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("#!version") {
            version = value.trim_start_matches([' ', '=']).trim().to_string();
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.trim_matches(['[', ']']).to_string();
            if !sections.contains(&section) {
                sections.push(section.clone());
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(path) = trimmed.split("script-path=").nth(1) {
            let source = path.split(',').next().unwrap_or(path).trim().to_string();
            if !source.is_empty() && !script_sources.contains(&source) {
                script_sources.push(source);
            }
        }
        if section == "MITM" && trimmed.starts_with("hostname") {
            if let Some(value) = trimmed.split('=').nth(1) {
                for hostname in value.split(',') {
                    let hostname = hostname.trim().trim_start_matches("%APPEND%").trim();
                    if !hostname.is_empty() && !hostnames.contains(&hostname.to_string()) {
                        hostnames.push(hostname.to_string());
                    }
                }
            }
        }
        if matches!(
            section.as_str(),
            "Rule" | "URL Rewrite" | "Map Local" | "Body Rewrite" | "Header Rewrite"
        ) {
            rule_count += 1;
        }
        if section == "Script" {
            script_count += 1;
        }
    }
    (
        name,
        description,
        version,
        sections,
        script_sources,
        hostnames,
        rule_count,
        script_count,
    )
}

fn module_option(line: &str, key: &str) -> Option<String> {
    let marker = format!("{key}=");
    let start = line.find(&marker)? + marker.len();
    let remainder = &line[start..];
    if remainder.starts_with('"') {
        let bytes = remainder.as_bytes();
        for index in 1..bytes.len() {
            if bytes[index] == b'"'
                && (index + 1 == bytes.len() || bytes[index + 1].is_ascii_whitespace())
            {
                return Some(remainder[1..index].to_string());
            }
        }
        Some(remainder.trim_start_matches('"').to_string())
    } else {
        Some(
            remainder
                .split(|character: char| character.is_whitespace() || character == ',')
                .next()
                .unwrap_or_default()
                .to_string(),
        )
    }
}

fn module_asset_references(content: &str) -> Vec<(String, String)> {
    let mut references = Vec::new();
    let mut section = String::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']).trim().to_string();
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let reference = match section.as_str() {
            "Script" => {
                module_option(line, "script-path").map(|value| ("script".to_string(), value))
            }
            "Rule" => {
                let fields: Vec<&str> = line.split(',').map(str::trim).collect();
                if fields
                    .first()
                    .map(|value| value.eq_ignore_ascii_case("RULE-SET"))
                    == Some(true)
                {
                    fields
                        .get(1)
                        .map(|value| ("rule-set".to_string(), (*value).to_string()))
                } else {
                    None
                }
            }
            "Map Local" => module_option(line, "data").and_then(|value| {
                if value.starts_with("http://")
                    || value.starts_with("https://")
                    || value.starts_with('{')
                    || value.starts_with('[')
                {
                    None
                } else {
                    Some(("data".to_string(), value))
                }
            }),
            _ => None,
        };
        if let Some((kind, source)) = reference {
            if !source.is_empty()
                && !references.iter().any(|(known_kind, known_source)| {
                    known_kind == &kind && known_source == &source
                })
            {
                references.push((kind, source));
            }
        }
    }
    references
}

fn safe_module_filename(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
            result.push(character.to_ascii_lowercase());
        } else if !result.ends_with('-') {
            result.push('-');
        }
        if result.len() >= 48 {
            break;
        }
    }
    result.trim_matches('-').to_string()
}

fn safe_asset_filename(value: &str) -> String {
    let basename = value.rsplit(['/', '\\']).next().unwrap_or(value);
    let mut result = String::new();
    for character in basename.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
            result.push(character);
        } else if !result.ends_with('-') {
            result.push('-');
        }
        if result.len() >= 120 {
            break;
        }
    }
    let result = result.trim_matches('-').to_string();
    if result.is_empty() {
        "asset.bin".into()
    } else {
        result
    }
}

fn asset_basename(source: &str) -> String {
    source
        .split('?')
        .next()
        .unwrap_or(source)
        .rsplit('/')
        .next()
        .unwrap_or(source)
        .trim()
        .to_string()
}

fn split_module_options(value: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut depth = 0usize;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current_quote) = quote {
            if character == current_quote {
                quote = None;
            }
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '{' || character == '[' {
            depth += 1;
        } else if character == '}' || character == ']' {
            depth = depth.saturating_sub(1);
        } else if character == ',' && depth == 0 {
            result.push(value[start..index].trim().to_string());
            start = index + character.len_utf8();
        }
    }
    result.push(value[start..].trim().to_string());
    result.into_iter().filter(|part| !part.is_empty()).collect()
}

fn parse_module_arguments(content: &str) -> Vec<(String, String)> {
    let mut arguments = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if !(line.starts_with("#!arguments") && !line.starts_with("#!arguments-desc")) {
            continue;
        }
        let Some((_, values)) = line.split_once('=') else {
            continue;
        };
        for entry in split_module_options(values) {
            let Some((name, default_value)) = entry.split_once(':') else {
                continue;
            };
            let name = name.trim().to_string();
            if name.is_empty() || arguments.iter().any(|(known, _)| known == &name) {
                continue;
            }
            arguments.push((name, default_value.trim().trim_matches('"').to_string()));
        }
    }
    arguments
}

fn parse_module_argument_descriptions(content: &str) -> BTreeMap<String, String> {
    let Some(raw_value) = content.lines().map(str::trim).find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with("#!arguments-desc") {
            return None;
        }
        line.split_once('=')
            .map(|(_, value)| value.trim().to_string())
    }) else {
        return BTreeMap::new();
    };

    let value = raw_value.replace("\\n", "\n");
    value
        .split("\n\n")
        .filter_map(|block| {
            let block = block.trim();
            let (name, description) = block.split_once(':')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), description.trim().to_string()))
        })
        .collect()
}

fn module_rule_action(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "REJECT" | "REJECT-DROP" | "REJECT-TINYGIF" => Some("reject"),
        "DIRECT" => Some("direct"),
        _ => None,
    }
}

fn module_push_unique(values: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !value.is_empty() && !values.iter().any(|known| known == &value) {
        values.push(value);
    }
}

fn module_static_rule(module: &str, kind: &str, value: &str, action: &str) -> serde_json::Value {
    serde_json::json!({
        "module": module,
        "kind": kind,
        "value": value,
        "action": action
    })
}

fn parse_module_rule_line(
    module: &str,
    line: &str,
    default_action: Option<&str>,
    plan: &mut ModuleRuntimePlan,
) {
    let fields: Vec<&str> = line.split(',').map(str::trim).collect();
    if fields.len() < 2 {
        return;
    }
    let kind = fields[0].to_ascii_uppercase();
    let action = fields
        .get(2)
        .and_then(|value| module_rule_action(value))
        .or(default_action);
    let Some(action) = action else { return };
    let value = fields[1].trim();
    if value.is_empty() {
        return;
    }
    let normalized_kind = match kind.as_str() {
        "DOMAIN" => "domain",
        "DOMAIN-SUFFIX" => "domain_suffix",
        "DOMAIN-KEYWORD" => "domain_keyword",
        "IP-CIDR" | "IP-CIDR6" => "ip_cidr",
        "URL-REGEX" => "url_regex",
        _ => return,
    };
    plan.static_rules
        .push(module_static_rule(module, normalized_kind, value, action));
}

fn parse_module_runtime_source(
    entry: &ModuleManifestEntry,
    content: &str,
    module_root: &Path,
    assets: &[ModuleAssetEntry],
    plan: &mut ModuleRuntimePlan,
) {
    let mut section = String::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']).trim().to_string();
            continue;
        }
        match section.as_str() {
            "MITM" => {
                if line.starts_with("hostname") {
                    if let Some((_, values)) = line.split_once('=') {
                        for hostname in values.split(',') {
                            let hostname = hostname.trim().trim_start_matches("%APPEND%").trim();
                            module_push_unique(&mut plan.mitm_hostnames, hostname.to_string());
                        }
                    }
                }
            }
            "Rule" => {
                let fields: Vec<&str> = line.split(',').map(str::trim).collect();
                if fields
                    .first()
                    .map(|value| value.eq_ignore_ascii_case("RULE-SET"))
                    == Some(true)
                {
                    let source = fields.get(1).copied().unwrap_or_default();
                    let action = fields.get(2).and_then(|value| module_rule_action(value));
                    if let Some(asset) = assets.iter().find(|asset| {
                        asset.module == entry.id
                            && asset.kind == "rule-set"
                            && asset.source == source
                    }) {
                        let relative = asset
                            .local_file
                            .strip_prefix("modules/")
                            .unwrap_or(&asset.local_file);
                        let path = module_root.join(relative);
                        if let Ok(rule_set) = fs::read_to_string(&path) {
                            for rule in rule_set
                                .lines()
                                .map(str::trim)
                                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                            {
                                parse_module_rule_line(&entry.id, rule, action, plan);
                            }
                        }
                    } else {
                        module_push_unique(
                            &mut plan.disabled_sections,
                            format!("{}:RULE-SET", entry.id),
                        );
                    }
                } else {
                    parse_module_rule_line(&entry.id, line, None, plan);
                }
            }
            "URL Rewrite" => {
                let mut fields = line.split_whitespace();
                let Some(pattern) = fields.next() else {
                    continue;
                };
                let rest = fields.collect::<Vec<_>>().join(" ");
                if rest.eq_ignore_ascii_case("- reject") {
                    plan.url_rewrites.push(serde_json::json!({
                        "module": entry.id,
                        "pattern": pattern.trim_matches('"'),
                        "action": "reject"
                    }));
                } else {
                    let mut rest_fields = rest.splitn(2, char::is_whitespace);
                    let first = rest_fields.next().unwrap_or_default();
                    let replacement = rest_fields.next().unwrap_or_default().trim();
                    if let Ok(status) = first.parse::<u16>() {
                        if (300..400).contains(&status) && !replacement.is_empty() {
                            plan.url_rewrites.push(serde_json::json!({
                                "module": entry.id,
                                "pattern": pattern.trim_matches('"'),
                                "action": "redirect",
                                "status": status,
                                "replacement": replacement.trim_matches('"')
                            }));
                        }
                    } else if !rest.is_empty() {
                        plan.url_rewrites.push(serde_json::json!({
                            "module": entry.id,
                            "pattern": pattern.trim_matches('"'),
                            "action": "replace",
                            "replacement": rest.trim_matches('"')
                        }));
                    }
                }
            }
            "Map Local" => {
                let Some(pattern) = line.split_whitespace().next() else {
                    continue;
                };
                let data = module_option(line, "data");
                let data_type = module_option(line, "data-type").unwrap_or_else(|| "text".into());
                let header = module_option(line, "header");
                let mut map = serde_json::json!({
                    "module": entry.id,
                    "pattern": pattern.trim_matches('"'),
                    "dataType": data_type,
                });
                if let Some(data) = data {
                    let asset_path = assets
                        .iter()
                        .find(|asset| {
                            asset.module == entry.id && asset.kind == "data" && asset.source == data
                        })
                        .map(|asset| {
                            let relative = asset
                                .local_file
                                .strip_prefix("modules/")
                                .unwrap_or(&asset.local_file);
                            module_root.join(relative).display().to_string()
                        });
                    if let Some(path) = asset_path {
                        map["localPath"] = serde_json::Value::String(path);
                        if let Some(asset) = assets.iter().find(|asset| {
                            asset.module == entry.id && asset.kind == "data" && asset.source == data
                        }) {
                            let relative = asset
                                .local_file
                                .strip_prefix("modules/")
                                .unwrap_or(&asset.local_file);
                            if let Ok(bytes) = fs::read(module_root.join(relative)) {
                                map["inlineDataBase64"] =
                                    serde_json::Value::String(base64_encode(&bytes));
                            }
                        }
                    } else if data.starts_with("http://") || data.starts_with("https://") {
                        map["disabledReason"] =
                            serde_json::Value::String("远程数据未找到本地哈希资源".into());
                    } else {
                        map["inlineData"] = serde_json::Value::String(data);
                    }
                }
                if let Some(header) = header {
                    map["header"] = serde_json::Value::String(header);
                }
                plan.map_locals.push(map);
            }
            "Header Rewrite" => {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 4 {
                    let operation = fields[2].trim().to_ascii_lowercase();
                    if matches!(
                        operation.as_str(),
                        "header-del" | "header-add" | "header-replace"
                    ) {
                        plan.header_rewrites.push(serde_json::json!({
                            "module": entry.id,
                            "phase": fields[0],
                            "pattern": fields[1].trim_matches('"'),
                            "operation": operation,
                            "name": fields[3],
                            "value": fields.get(4..).map(|values| values.join(" ")).unwrap_or_default()
                        }));
                    }
                }
            }
            "Script" | "Body Rewrite" => {}
            _ => {}
        }
    }
}

fn load_module_preferences(app: &AppHandle) -> Result<ModulePreferences, String> {
    let Some(config) = read_songsterx_user_config(app)? else {
        return Ok(ModulePreferences::default());
    };
    let mut preferences = ModulePreferences::default();
    for module in config.modules {
        preferences.modules.push(ModulePreference {
            id: module.id.clone(),
            enabled: module.enabled,
        });
        if !module.argument_values.is_empty() {
            preferences
                .argument_values
                .insert(module.id, module.argument_values);
        }
    }
    Ok(preferences)
}

fn persist_module_preferences(
    app: &AppHandle,
    preferences: &ModulePreferences,
) -> Result<(), String> {
    let settings = load_settings(app)?;
    let config = load_proxy_config(app)?;
    let modules = load_modules_with_preferences(app, preferences)?;
    write_songsterx_config(app, &settings, &config, &modules)
}

fn load_modules(app: &AppHandle) -> Result<Vec<ModuleInfo>, String> {
    let preferences = load_module_preferences(app)?;
    load_modules_with_preferences(app, &preferences)
}

fn load_modules_with_preferences(
    app: &AppHandle,
    preferences: &ModulePreferences,
) -> Result<Vec<ModuleInfo>, String> {
    let module_root = module_root(app)?;
    let manifest = load_imported_manifest(app)?;
    let assets = load_imported_assets(app)?;

    manifest
        .into_iter()
        .map(|entry| {
            let relative = entry
                .local_file
                .strip_prefix("modules/")
                .unwrap_or(&entry.local_file);
            let path = module_root.join(relative);
            let source_content = fs::read_to_string(&path)
                .map_err(|error| format!("无法读取模块 {}：{error}", path.display()))?;
            let (
                name,
                description,
                version,
                parsed_sections,
                script_sources,
                hostnames,
                rule_count,
                script_count,
            ) = parse_module_source(&source_content);
            let argument_descriptions = parse_module_argument_descriptions(&source_content);
            let arguments = parse_module_arguments(&source_content)
                .into_iter()
                .map(|(name, default_value)| {
                    let value = preferences
                        .argument_values
                        .get(&entry.id)
                        .and_then(|values| values.get(&name))
                        .cloned()
                        .unwrap_or_else(|| default_value.clone());
                    ModuleArgumentInfo {
                        description: argument_descriptions
                            .get(&name)
                            .cloned()
                            .unwrap_or_default(),
                        value,
                        name,
                        default_value,
                    }
                })
                .collect();
            let module_hash = sha256_file(&path)?;
            let mut script_assets = Vec::new();
            let mut assets_verified = true;
            let mut warning_parts = Vec::new();
            for source in script_sources {
                if let Some(asset) = assets.iter().find(|asset| {
                    asset.module == entry.id && asset.kind == "script" && asset.source == source
                }) {
                    let asset_relative = asset
                        .local_file
                        .strip_prefix("modules/")
                        .unwrap_or(&asset.local_file);
                    let asset_path = module_root.join(asset_relative);
                    match sha256_file(&asset_path) {
                        Ok(hash) if hash == asset.sha256 => {
                            script_assets.push(asset.local_file.clone())
                        }
                        Ok(_) => {
                            assets_verified = false;
                            warning_parts.push(format!("资源校验失败：{}", asset.local_file));
                        }
                        Err(error) => {
                            assets_verified = false;
                            warning_parts.push(error);
                        }
                    }
                } else {
                    assets_verified = false;
                    warning_parts.push(format!("未收录脚本资源：{source}"));
                }
            }
            let verified = module_hash == entry.sha256 && assets_verified;
            if module_hash != entry.sha256 {
                warning_parts.push("模块文件 SHA-256 不匹配".into());
            }
            let enabled = preferences
                .modules
                .iter()
                .find(|item| item.id == entry.id)
                .map(|item| item.enabled)
                .unwrap_or(false);
            let has_static_or_http = parsed_sections.iter().any(|section| {
                matches!(
                    section.as_str(),
                    "Rule" | "URL Rewrite" | "Map Local" | "Header Rewrite" | "MITM"
                )
            });
            let runtime_status = if script_count > 0 && has_static_or_http {
                "静态、HTTP 与 Script 已接入".to_string()
            } else if script_count > 0 {
                "MITM 与 Script 已接入".to_string()
            } else if has_static_or_http {
                "静态与 HTTP 规则已接入".to_string()
            } else {
                "可进入静态规则适配".to_string()
            };
            Ok(ModuleInfo {
                id: entry.id,
                name: if name.is_empty() {
                    "未命名模块".into()
                } else {
                    name
                },
                description,
                version,
                local_file: entry.local_file,
                source: entry.source,
                sha256: entry.sha256,
                verified,
                enabled,
                sections: if parsed_sections.is_empty() {
                    entry.sections
                } else {
                    parsed_sections
                },
                script_assets,
                mitm_hostnames: hostnames,
                rule_count,
                script_count,
                runtime_status,
                warning: warning_parts.join("；"),
                arguments,
            })
        })
        .collect()
}

fn load_module_runtime_plan(app: &AppHandle) -> Result<ModuleRuntimePlan, String> {
    let module_root = module_root(app)?;
    let manifest = load_imported_manifest(app)?;
    let assets = load_imported_assets(app)?;
    let modules = load_modules(app)?;
    let preferences = load_module_preferences(app)?;
    let mut plan = ModuleRuntimePlan {
        version: 2,
        ..Default::default()
    };

    for entry in manifest {
        let Some(module) = modules.iter().find(|module| module.id == entry.id) else {
            continue;
        };
        if !module.enabled || !module.verified {
            continue;
        }
        let relative = entry
            .local_file
            .strip_prefix("modules/")
            .unwrap_or(&entry.local_file);
        let path = module_root.join(relative);
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("无法读取已启用模块 {}：{error}", path.display()))?;
        module_push_unique(&mut plan.enabled_modules, entry.id.clone());
        let mut module_file = serde_json::json!({
            "id": entry.id,
            "path": path.display().to_string(),
            "content": source,
            "arguments": preferences.argument_values.get(&entry.id).cloned().unwrap_or_default()
        });
        let embedded_assets = assets
            .iter()
            .filter(|asset| asset.module == entry.id)
            .filter_map(|asset| {
                let relative = asset
                    .local_file
                    .strip_prefix("modules/")
                    .unwrap_or(&asset.local_file);
                let asset_path = module_root.join(relative);
                let bytes = fs::read(&asset_path).ok()?;
                Some(serde_json::json!({
                    "kind": asset.kind,
                    "source": asset.source,
                    "contentBase64": base64_encode(&bytes),
                    "sha256": asset.sha256,
                }))
            })
            .collect::<Vec<_>>();
        module_file["assets"] = serde_json::Value::Array(embedded_assets);
        plan.module_files.push(module_file);
        parse_module_runtime_source(&entry, &source, &module_root, &assets, &mut plan);
    }
    if module_plan_requires_mitm(&plan) {
        plan.mitm_ca_pem = load_mitm_ca_for_guest(app)?;
    }
    Ok(plan)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(third & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn module_runtime_plan_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(MODULE_RUNTIME_PLAN_FILE))
}

fn write_module_runtime_plan(app: &AppHandle) -> Result<ModuleRuntimePlan, String> {
    let plan = load_module_runtime_plan(app)?;
    persist_module_runtime_plan(app, &plan)?;
    Ok(plan)
}

fn persist_module_runtime_plan(app: &AppHandle, plan: &ModuleRuntimePlan) -> Result<(), String> {
    let directory = app_data_dir(app)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let path = module_runtime_plan_path(app)?;
    let content = serde_json::to_string_pretty(plan)
        .map_err(|error| format!("无法序列化模块运行计划：{error}"))?;
    write_private_file(&path, format!("{content}\n").as_bytes())
        .map_err(|error| format!("无法写入模块运行计划 {}：{error}", path.display()))?;
    Ok(())
}

fn module_route_rules(plan: &ModuleRuntimePlan) -> Vec<serde_json::Value> {
    plan.static_rules
        .iter()
        .filter_map(|rule| {
            let kind = rule["kind"].as_str()?;
            let field = match kind {
                "domain" | "domain_suffix" | "domain_keyword" | "ip_cidr" => kind,
                // sing-box route rules do not match a full URL regex. Keep
                // these rules in the MITM plan instead of emitting invalid
                // sing-box JSON.
                _ => return None,
            };
            let value = rule["value"].as_str()?.to_string();
            let action = rule["action"].as_str()?;
            let mut rendered = serde_json::json!({ field: [value] });
            match action {
                "reject" => rendered["action"] = serde_json::Value::String("reject".into()),
                "direct" => {
                    rendered["action"] = serde_json::Value::String("route".into());
                    rendered["outbound"] = serde_json::Value::String("direct".into());
                }
                _ => return None,
            }
            Some(rendered)
        })
        .collect()
}

fn module_mitm_route_rules(plan: &ModuleRuntimePlan) -> Vec<serde_json::Value> {
    let mut rules = Vec::new();
    let mut known_hosts = Vec::new();
    for hostname in &plan.mitm_hostnames {
        let hostname = hostname.trim().trim_start_matches('%').to_string();
        if hostname.is_empty() || known_hosts.iter().any(|known| known == &hostname) {
            continue;
        }
        known_hosts.push(hostname.clone());
        let (field, value) = if let Some(suffix) = hostname.strip_prefix("*.") {
            ("domain_suffix", suffix.to_string())
        } else if let Some(suffix) = hostname.strip_prefix('*') {
            ("domain_suffix", suffix.trim_start_matches('.').to_string())
        } else {
            ("domain", hostname.clone())
        };
        let rendered = serde_json::json!({
            field: [value],
            "network": ["tcp"],
            "action": "route",
            "outbound": "module-mitm"
        });
        rules.push(rendered);
    }
    rules
}

fn runtime_config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(RUNTIME_CONFIG_FILE))
}

fn gateway_guest_runtime_config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(GATEWAY_GUEST_RUNTIME_CONFIG_FILE))
}

fn gateway_guest_proxy_config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(GATEWAY_GUEST_PROXY_CONFIG_FILE))
}

fn songsterx_config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(SONGSTERX_CONFIG_FILE))
}

fn surge_config_value(value: &str) -> String {
    if value.is_empty()
        || value.contains(',')
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('"')
        || value.contains('\\')
        || value.contains('#')
        || value.contains('=')
        || value.contains("&&")
        || value.contains("||")
        || value.contains('(')
        || value.contains(')')
        || value.trim() != value
        || value.chars().any(char::is_whitespace)
    {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn config_unquote_value(value: &str) -> String {
    let value = value.trim();
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    let value = if quoted {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let mut result = String::with_capacity(value.len());
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            let decoded = match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            };
            if !matches!(character, 'n' | 'r' | 't' | '"' | '\\' | '\'') {
                result.push('\\');
            }
            result.push(decoded);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            result.push(character);
        }
    }
    if escaped {
        result.push('\\');
    }
    result
}

fn split_config_fields(value: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push('\\');
            current.push(character);
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            current.push(character);
            escaped = true;
            continue;
        }
        if let Some(current_quote) = quote {
            if character == current_quote {
                quote = None;
            }
            current.push(character);
            continue;
        }
        if character == '"' || character == '\'' {
            quote = Some(character);
            current.push(character);
        } else if character == ',' {
            fields.push(config_unquote_value(&current));
            current.clear();
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err("配置字段包含未闭合的引号或转义符".into());
    }
    fields.push(config_unquote_value(&current));
    Ok(fields)
}

fn strip_config_comment(value: &str) -> (String, String) {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current_quote) = quote {
            if character == current_quote {
                quote = None;
            }
        } else if character == '"' || character == '\'' {
            quote = Some(character);
        } else if character == '#' {
            return (
                value[..index].trim().to_string(),
                value[index + 1..].trim().to_string(),
            );
        }
    }
    (value.trim().to_string(), String::new())
}

fn split_config_option(value: &str) -> Option<(String, String)> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current_quote) = quote {
            if character == current_quote {
                quote = None;
            }
        } else if character == '"' || character == '\'' {
            quote = Some(character);
        } else if character == '=' {
            return Some((
                value[..index].trim().to_string(),
                config_unquote_value(&value[index + 1..]),
            ));
        }
    }
    None
}

fn kebab_to_camel(value: &str) -> String {
    let mut result = String::new();
    let mut uppercase = false;
    for character in value.chars() {
        if character == '-' || character == '_' {
            uppercase = true;
        } else if uppercase {
            result.extend(character.to_uppercase());
            uppercase = false;
        } else {
            result.push(character);
        }
    }
    result
}

fn proxy_option_name(key: &str) -> String {
    match key {
        "tlsEnabled" => "tls".into(),
        "insecure" => "skip-cert-verify".into(),
        "pluginOptions" => "plugin-opts".into(),
        "serverPorts" => "server-ports".into(),
        "hopInterval" => "hop-interval".into(),
        "hopIntervalMax" => "hop-interval-max".into(),
        "transportMethod" => "transport-method".into(),
        "transportServiceName" => "transport-service-name".into(),
        "transportHeaders" => "transport-headers".into(),
        "transportIdleTimeout" => "transport-idle-timeout".into(),
        "transportPingTimeout" => "transport-ping-timeout".into(),
        "transportPermitWithoutStream" => "transport-permit-without-stream".into(),
        "transportMaxEarlyData" => "transport-max-early-data".into(),
        "transportEarlyDataHeaderName" => "transport-early-data-header-name".into(),
        "transportQuicSecurity" => "transport-quic-security".into(),
        "transportQuicKey" => "transport-quic-key".into(),
        "tlsDisableSni" => "tls-disable-sni".into(),
        "tlsAlpn" => "tls-alpn".into(),
        "tlsMinVersion" => "tls-min-version".into(),
        "tlsMaxVersion" => "tls-max-version".into(),
        "tlsCertificatePath" => "tls-certificate-path".into(),
        "tlsCertificatePublicKeySha256" => "tls-certificate-public-key-sha256".into(),
        "tlsHandshakeTimeout" => "tls-handshake-timeout".into(),
        "tlsUtlFingerprint" => "tls-utl-fingerprint".into(),
        "tlsRealityPublicKey" => "tls-reality-public-key".into(),
        "tlsRealityShortId" => "tls-reality-short-id".into(),
        "packetEncoding" => "packet-encoding".into(),
        "alterId" => "alter-id".into(),
        "privateKey" => "private-key".into(),
        "privateKeyPath" => "private-key-path".into(),
        "peerPublicKey" => "peer-public-key".into(),
        "preSharedKey" => "pre-shared-key".into(),
        "localAddress" => "local-address".into(),
        "wireguardSystemInterface" => "wireguard-system-interface".into(),
        "wireguardInterfaceName" => "wireguard-interface-name".into(),
        "wireguardMtu" => "wireguard-mtu".into(),
        "wireguardWorkers" => "wireguard-workers".into(),
        "wireguardNetwork" => "wireguard-network".into(),
        "wireguardReserved" => "wireguard-reserved".into(),
        "upMbps" => "up-mbps".into(),
        "downMbps" => "down-mbps".into(),
        "upBandwidth" => "up-bandwidth".into(),
        "downBandwidth" => "down-bandwidth".into(),
        "authBase64" => "auth-base64".into(),
        "obfsPassword" => "obfs-password".into(),
        "congestionControl" => "congestion-control".into(),
        "udpRelayMode" => "udp-relay-mode".into(),
        "zeroRttHandshake" => "zero-rtt-handshake".into(),
        "tuicUdpOverStream" => "tuic-udp-over-stream".into(),
        "idleSessionCheckInterval" => "idle-session-check-interval".into(),
        "idleSessionExpiration" => "idle-session-expiration".into(),
        "minIdleSession" => "min-idle-session".into(),
        "snellUserkey" => "snell-userkey".into(),
        "snellObfsMode" => "snell-obfs-mode".into(),
        "snellObfsHost" => "snell-obfs-host".into(),
        "snellMode" => "snell-mode".into(),
        "sshPrivateKey" => "ssh-private-key".into(),
        "sshPrivateKeyPassphrase" => "ssh-private-key-passphrase".into(),
        "sshHostKey" => "ssh-host-key".into(),
        "sshHostKeyAlgorithms" => "ssh-host-key-algorithms".into(),
        "sshClientVersion" => "ssh-client-version".into(),
        "sshCipher" => "ssh-cipher".into(),
        "sshMac" => "ssh-mac".into(),
        "sshKexAlgorithm" => "ssh-kex-algorithm".into(),
        "executablePath" => "executable-path".into(),
        "dataDirectory" => "data-directory".into(),
        "torArgs" => "tor-args".into(),
        "anytlsClientMetadata" => "anytls-client-metadata".into(),
        "bindInterface" => "bind-interface".into(),
        "inet4BindAddress" => "inet4-bind-address".into(),
        "inet6BindAddress" => "inet6-bind-address".into(),
        "bindAddressNoPort" => "bind-address-no-port".into(),
        "routingMark" => "routing-mark".into(),
        "reuseAddr" => "reuse-addr".into(),
        "connectTimeout" => "connect-timeout".into(),
        "tcpFastOpen" => "tcp-fast-open".into(),
        "tcpMultiPath" => "tcp-multi-path".into(),
        "disableTcpKeepAlive" => "disable-tcp-keep-alive".into(),
        "tcpKeepAlive" => "tcp-keep-alive".into(),
        "tcpKeepAliveInterval" => "tcp-keep-alive-interval".into(),
        "udpFragment" => "udp-fragment".into(),
        "domainResolver" => "domain-resolver".into(),
        "networkStrategy" => "network-strategy".into(),
        "networkType" => "network-type".into(),
        "fallbackNetworkType" => "fallback-network-type".into(),
        "fallbackDelay" => "fallback-delay".into(),
        "domainStrategy" => "domain-strategy".into(),
        "multiplexEnabled" => "multiplex-enabled".into(),
        "multiplexProtocol" => "multiplex-protocol".into(),
        "multiplexMaxConnections" => "multiplex-max-connections".into(),
        "multiplexMinStreams" => "multiplex-min-streams".into(),
        "multiplexMaxStreams" => "multiplex-max-streams".into(),
        "multiplexPadding" => "multiplex-padding".into(),
        "multiplexBrutal" => "multiplex-brutal".into(),
        "extraJson" => "advanced-json".into(),
        _ => key.to_string(),
    }
}

fn proxy_option_key(key: &str) -> String {
    match key {
        "tls" => "tlsEnabled".into(),
        "skip-cert-verify" => "insecure".into(),
        "plugin-opts" => "pluginOptions".into(),
        "advanced-json" => "extraJson".into(),
        _ => kebab_to_camel(key),
    }
}

fn render_proxy_scalar(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(surge_config_value(value)),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn should_render_proxy_option(key: &str, value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Bool(value) => *value || key == "tlsEnabled",
        serde_json::Value::Number(value) => value.as_u64().unwrap_or(1) != 0,
        serde_json::Value::Null => false,
        _ => true,
    }
}

fn parse_scalar_for_json(
    key: &str,
    value: &str,
    defaults: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if let Some(default) = defaults.get(key) {
        match default {
            serde_json::Value::Bool(_) => {
                return match value.trim().to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => Ok(serde_json::Value::Bool(true)),
                    "false" | "0" | "no" | "off" => Ok(serde_json::Value::Bool(false)),
                    _ => Err(format!("{key} 只能填写 true 或 false")),
                }
            }
            serde_json::Value::Number(_) => {
                if let Ok(number) = value.parse::<u64>() {
                    return Ok(serde_json::Value::Number(number.into()));
                }
                return Err(format!("{key} 不是有效数字"));
            }
            _ => {}
        }
    }
    Ok(serde_json::Value::String(value.to_string()))
}

fn render_rule_condition(condition: &RuleCondition) -> String {
    if !condition.rules.is_empty() {
        let joiner = if condition.mode.eq_ignore_ascii_case("or") {
            " || "
        } else {
            " && "
        };
        let nested = condition
            .rules
            .iter()
            .map(render_rule_condition)
            .collect::<Vec<_>>()
            .join(joiner);
        return if condition.invert {
            format!("NOT ({nested})")
        } else {
            format!("({nested})")
        };
    }
    let value = if condition.value.is_empty() {
        "*"
    } else {
        &condition.value
    };
    let rendered = if condition.field.is_empty() {
        value.to_string()
    } else {
        format!("{}={}", condition.field, surge_config_value(value))
    };
    if condition.invert {
        format!("NOT {rendered}")
    } else {
        rendered
    }
}

fn render_songsterx_config(
    settings: &RuntimeSettings,
    config: &ProxyConfig,
    modules: &[ModuleInfo],
) -> String {
    let mut output = String::from("# SongsterX Configuration Format v1 (editable)\n# Surge-style syntax for readability; this is NOT a Surge profile.\n# This is NOT a sing-box configuration file. Edit this file, then use ‘从文件重载’ in the app.\n# sing-box.runtime.json is generated from this model and is not the user source file.\n# Values containing commas, spaces, operators or quotes are double-quoted with escapes.\n\n");
    output.push_str("[General]\n");
    output.push_str("format-version = 1\n");
    let _ = writeln!(
        output,
        "mode = {}",
        if settings.mode == "gateway" {
            "gateway-no-dhcp"
        } else {
            "mixed-direct"
        }
    );
    let _ = writeln!(output, "listen = {}", surge_config_value(&settings.listen));
    let _ = writeln!(output, "port = {}", settings.port);
    let _ = writeln!(output, "dns-mode = {}", settings.dns_mode);
    let _ = writeln!(
        output,
        "dns-server = {}",
        surge_config_value(&settings.dns_server)
    );
    let _ = writeln!(
        output,
        "sing-box-path = {}",
        surge_config_value(&settings.sing_box_path)
    );
    let _ = writeln!(
        output,
        "vmnet-helper-path = {}",
        surge_config_value(&settings.vmnet_helper_path)
    );
    let _ = writeln!(
        output,
        "vfkit-path = {}",
        surge_config_value(&settings.vfkit_path)
    );
    let _ = writeln!(
        output,
        "gateway-guest-kernel = {}",
        surge_config_value(&settings.gateway_guest_kernel_path)
    );
    let _ = writeln!(
        output,
        "gateway-guest-initrd = {}",
        surge_config_value(&settings.gateway_guest_initrd_path)
    );
    let _ = writeln!(
        output,
        "gateway-guest-cmdline = {}",
        surge_config_value(&settings.gateway_guest_cmdline)
    );
    let _ = writeln!(
        output,
        "gateway-guest-cpus = {}",
        settings.gateway_guest_cpus
    );
    let _ = writeln!(
        output,
        "gateway-guest-memory-mib = {}",
        settings.gateway_guest_memory_mib
    );
    let _ = writeln!(
        output,
        "gateway-host-ip = {}",
        surge_config_value(&settings.gateway_host_ip)
    );
    let _ = writeln!(
        output,
        "gateway-guest-host-ip = {}",
        surge_config_value(&settings.gateway_guest_host_ip)
    );
    let _ = writeln!(
        output,
        "gateway-host-cidr = {}",
        surge_config_value(&settings.gateway_host_cidr)
    );
    let _ = writeln!(
        output,
        "gateway-guest-agent-port = {}",
        settings.gateway_guest_agent_port
    );
    let _ = writeln!(
        output,
        "gateway-guest-lan-selector = {}",
        surge_config_value(&settings.gateway_guest_lan_selector)
    );
    let _ = writeln!(
        output,
        "gateway-guest-host-selector = {}",
        surge_config_value(&settings.gateway_guest_host_selector)
    );
    let _ = writeln!(
        output,
        "gateway-upstream-gateway = {}",
        surge_config_value(&settings.gateway_upstream_gateway)
    );
    let _ = writeln!(
        output,
        "vmnet-bridge-interface = {}",
        surge_config_value(&settings.gateway_lan_interface)
    );
    let _ = writeln!(
        output,
        "vm-gateway-ip = {}",
        surge_config_value(&settings.gateway_ip)
    );
    let _ = writeln!(
        output,
        "vm-gateway-cidr = {}",
        surge_config_value(&settings.gateway_cidr)
    );
    let _ = writeln!(
        output,
        "fakeip-dns-ip = {}",
        surge_config_value(&settings.gateway_dns_ip)
    );
    let _ = writeln!(
        output,
        "mitm-ca-dir = {}",
        surge_config_value(&settings.mitm_ca_dir)
    );
    let _ = writeln!(output, "log-level = {}", settings.log_level);
    let _ = writeln!(output, "tun = {}", settings.mode == "gateway");
    let _ = writeln!(output, "system-dns = {}\n", settings.dns_mode == "system");

    output.push_str("[Gateway]\n");
    output.push_str("# Gateway is an additional LAN entry; Mixed remains enabled in parallel.\n");
    let _ = writeln!(output, "enabled = {}", settings.mode == "gateway");
    let _ = writeln!(
        output,
        "interface = {}",
        surge_config_value(&settings.gateway_lan_interface)
    );
    let _ = writeln!(
        output,
        "gateway-ip = {}",
        surge_config_value(&settings.gateway_ip)
    );
    let _ = writeln!(
        output,
        "cidr = {}",
        surge_config_value(&settings.gateway_cidr)
    );
    let _ = writeln!(
        output,
        "dns-ip = {}",
        surge_config_value(&settings.gateway_dns_ip)
    );
    output.push_str("dhcp = false\n");
    output.push_str("ipv6 = false\n");
    let _ = writeln!(
        output,
        "client-policy = {}",
        surge_config_value(&settings.gateway_client_policy)
    );
    let _ = writeln!(
        output,
        "clients = {}\n",
        surge_config_value(&settings.gateway_clients)
    );
    let _ = writeln!(output, "policy-mode = {}\n", settings.gateway_policy_mode);

    output.push_str("[Proxy]\n");
    if config.nodes.is_empty() {
        output.push_str("# tag = type, server, port, options…\n");
    }
    for node in &config.nodes {
        let mut fields = vec![
            surge_config_value(&node.tag),
            surge_config_value(&node.kind),
            surge_config_value(&node.server),
            node.server_port.to_string(),
        ];
        if let Some(object) = serde_json::to_value(node)
            .ok()
            .and_then(|value| value.as_object().cloned())
        {
            for (key, value) in object {
                if matches!(key.as_str(), "tag" | "type" | "server" | "serverPort")
                    || !should_render_proxy_option(&key, &value)
                {
                    continue;
                }
                if let Some(rendered) = render_proxy_scalar(&value) {
                    fields.push(format!("{}={rendered}", proxy_option_name(&key)));
                }
            }
        }
        let _ = writeln!(output, "{}", fields.join(","));
    }
    output.push_str("\n[Proxy Group]\n");
    if config.groups.is_empty() {
        output.push_str("# name = select, member-1, member-2\n");
    }
    for group in &config.groups {
        let mut fields = vec![
            surge_config_value(&group.name),
            surge_config_value(&group.kind),
        ];
        fields.extend(
            group
                .members
                .iter()
                .map(|member| surge_config_value(member)),
        );
        if !group.default.is_empty() {
            fields.push(format!("default={}", surge_config_value(&group.default)));
        }
        if !group.url.is_empty() {
            fields.push(format!("url={}", surge_config_value(&group.url)));
        }
        if !group.interval.is_empty() {
            fields.push(format!("interval={}", surge_config_value(&group.interval)));
        }
        if group.tolerance != 0 {
            fields.push(format!("tolerance={}", group.tolerance));
        }
        if !group.idle_timeout.is_empty() {
            fields.push(format!(
                "idle-timeout={}",
                surge_config_value(&group.idle_timeout)
            ));
        }
        if group.interrupt_exist_connections {
            fields.push("interrupt-exist-connections=true".into());
        }
        let _ = writeln!(output, "{}", fields.join(","));
    }

    output.push_str("\n[Rule Set]\n");
    if config.rule_sets.is_empty() {
        output.push_str("# tag = remote, url, format=source, update-interval=1d\n");
    }
    for rule_set in &config.rule_sets {
        let source = if rule_set.kind.eq_ignore_ascii_case("local") {
            &rule_set.path
        } else {
            &rule_set.url
        };
        let mut fields = vec![rule_set.tag.clone(), rule_set.kind.clone(), source.clone()];
        if !rule_set.format.is_empty() {
            fields.push(format!("format={}", rule_set.format));
        }
        if !rule_set.update_interval.is_empty() {
            fields.push(format!("update-interval={}", rule_set.update_interval));
        }
        let _ = writeln!(
            output,
            "{}",
            fields
                .iter()
                .map(|field| surge_config_value(field))
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    output.push_str("\n[Rule]\n");
    if config.rules.is_empty() {
        output.push_str("# condition, action, outbound\n");
    }
    for rule in &config.rules {
        if !rule.enabled {
            output.push_str("# disabled: ");
        }
        let condition = rule
            .condition
            .as_ref()
            .map(render_rule_condition)
            .unwrap_or_else(|| "*".into());
        let comment = if rule.name.is_empty() || rule.name == rule.id {
            format!("id={}", surge_config_value(&rule.id))
        } else {
            format!(
                "id={}; name={}",
                surge_config_value(&rule.id),
                surge_config_value(&rule.name)
            )
        };
        let _ = writeln!(
            output,
            "{}, {}, {} # {}",
            condition,
            surge_config_value(&rule.action),
            surge_config_value(&rule.outbound),
            comment
        );
    }

    output.push_str("\n[Module]\n");
    if modules.is_empty() {
        output.push_str("# id = enabled, local-file, sections…\n");
    }
    for module in modules {
        let enabled = if module.enabled { "true" } else { "false" };
        let argument_values = module
            .arguments
            .iter()
            .map(|argument| (argument.name.clone(), argument.value.clone()))
            .collect::<BTreeMap<_, _>>();
        let arguments_json =
            serde_json::to_string(&argument_values).unwrap_or_else(|_| "{}".into());
        let _ = writeln!(
            output,
            "{}, {}, {}, {}, arguments-json={} # {}",
            surge_config_value(&module.id),
            enabled,
            surge_config_value(&module.local_file),
            surge_config_value(&module.sections.join("/")),
            surge_config_value(&arguments_json),
            surge_config_value(&module.name)
        );
    }
    output
}

#[derive(Clone, Default)]
struct SongsterXModulePreference {
    id: String,
    enabled: bool,
    argument_values: BTreeMap<String, String>,
}

#[derive(Clone)]
struct SongsterXUserConfig {
    settings: RuntimeSettings,
    proxy_config: ProxyConfig,
    modules: Vec<SongsterXModulePreference>,
}

fn parse_proxy_node(fields: &[String], line_number: usize) -> Result<ProxyNode, String> {
    if fields.len() < 4 {
        return Err(format!(
            "[Proxy] 第 {line_number} 行至少需要 tag、type、server、port 四个字段"
        ));
    }
    let defaults = serde_json::to_value(ProxyNode::default())
        .map_err(|error| format!("无法准备代理字段默认值：{error}"))?;
    let defaults = defaults
        .as_object()
        .expect("ProxyNode serializes to an object");
    let mut object = defaults.clone();
    object.insert("tag".into(), serde_json::Value::String(fields[0].clone()));
    object.insert("type".into(), serde_json::Value::String(fields[1].clone()));
    object.insert(
        "server".into(),
        serde_json::Value::String(fields[2].clone()),
    );
    let server_port = fields[3]
        .parse::<u16>()
        .map_err(|error| format!("[Proxy] 第 {line_number} 行端口无效：{error}"))?;
    object.insert(
        "serverPort".into(),
        serde_json::Value::Number(server_port.into()),
    );

    let mut unknown = serde_json::Map::new();
    for option in &fields[4..] {
        let (raw_key, raw_value) = option
            .split_once('=')
            .map(|(key, value)| (key.trim(), config_unquote_value(value)))
            .ok_or_else(|| format!("[Proxy] 第 {line_number} 行选项缺少 '='：{option}"))?;
        let key = proxy_option_key(raw_key);
        let parsed = parse_scalar_for_json(&key, &raw_value, defaults)
            .map_err(|error| format!("[Proxy] 第 {line_number} 行 {raw_key}：{error}"))?;
        if defaults.contains_key(&key) {
            object.insert(key, parsed);
        } else {
            unknown.insert(raw_key.to_string(), parsed);
        }
    }
    if !unknown.is_empty() {
        let mut extra = object
            .get("extraJson")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        extra.extend(unknown);
        object.insert(
            "extraJson".into(),
            serde_json::Value::String(serde_json::Value::Object(extra).to_string()),
        );
    }
    serde_json::from_value(serde_json::Value::Object(object))
        .map_err(|error| format!("[Proxy] 第 {line_number} 行字段无效：{error}"))
}

fn parse_policy_group(fields: &[String], line_number: usize) -> Result<PolicyGroup, String> {
    if fields.len() < 2 {
        return Err(format!(
            "[Proxy Group] 第 {line_number} 行至少需要名称和类型"
        ));
    }
    let defaults = serde_json::to_value(PolicyGroup::default())
        .map_err(|error| format!("无法准备策略组默认值：{error}"))?;
    let defaults = defaults
        .as_object()
        .expect("PolicyGroup serializes to an object");
    let mut object = defaults.clone();
    object.insert("name".into(), serde_json::Value::String(fields[0].clone()));
    object.insert("type".into(), serde_json::Value::String(fields[1].clone()));
    object.insert(
        "members".into(),
        serde_json::Value::Array(
            fields[2..]
                .iter()
                .filter(|field| !field.contains('='))
                .map(|field| serde_json::Value::String(field.clone()))
                .collect(),
        ),
    );
    for option in &fields[2..] {
        let Some((raw_key, raw_value)) = option.split_once('=') else {
            continue;
        };
        let key = kebab_to_camel(raw_key.trim());
        let parsed = parse_scalar_for_json(&key, &config_unquote_value(raw_value), defaults)
            .map_err(|error| format!("[Proxy Group] 第 {line_number} 行 {raw_key}：{error}"))?;
        if defaults.contains_key(&key) {
            object.insert(key, parsed);
        } else {
            return Err(format!(
                "[Proxy Group] 第 {line_number} 行不支持字段：{raw_key}"
            ));
        }
    }
    serde_json::from_value(serde_json::Value::Object(object))
        .map_err(|error| format!("[Proxy Group] 第 {line_number} 行字段无效：{error}"))
}

fn split_top_level_expression(value: &str, operator: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < value.len() {
        let character = value[index..].chars().next().expect("valid char boundary");
        let width = character.len_utf8();
        if escaped {
            escaped = false;
            index += width;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            index += width;
            continue;
        }
        if let Some(current_quote) = quote {
            if character == current_quote {
                quote = None;
            }
            index += width;
            continue;
        }
        if character == '"' || character == '\'' {
            quote = Some(character);
            index += width;
            continue;
        }
        if character == '(' {
            depth += 1;
        } else if character == ')' {
            depth = depth.saturating_sub(1);
        }
        if depth == 0 && value[index..].starts_with(operator) {
            result.push(value[start..index].trim().to_string());
            index += operator.len();
            start = index;
            continue;
        }
        index += width;
    }
    if result.is_empty() {
        None
    } else {
        result.push(value[start..].trim().to_string());
        Some(result)
    }
}

fn strip_expression_parentheses(value: &str) -> Option<&str> {
    let value = value.trim();
    if !value.starts_with('(') || !value.ends_with(')') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current_quote) = quote {
            if character == current_quote {
                quote = None;
            }
            continue;
        }
        if character == '"' || character == '\'' {
            quote = Some(character);
        } else if character == '(' {
            depth += 1;
        } else if character == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 && index != value.len() - 1 {
                return None;
            }
        }
    }
    (depth == 0).then_some(&value[1..value.len() - 1])
}

fn find_top_level_equals(value: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current_quote) = quote {
            if character == current_quote {
                quote = None;
            }
            continue;
        }
        if character == '"' || character == '\'' {
            quote = Some(character);
        } else if character == '(' {
            depth += 1;
        } else if character == ')' {
            depth = depth.saturating_sub(1);
        } else if character == '=' && depth == 0 {
            return Some(index);
        }
    }
    None
}

fn parse_rule_condition_expression(value: &str) -> Result<RuleCondition, String> {
    let value = value.trim();
    if value.is_empty() || value == "*" {
        return Ok(RuleCondition {
            kind: "field".into(),
            value: "*".into(),
            ..Default::default()
        });
    }
    if let Some(rest) = value
        .strip_prefix("NOT ")
        .or_else(|| value.strip_prefix("not "))
    {
        let mut condition = parse_rule_condition_expression(rest.trim())?;
        condition.invert = !condition.invert;
        return Ok(condition);
    }
    if let Some(inner) = strip_expression_parentheses(value) {
        return parse_rule_condition_expression(inner);
    }
    if let Some(parts) = split_top_level_expression(value, "||") {
        return Ok(RuleCondition {
            kind: "group".into(),
            mode: "or".into(),
            rules: parts
                .into_iter()
                .map(|part| parse_rule_condition_expression(&part))
                .collect::<Result<_, _>>()?,
            ..Default::default()
        });
    }
    if let Some(parts) = split_top_level_expression(value, "&&") {
        return Ok(RuleCondition {
            kind: "group".into(),
            mode: "and".into(),
            rules: parts
                .into_iter()
                .map(|part| parse_rule_condition_expression(&part))
                .collect::<Result<_, _>>()?,
            ..Default::default()
        });
    }
    if let Some(index) = find_top_level_equals(value) {
        return Ok(RuleCondition {
            kind: "field".into(),
            field: value[..index].trim().to_string(),
            value: config_unquote_value(&value[index + 1..]),
            ..Default::default()
        });
    }
    Ok(RuleCondition {
        kind: "field".into(),
        value: config_unquote_value(value),
        ..Default::default()
    })
}

fn parse_rule_comment(comment: &str, fallback_id: String) -> (String, String) {
    let mut id = String::new();
    let mut name = String::new();
    for part in comment.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("id=") {
            id = config_unquote_value(value);
        } else if let Some(value) = part.strip_prefix("name=") {
            name = config_unquote_value(value);
        } else if id.is_empty() && !part.is_empty() {
            id = config_unquote_value(part);
        }
    }
    if id.is_empty() {
        id = fallback_id;
    }
    if name.is_empty() {
        name = id.clone();
    }
    (id, name)
}

fn parse_songsterx_config(text: &str) -> Result<SongsterXUserConfig, String> {
    let mut section = String::new();
    let mut settings = RuntimeSettings::default();
    let mut config = ProxyConfig::default();
    let mut modules = Vec::new();
    let mut saw_nodes = false;
    let mut saw_groups = false;
    let mut saw_rules = false;
    let mut saw_rule_sets = false;

    for (line_index, raw_line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        let raw_line = raw_line.trim();
        let disabled_rule = raw_line.starts_with("# disabled:");
        if raw_line.is_empty() || (raw_line.starts_with('#') && !disabled_rule) {
            continue;
        }
        if raw_line.starts_with('[') && raw_line.ends_with(']') {
            section = raw_line[1..raw_line.len() - 1].trim().to_string();
            continue;
        }
        let comment_source = if disabled_rule {
            raw_line.trim_start_matches("# disabled:").trim()
        } else {
            raw_line
        };
        let (line, comment) = strip_config_comment(comment_source);
        if line.is_empty() {
            continue;
        }
        match section.as_str() {
            "General" => {
                let (key, value) = split_config_option(&line)
                    .ok_or_else(|| format!("[General] 第 {line_number} 行缺少 '='"))?;
                match key.as_str() {
                    "mode" => {
                        settings.mode = if value == "gateway-no-dhcp" || value == "gateway" {
                            "gateway".into()
                        } else {
                            "mixed".into()
                        }
                    }
                    "listen" => settings.listen = value,
                    "port" => {
                        settings.port = value.parse().map_err(|error| {
                            format!("[General] 第 {line_number} 行端口无效：{error}")
                        })?
                    }
                    "dns-mode" => settings.dns_mode = value,
                    "dns-server" => settings.dns_server = value,
                    "sing-box-path" => settings.sing_box_path = value,
                    "vmnet-helper-path" => settings.vmnet_helper_path = value,
                    "vfkit-path" => settings.vfkit_path = value,
                    "gateway-guest-kernel" => settings.gateway_guest_kernel_path = value,
                    "gateway-guest-initrd" => settings.gateway_guest_initrd_path = value,
                    "gateway-guest-cmdline" => settings.gateway_guest_cmdline = value,
                    "gateway-guest-cpus" => {
                        settings.gateway_guest_cpus = value.parse().map_err(|error| {
                            format!("[General] 第 {line_number} 行 guest CPU 数无效：{error}")
                        })?
                    }
                    "gateway-guest-memory-mib" => {
                        settings.gateway_guest_memory_mib = value.parse().map_err(|error| {
                            format!("[General] 第 {line_number} 行 guest 内存无效：{error}")
                        })?
                    }
                    "gateway-host-ip" => settings.gateway_host_ip = value,
                    "gateway-guest-host-ip" => settings.gateway_guest_host_ip = value,
                    "gateway-host-cidr" => settings.gateway_host_cidr = value,
                    "gateway-guest-agent-port" => {
                        settings.gateway_guest_agent_port = value.parse().map_err(|error| {
                            format!("[General] 第 {line_number} 行 guest agent 端口无效：{error}")
                        })?
                    }
                    "gateway-guest-lan-selector" => settings.gateway_guest_lan_selector = value,
                    "gateway-guest-host-selector" => settings.gateway_guest_host_selector = value,
                    "gateway-upstream-gateway" => settings.gateway_upstream_gateway = value,
                    "vmnet-bridge-interface" | "gateway-lan-interface" => {
                        settings.gateway_lan_interface = value
                    }
                    "vm-gateway-ip" | "gateway-ip" => settings.gateway_ip = value,
                    "vm-gateway-cidr" | "gateway-cidr" => settings.gateway_cidr = value,
                    "fakeip-dns-ip" | "gateway-dns-ip" => settings.gateway_dns_ip = value,
                    "mitm-ca-dir" => settings.mitm_ca_dir = value,
                    "log-level" => settings.log_level = value,
                    "format-version" | "config-version" | "tun" | "system-dns"
                    | "gateway-profile" | "gatewaykit-path" | "gateway-backend" => {}
                    _ => return Err(format!("[General] 第 {line_number} 行不支持字段：{key}")),
                }
            }
            "Gateway" => {
                let (key, value) = split_config_option(&line)
                    .ok_or_else(|| format!("[Gateway] 第 {line_number} 行缺少 '='"))?;
                match key.as_str() {
                    "enabled" => {
                        let enabled = matches!(
                            value.to_ascii_lowercase().as_str(),
                            "true" | "1" | "yes" | "on"
                        );
                        settings.mode = if enabled { "gateway" } else { "mixed" }.into();
                    }
                    "interface" | "vmnet-interface" | "bridge-interface" => {
                        settings.gateway_lan_interface = value
                    }
                    "gateway-ip" | "ip" => settings.gateway_ip = value,
                    "cidr" | "gateway-cidr" => settings.gateway_cidr = value,
                    "dns-ip" | "gateway-dns-ip" => settings.gateway_dns_ip = value,
                    "client-policy" => settings.gateway_client_policy = value,
                    "clients" | "static-clients" => settings.gateway_clients = value,
                    "policy-mode" | "proxy-policy-mode" => settings.gateway_policy_mode = value,
                    "gateway-profile" => {}
                    "dhcp"
                        if matches!(
                            value.to_ascii_lowercase().as_str(),
                            "true" | "1" | "yes" | "on"
                        ) =>
                    {
                        return Err("[Gateway] dhcp 必须为 false；SongsterX 网关不提供 DHCP".into())
                    }
                    "ipv6"
                        if matches!(
                            value.to_ascii_lowercase().as_str(),
                            "true" | "1" | "yes" | "on"
                        ) =>
                    {
                        return Err("[Gateway] ipv6 必须为 false；当前网关不提供 IPv6 RA/NDP".into())
                    }
                    "dhcp" | "ipv6" => {}
                    _ => return Err(format!("[Gateway] 第 {line_number} 行不支持字段：{key}")),
                }
            }
            "Proxy" => {
                if !saw_nodes {
                    config.nodes.clear();
                    saw_nodes = true;
                }
                config
                    .nodes
                    .push(parse_proxy_node(&split_config_fields(&line)?, line_number)?);
            }
            "Proxy Group" => {
                if !saw_groups {
                    config.groups.clear();
                    saw_groups = true;
                }
                config.groups.push(parse_policy_group(
                    &split_config_fields(&line)?,
                    line_number,
                )?);
            }
            "Rule Set" => {
                if !saw_rule_sets {
                    config.rule_sets.clear();
                    saw_rule_sets = true;
                }
                let fields = split_config_fields(&line)?;
                if fields.len() < 3 {
                    return Err(format!(
                        "[Rule Set] 第 {line_number} 行至少需要 tag、type、source"
                    ));
                }
                let mut rule_set = RuleSetConfig {
                    kind: fields[1].clone(),
                    tag: fields[0].clone(),
                    ..Default::default()
                };
                if rule_set.kind.eq_ignore_ascii_case("local") {
                    rule_set.path = fields[2].clone();
                } else {
                    rule_set.url = fields[2].clone();
                }
                for option in &fields[3..] {
                    let Some((key, value)) = option.split_once('=') else {
                        return Err(format!(
                            "[Rule Set] 第 {line_number} 行选项缺少 '='：{option}"
                        ));
                    };
                    match key.trim() {
                        "format" => rule_set.format = config_unquote_value(value),
                        "update-interval" => rule_set.update_interval = config_unquote_value(value),
                        other => {
                            return Err(format!(
                                "[Rule Set] 第 {line_number} 行不支持字段：{other}"
                            ))
                        }
                    }
                }
                config.rule_sets.push(rule_set);
            }
            "Rule" => {
                if !saw_rules {
                    config.rules.clear();
                    saw_rules = true;
                }
                let disabled = disabled_rule;
                let fields = split_config_fields(&line)?;
                if fields.len() < 3 {
                    return Err(format!(
                        "[Rule] 第 {line_number} 行至少需要 condition、action、outbound"
                    ));
                }
                let (id, name) = parse_rule_comment(&comment, format!("rule-{line_number}"));
                config.rules.push(ProxyRule {
                    id,
                    name,
                    enabled: !disabled,
                    action: fields[1].clone(),
                    outbound: fields[2].clone(),
                    condition: Some(
                        parse_rule_condition_expression(&fields[0]).map_err(|error| {
                            format!("[Rule] 第 {line_number} 行条件无效：{error}")
                        })?,
                    ),
                    legacy_kind: String::new(),
                    legacy_value: String::new(),
                });
            }
            "Module" => {
                let fields = split_config_fields(&line)?;
                if fields.len() < 2 {
                    return Err(format!("[Module] 第 {line_number} 行至少需要 id、enabled"));
                }
                let enabled = matches!(
                    fields[1].to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes" | "on"
                );
                let mut argument_values = BTreeMap::new();
                for option in fields.get(4..).unwrap_or(&[]) {
                    let Some((key, value)) = option.split_once('=') else {
                        return Err(format!(
                            "[Module] 第 {line_number} 行选项缺少 '='：{option}"
                        ));
                    };
                    if key.trim() != "arguments-json" {
                        return Err(format!(
                            "[Module] 第 {line_number} 行不支持字段：{}",
                            key.trim()
                        ));
                    }
                    argument_values =
                        serde_json::from_str(&config_unquote_value(value)).map_err(|error| {
                            format!("[Module] 第 {line_number} 行 arguments-json 无效：{error}")
                        })?;
                }
                modules.push(SongsterXModulePreference {
                    id: fields[0].clone(),
                    enabled,
                    argument_values,
                });
            }
            other => return Err(format!("第 {line_number} 行位于未知配置段 [{other}]")),
        }
    }
    if settings.gateway_guest_lan_selector.trim().is_empty() {
        settings.gateway_guest_lan_selector = vfkit::DEFAULT_GATEWAY_GUEST_LAN_SELECTOR.into();
    }
    if settings.gateway_guest_host_selector.trim().is_empty() {
        settings.gateway_guest_host_selector = vfkit::DEFAULT_GATEWAY_GUEST_HOST_SELECTOR.into();
    }
    validate_settings(&settings)?;
    Ok(SongsterXUserConfig {
        settings,
        proxy_config: normalize_proxy_config(&mut config),
        modules,
    })
}

fn parse_ipv4(value: &str, label: &str) -> Result<Ipv4Addr, String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("{label}必须是有效的 IPv4 地址"))
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address, prefix) = value.trim().split_once('/').ok_or_else(|| {
        "VM Gateway 网段必须使用 IPv4/prefix 格式，例如 192.168.88.0/24".to_string()
    })?;
    let address = parse_ipv4(address, "VM Gateway 网段")?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "VM Gateway 网段的 prefix 无效".to_string())?;
    if !(1..=30).contains(&prefix) {
        return Err("VM Gateway 网段的 prefix 必须在 1-30 之间".into());
    }
    Ok((address, prefix))
}

fn detect_interface_cidr(interface: &str) -> Result<String, String> {
    let output = Command::new("ifconfig")
        .arg(interface.trim())
        .output()
        .map_err(|error| format!("无法读取物理网卡 {} 的网络信息：{error}", interface.trim()))?;
    if !output.status.success() {
        return Err(format!("物理网卡 {} 不存在或不可用", interface.trim()));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();
    for index in 0..fields.len() {
        if fields[index] != "inet" || index + 3 >= fields.len() || fields[index + 2] != "netmask" {
            continue;
        }
        let address = fields[index + 1]
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("物理网卡 {} 的 IPv4 地址无效", interface.trim()))?;
        let mask_value = fields[index + 3].trim_start_matches("0x");
        let mask = u32::from_str_radix(mask_value, 16)
            .map_err(|_| format!("物理网卡 {} 的 IPv4 掩码无效", interface.trim()))?;
        let prefix = mask.leading_ones();
        if mask != 0 && mask != u32::MAX << (32 - prefix) {
            return Err(format!(
                "物理网卡 {} 的 IPv4 掩码不是连续掩码",
                interface.trim()
            ));
        }
        let network = u32::from(address) & mask;
        return Ok(format!("{}/{}", Ipv4Addr::from(network), prefix));
    }
    Err(format!(
        "物理网卡 {} 没有可用的 IPv4 地址和掩码，无法自动确定局域网网段",
        interface.trim()
    ))
}

fn ensure_gateway_ip_is_not_in_use(settings: &RuntimeSettings) -> Result<(), String> {
    let gateway_ip = parse_ipv4(&settings.gateway_ip, "VM Gateway IP")?;
    let gateway_ip_text = gateway_ip.to_string();
    let interface = settings.gateway_lan_interface.trim();
    let ifconfig = Command::new("ifconfig")
        .arg(interface)
        .output()
        .map_err(|error| format!("无法检查网关 IP 是否冲突：{error}"))?;
    if ifconfig.status.success() {
        let text = String::from_utf8_lossy(&ifconfig.stdout);
        if text
            .split_whitespace()
            .any(|field| field == gateway_ip_text)
        {
            return Err(format!(
                "局域网网关 IP {} 已经配置在物理网卡 {} 上，不能重复使用",
                gateway_ip, interface
            ));
        }
    }

    // A successful ICMP response is a strong duplicate-address signal. A
    // timeout is deliberately treated as inconclusive because many LAN
    // devices disable ICMP; the actual Gateway packet-path gate remains
    // responsible for proving forwarding after startup.
    let ping = Command::new("ping")
        .args(["-c", "1", "-W", "300", &gateway_ip_text])
        .output()
        .map_err(|error| format!("无法执行网关 IP 冲突探测：{error}"))?;
    if ping.status.success() {
        return Err(format!(
            "局域网网关 IP {} 已有设备响应，请选择未占用的地址",
            gateway_ip
        ));
    }
    Ok(())
}

fn gateway_cidr_for_runtime(settings: &RuntimeSettings) -> Result<String, String> {
    if !settings.gateway_cidr.trim().is_empty() {
        return Ok(settings.gateway_cidr.trim().to_string());
    }
    detect_interface_cidr(&settings.gateway_lan_interface)
}

fn parse_gateway_clients(value: &str) -> Result<Vec<(String, String)>, String> {
    let mut clients = Vec::new();
    for (index, raw_line) in value.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        let (ip, mac) = match fields.as_slice() {
            [ip, mac] => (*ip, *mac),
            [_, ip, mac] => (*ip, *mac),
            _ => return Err(format!("网关静态客户端第 {} 行必须是 IP,MAC", index + 1)),
        };
        parse_ipv4(ip, &format!("网关静态客户端第 {} 行 IP", index + 1))?;
        let mac_parts: Vec<&str> = mac.split(':').collect();
        if mac_parts.len() != 6
            || mac_parts
                .iter()
                .any(|part| part.len() != 2 || u8::from_str_radix(part, 16).is_err())
        {
            return Err(format!(
                "网关静态客户端第 {} 行 MAC 无效：{}",
                index + 1,
                mac
            ));
        }
        clients.push((ip.to_string(), mac.to_ascii_lowercase()));
    }
    Ok(clients)
}

fn ipv4_u32(address: Ipv4Addr) -> u32 {
    u32::from_be_bytes(address.octets())
}

fn validate_gateway_network(settings: &RuntimeSettings) -> Result<(), String> {
    if settings.gateway_lan_interface.trim().is_empty() {
        return Err("VM Gateway 模式必须填写物理网卡名称，例如 en0".into());
    }
    if settings.gateway_client_policy != "all" && settings.gateway_client_policy != "allowlist" {
        return Err("网关客户端策略只能是 all 或 allowlist".into());
    }
    if settings.gateway_client_policy == "allowlist" {
        return Err(
            "Gateway 客户端 allowlist 尚未接入 Linux guest，当前只能使用 client-policy = all"
                .into(),
        );
    }
    if !settings.gateway_clients.trim().is_empty() {
        parse_gateway_clients(&settings.gateway_clients)?;
    }
    if settings.gateway_client_policy == "allowlist" && settings.gateway_clients.trim().is_empty() {
        return Err("仅允许指定设备时，必须填写至少一个客户端（IP,MAC）".into());
    }
    if settings.gateway_ip.trim().is_empty() {
        return Err("VM Gateway 模式必须填写局域网网关 IP".into());
    }
    let gateway_ip = parse_ipv4(&settings.gateway_ip, "VM Gateway IP")?;
    parse_ipv4(&settings.dns_server, "Gateway guest DNS")?;
    let gateway_cidr = gateway_cidr_for_runtime(settings)?;
    let (cidr_ip, prefix) = parse_ipv4_cidr(&gateway_cidr)?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = ipv4_u32(cidr_ip) & mask;
    let gateway = ipv4_u32(gateway_ip);
    let broadcast = network | !mask;
    if gateway & mask != network {
        return Err("局域网网关 IP 不在物理局域网网段内".into());
    }
    if gateway == network || gateway == broadcast {
        return Err("局域网网关 IP 不能是网络地址或广播地址".into());
    }
    if settings.dns_mode == "fakeip"
        && !settings.gateway_dns_ip.trim().is_empty()
        && settings.gateway_dns_ip.trim() != "198.18.0.2"
    {
        return Err("VM Gateway 的 FakeIP DNS 固定为 198.18.0.2".into());
    }
    let dns_is_fakeip = settings.dns_mode == "fakeip"
        && (settings.gateway_dns_ip.trim().is_empty()
            || settings.gateway_dns_ip.trim() == "198.18.0.2");
    let dns_ip = if settings.gateway_dns_ip.trim().is_empty() {
        if settings.dns_mode == "fakeip" {
            Ipv4Addr::new(198, 18, 0, 2)
        } else {
            gateway_ip
        }
    } else {
        parse_ipv4(&settings.gateway_dns_ip, "VM Gateway DNS IP")?
    };
    if !dns_is_fakeip && ipv4_u32(dns_ip) & mask != network {
        return Err("局域网网关 DNS IP 不在物理局域网网段内".into());
    }
    Ok(())
}

fn validate_vfkit_settings(settings: &RuntimeSettings) -> Result<(), String> {
    if settings.gateway_guest_cpus == 0 || settings.gateway_guest_cpus > 8 {
        return Err("vfkit guest CPU 数必须在 1-8 之间".into());
    }
    if !(256..=16_384).contains(&settings.gateway_guest_memory_mib) {
        return Err("vfkit guest 内存必须在 256-16384 MiB 之间".into());
    }
    if settings.gateway_guest_agent_port == 0 {
        return Err("vfkit guest agent 端口无效".into());
    }
    let host_ip = parse_ipv4(&settings.gateway_host_ip, "vfkit host-only host IP")?;
    let guest_ip = parse_ipv4(&settings.gateway_guest_host_ip, "vfkit host-only guest IP")?;
    if host_ip == guest_ip {
        return Err("vfkit host-only 网卡的 host IP 与 guest IP 不能相同".into());
    }
    let (network_ip, prefix) = parse_ipv4_cidr(&settings.gateway_host_cidr)?;
    if !(1..=30).contains(&prefix) {
        return Err("vfkit host-only 网段 prefix 必须在 1-30 之间".into());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(network_ip) & mask;
    for (label, address) in [("host", host_ip), ("guest", guest_ip)] {
        if u32::from(address) & mask != network {
            return Err(format!(
                "vfkit host-only {label} IP 不在 {} 内",
                settings.gateway_host_cidr.trim()
            ));
        }
    }
    Ok(())
}

fn validate_settings(settings: &RuntimeSettings) -> Result<(), String> {
    if settings.mode != "mixed" && settings.mode != "gateway" {
        return Err("运行模式只能是 mixed 或 gateway".into());
    }
    if settings.listen.trim().is_empty() {
        return Err("监听地址不能为空".into());
    }
    if settings.port == 0 {
        return Err("监听端口必须在 1-65535 之间".into());
    }
    if settings.dns_mode != "system"
        && settings.dns_mode != "custom"
        && settings.dns_mode != "fakeip"
    {
        return Err("DNS 模式只能是 system、custom 或 fakeip".into());
    }
    if settings.dns_mode == "fakeip" && settings.mode != "gateway" {
        return Err("FakeIP 只允许在网关模式使用".into());
    }
    if settings.gateway_policy_mode != "shared" && settings.gateway_policy_mode != "separate" {
        return Err("Gateway 策略模式只能是 shared 或 separate".into());
    }
    if settings.mode == "gateway" {
        validate_gateway_network(settings)?;
        validate_vfkit_settings(settings)?;
    }
    if settings.dns_mode == "custom" && settings.dns_server.trim().is_empty() {
        return Err("自定义 DNS 服务器不能为空".into());
    }
    if !matches!(
        settings.log_level.as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    ) {
        return Err("日志等级不合法".into());
    }
    Ok(())
}

fn read_songsterx_user_config(app: &AppHandle) -> Result<Option<SongsterXUserConfig>, String> {
    let path = songsterx_config_path(app)?;
    if !path.is_file() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取 SongsterX 配置 {}：{error}", path.display()))?;
    parse_songsterx_config(&content).map(Some)
}

fn current_songsterx_user_config(app: &AppHandle) -> Result<SongsterXUserConfig, String> {
    Ok(
        read_songsterx_user_config(app)?.unwrap_or_else(|| SongsterXUserConfig {
            settings: RuntimeSettings::default(),
            proxy_config: ProxyConfig::default(),
            modules: Vec::new(),
        }),
    )
}

fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    use std::io::Write;
    file.write_all(contents)?;
    file.sync_all()
}

fn write_songsterx_config(
    app: &AppHandle,
    settings: &RuntimeSettings,
    config: &ProxyConfig,
    modules: &[ModuleInfo],
) -> Result<(), String> {
    let directory = app_data_dir(app)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let path = songsterx_config_path(app)?;
    let temporary_path = path.with_extension("conf.tmp");
    let content = render_songsterx_config(settings, config, modules);
    write_private_file(&temporary_path, content.as_bytes()).map_err(|error| {
        format!(
            "无法写入临时 SongsterX 配置 {}：{error}",
            temporary_path.display()
        )
    })?;
    if let Err(error) = fs::rename(&temporary_path, &path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!(
            "无法提交 SongsterX 配置 {}：{error}",
            path.display()
        ));
    }
    Ok(())
}

fn write_songsterx_config_from_current_state(app: &AppHandle) -> Result<(), String> {
    let current = current_songsterx_user_config(app)?;
    let modules = load_modules(app)?;
    write_songsterx_config(app, &current.settings, &current.proxy_config, &modules)
}

fn contains_obsolete_gateway_profile_field(content: &str) -> bool {
    content.lines().any(|line| {
        line.split_once('=')
            .map(|(key, _)| key.trim() == "gateway-profile")
            .unwrap_or(false)
    })
}

fn ensure_songsterx_config(app: &AppHandle) -> Result<String, String> {
    let path = songsterx_config_path(app)?;
    if !path.is_file() {
        write_songsterx_config_from_current_state(app)?;
    } else {
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("无法读取 SongsterX 配置 {}：{error}", path.display()))?;
        if contains_obsolete_gateway_profile_field(&content) {
            // 旧字段只作为待清理的残留处理，不读取其值，也不恢复旧 profile。
            write_songsterx_config_from_current_state(app)?;
        }
    }
    fs::read_to_string(&path)
        .map_err(|error| format!("无法读取 SongsterX 配置 {}：{error}", path.display()))
}

fn persist_settings(
    app: &AppHandle,
    settings: &RuntimeSettings,
) -> Result<RuntimeSettings, String> {
    let mut settings = settings.clone();
    if settings.mode == "gateway" && settings.gateway_cidr.trim().is_empty() {
        settings.gateway_cidr = detect_interface_cidr(&settings.gateway_lan_interface)?;
    }
    if settings.gateway_guest_lan_selector.trim().is_empty() {
        settings.gateway_guest_lan_selector = vfkit::DEFAULT_GATEWAY_GUEST_LAN_SELECTOR.into();
    }
    if settings.gateway_guest_host_selector.trim().is_empty() {
        settings.gateway_guest_host_selector = vfkit::DEFAULT_GATEWAY_GUEST_HOST_SELECTOR.into();
    }
    validate_settings(&settings)?;
    let current = current_songsterx_user_config(app)?;
    let modules = load_modules(app)?;
    write_songsterx_config(app, &settings, &current.proxy_config, &modules)?;
    if settings.mode == "gateway" && settings.gateway_policy_mode == "separate" {
        let path = gateway_guest_proxy_config_path(app)?;
        if !path.is_file() {
            write_gateway_guest_proxy_config_file(app, &current.proxy_config)?;
        }
    }
    Ok(settings)
}

fn load_settings(app: &AppHandle) -> Result<RuntimeSettings, String> {
    Ok(current_songsterx_user_config(app)?.settings)
}

fn dns_status(settings: &RuntimeSettings) -> String {
    if settings.dns_mode == "fakeip" {
        if settings.mode == "gateway" {
            let dns_ip = if settings.gateway_dns_ip.trim().is_empty() {
                "198.18.0.2"
            } else {
                settings.gateway_dns_ip.trim()
            };
            format!("FakeIP · DNS {} · 198.18.0.0/15", dns_ip)
        } else {
            "FakeIP · 198.18.0.0/15".into()
        }
    } else if settings.dns_mode == "custom" {
        format!("自定义 DNS · {}", settings.dns_server.trim())
    } else {
        "系统 DNS".into()
    }
}

fn load_proxy_config(app: &AppHandle) -> Result<ProxyConfig, String> {
    Ok(current_songsterx_user_config(app)?.proxy_config)
}

fn write_gateway_guest_proxy_config_file(
    app: &AppHandle,
    config: &ProxyConfig,
) -> Result<(), String> {
    let directory = app_data_dir(app)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let path = gateway_guest_proxy_config_path(app)?;
    let content = serde_json::to_string_pretty(config)
        .map_err(|error| format!("无法序列化 Gateway guest 策略：{error}"))?;
    write_private_file(&path, format!("{content}\n").as_bytes()).map_err(|error| {
        format!(
            "无法写入 Gateway guest 独立策略 {}：{error}",
            path.display()
        )
    })
}

fn load_gateway_guest_proxy_config(app: &AppHandle) -> Result<ProxyConfig, String> {
    let current = current_songsterx_user_config(app)?;
    if current.settings.mode != "gateway" || current.settings.gateway_policy_mode == "shared" {
        return Ok(current.proxy_config);
    }
    let path = gateway_guest_proxy_config_path(app)?;
    if !path.is_file() {
        write_gateway_guest_proxy_config_file(app, &current.proxy_config)?;
        return Ok(current.proxy_config);
    }
    let content = fs::read_to_string(&path).map_err(|error| {
        format!(
            "无法读取 Gateway guest 独立策略 {}：{error}",
            path.display()
        )
    })?;
    let mut config: ProxyConfig = serde_json::from_str(&content).map_err(|error| {
        format!(
            "Gateway guest 独立策略 {} 不是有效 JSON：{error}",
            path.display()
        )
    })?;
    Ok(normalize_proxy_config(&mut config))
}

fn persist_gateway_guest_proxy_config(
    app: &AppHandle,
    config: &ProxyConfig,
) -> Result<ProxyConfig, String> {
    let settings = load_settings(app)?;
    if settings.mode != "gateway" || settings.gateway_policy_mode != "separate" {
        return Err("只有 Gateway 的“Host / Gateway 分开”模式可以单独保存 guest 策略".into());
    }
    let mut config = config.clone();
    let normalized = normalize_proxy_config(&mut config);
    write_gateway_guest_proxy_config_file(app, &normalized)?;
    Ok(normalized)
}

fn normalize_proxy_config(config: &mut ProxyConfig) -> ProxyConfig {
    for (rule_index, rule) in config.rules.iter_mut().enumerate() {
        if rule.id.trim().is_empty() {
            rule.id = format!("rule-{}", rule_index + 1);
        }
        if rule.name.trim().is_empty() {
            rule.name = rule.id.clone();
        }
        let legacy_kind = std::mem::take(&mut rule.legacy_kind);
        let legacy_value = std::mem::take(&mut rule.legacy_value);
        if rule.condition.is_none() && !legacy_kind.trim().is_empty() {
            rule.condition = Some(RuleCondition {
                id: format!("{}-condition", rule.id),
                kind: "field".into(),
                field: legacy_kind,
                value: legacy_value,
                mode: String::new(),
                invert: false,
                rules: vec![],
            });
        }
        if let Some(condition) = &mut rule.condition {
            normalize_condition_ids(condition, &format!("{}-condition", rule.id));
        }
    }
    config.clone()
}

fn normalize_condition_ids(condition: &mut RuleCondition, fallback_id: &str) {
    if condition.id.trim().is_empty() {
        condition.id = fallback_id.to_string();
    }
    for (index, child) in condition.rules.iter_mut().enumerate() {
        normalize_condition_ids(child, &format!("{}-{}", condition.id, index + 1));
    }
}

fn persist_proxy_config(app: &AppHandle, config: &ProxyConfig) -> Result<ProxyConfig, String> {
    let current = current_songsterx_user_config(app)?;
    let modules = load_modules(app)?;
    write_songsterx_config(app, &current.settings, config, &modules)?;
    Ok(config.clone())
}

fn merge_extra_json(outbound: &mut serde_json::Value, raw: &str, tag: &str) -> Result<(), String> {
    if raw.trim().is_empty() {
        return Ok(());
    }
    let extra: serde_json::Value = serde_json::from_str(raw)
        .map_err(|error| format!("出站 {tag} 的高级 JSON 无效：{error}"))?;
    let object = extra
        .as_object()
        .ok_or_else(|| format!("出站 {tag} 的高级 JSON 必须是对象"))?;
    let target = outbound
        .as_object_mut()
        .expect("outbound should always be a JSON object");
    for (key, value) in object {
        target.insert(key.clone(), value.clone());
    }
    Ok(())
}

fn parse_optional_json(
    raw: &str,
    field: &str,
    tag: &str,
) -> Result<Option<serde_json::Value>, String> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(raw)
        .map(Some)
        .map_err(|error| format!("出站 {tag} 的 {field} JSON 无效：{error}"))
}

fn apply_common_outbound_fields(
    outbound: &mut serde_json::Value,
    node: &ProxyNode,
) -> Result<(), String> {
    if !node.detour.is_empty() {
        outbound["detour"] = serde_json::Value::String(node.detour.clone());
    }
    if !node.bind_interface.is_empty() {
        outbound["bind_interface"] = serde_json::Value::String(node.bind_interface.clone());
    }
    if !node.inet4_bind_address.is_empty() {
        outbound["inet4_bind_address"] = serde_json::Value::String(node.inet4_bind_address.clone());
    }
    if !node.inet6_bind_address.is_empty() {
        outbound["inet6_bind_address"] = serde_json::Value::String(node.inet6_bind_address.clone());
    }
    if node.bind_address_no_port {
        outbound["bind_address_no_port"] = serde_json::Value::Bool(true);
    }
    if node.routing_mark > 0 {
        outbound["routing_mark"] = serde_json::Value::Number(node.routing_mark.into());
    }
    if node.reuse_addr {
        outbound["reuse_addr"] = serde_json::Value::Bool(true);
    }
    if !node.connect_timeout.is_empty() {
        outbound["connect_timeout"] = serde_json::Value::String(node.connect_timeout.clone());
    }
    if node.tcp_fast_open {
        outbound["tcp_fast_open"] = serde_json::Value::Bool(true);
    }
    if node.tcp_multi_path {
        outbound["tcp_multi_path"] = serde_json::Value::Bool(true);
    }
    if node.disable_tcp_keep_alive {
        outbound["disable_tcp_keep_alive"] = serde_json::Value::Bool(true);
    }
    if !node.tcp_keep_alive.is_empty() {
        outbound["tcp_keep_alive"] = serde_json::Value::String(node.tcp_keep_alive.clone());
    }
    if !node.tcp_keep_alive_interval.is_empty() {
        outbound["tcp_keep_alive_interval"] =
            serde_json::Value::String(node.tcp_keep_alive_interval.clone());
    }
    if node.udp_fragment {
        outbound["udp_fragment"] = serde_json::Value::Bool(true);
    }
    if !node.domain_resolver.is_empty() {
        outbound["domain_resolver"] = serde_json::Value::String(node.domain_resolver.clone());
    }
    if !node.network_strategy.is_empty() {
        outbound["network_strategy"] = serde_json::Value::String(node.network_strategy.clone());
    }
    if !node.network_type.is_empty() {
        outbound["network_type"] = serde_json::Value::Array(
            split_rule_values(&node.network_type)
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    if !node.fallback_network_type.is_empty() {
        outbound["fallback_network_type"] = serde_json::Value::Array(
            split_rule_values(&node.fallback_network_type)
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    if !node.fallback_delay.is_empty() {
        outbound["fallback_delay"] = serde_json::Value::String(node.fallback_delay.clone());
    }
    if !node.domain_strategy.is_empty() {
        outbound["domain_strategy"] = serde_json::Value::String(node.domain_strategy.clone());
    }

    if node.multiplex_enabled
        || !node.multiplex_protocol.is_empty()
        || node.multiplex_max_connections > 0
        || node.multiplex_min_streams > 0
        || node.multiplex_max_streams > 0
        || node.multiplex_padding
        || !node.multiplex_brutal.is_empty()
    {
        let mut multiplex = serde_json::json!({ "enabled": node.multiplex_enabled });
        if !node.multiplex_protocol.is_empty() {
            multiplex["protocol"] = serde_json::Value::String(node.multiplex_protocol.clone());
        }
        if node.multiplex_max_connections > 0 {
            multiplex["max_connections"] =
                serde_json::Value::Number(node.multiplex_max_connections.into());
        }
        if node.multiplex_min_streams > 0 {
            multiplex["min_streams"] = serde_json::Value::Number(node.multiplex_min_streams.into());
        }
        if node.multiplex_max_streams > 0 {
            multiplex["max_streams"] = serde_json::Value::Number(node.multiplex_max_streams.into());
        }
        if node.multiplex_padding {
            multiplex["padding"] = serde_json::Value::Bool(true);
        }
        if let Some(brutal) =
            parse_optional_json(&node.multiplex_brutal, "multiplex.brutal", &node.tag)?
        {
            multiplex["brutal"] = brutal;
        }
        outbound["multiplex"] = multiplex;
    }
    Ok(())
}

fn render_outbound(node: &ProxyNode) -> Result<serde_json::Value, String> {
    let mut outbound = serde_json::json!({
        "type": node.kind,
        "tag": node.tag
    });
    let uses_server_ports = matches!(node.kind.as_str(), "hysteria" | "hysteria2")
        && !node.server_ports.trim().is_empty();
    if node.kind != "tor" {
        if node.server.trim().is_empty() {
            return Err(format!("出站 {} 缺少服务器地址", node.tag));
        }
        outbound["server"] = serde_json::Value::String(node.server.clone());
        if !uses_server_ports && node.server_port == 0 {
            return Err(format!("出站 {} 的端口无效", node.tag));
        }
        if !uses_server_ports {
            outbound["server_port"] = serde_json::Value::Number(node.server_port.into());
        }
    }

    match node.kind.as_str() {
        "trojan" => {
            outbound["password"] = serde_json::Value::String(node.password.clone());
        }
        "vmess" => {
            outbound["uuid"] = serde_json::Value::String(node.uuid.clone());
            if !node.security.is_empty() {
                outbound["security"] = serde_json::Value::String(node.security.clone());
            }
            if node.alter_id > 0 {
                outbound["alter_id"] = serde_json::Value::Number(node.alter_id.into());
            }
            if !node.packet_encoding.is_empty() {
                outbound["packet_encoding"] =
                    serde_json::Value::String(node.packet_encoding.clone());
            }
        }
        "vless" => {
            outbound["uuid"] = serde_json::Value::String(node.uuid.clone());
            if !node.flow.is_empty() {
                outbound["flow"] = serde_json::Value::String(node.flow.clone());
            }
            if !node.packet_encoding.is_empty() {
                outbound["packet_encoding"] =
                    serde_json::Value::String(node.packet_encoding.clone());
            }
        }
        "shadowsocks" => {
            outbound["method"] = serde_json::Value::String(node.method.clone());
            outbound["password"] = serde_json::Value::String(node.password.clone());
            if !node.plugin.is_empty() {
                outbound["plugin"] = serde_json::Value::String(node.plugin.clone());
            }
            if !node.plugin_options.is_empty() {
                outbound["plugin_opts"] = serde_json::Value::String(node.plugin_options.clone());
            }
        }
        "socks" => {
            outbound["version"] = serde_json::Value::String(if node.version == 0 {
                "5".into()
            } else {
                node.version.to_string()
            });
            if !node.username.is_empty() {
                outbound["username"] = serde_json::Value::String(node.username.clone());
            }
            if !node.password.is_empty() {
                outbound["password"] = serde_json::Value::String(node.password.clone());
            }
        }
        "http" => {
            if !node.username.is_empty() {
                outbound["username"] = serde_json::Value::String(node.username.clone());
            }
            if !node.password.is_empty() {
                outbound["password"] = serde_json::Value::String(node.password.clone());
            }
        }
        "wireguard" => {
            if !node.private_key.is_empty() {
                outbound["private_key"] = serde_json::Value::String(node.private_key.clone());
            }
            if !node.peer_public_key.is_empty() {
                outbound["peer_public_key"] =
                    serde_json::Value::String(node.peer_public_key.clone());
            }
            if !node.pre_shared_key.is_empty() {
                outbound["pre_shared_key"] = serde_json::Value::String(node.pre_shared_key.clone());
            }
            if !node.local_address.is_empty() {
                outbound["local_address"] = serde_json::Value::Array(
                    split_rule_values(&node.local_address)
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                );
            }
            if node.wireguard_system_interface {
                outbound["system_interface"] = serde_json::Value::Bool(true);
            }
            if !node.wireguard_interface_name.is_empty() {
                outbound["interface_name"] =
                    serde_json::Value::String(node.wireguard_interface_name.clone());
            }
            if node.wireguard_mtu > 0 {
                outbound["mtu"] = serde_json::Value::Number(node.wireguard_mtu.into());
            }
            if node.wireguard_workers > 0 {
                outbound["workers"] = serde_json::Value::Number(node.wireguard_workers.into());
            }
            if !node.wireguard_network.is_empty() {
                outbound["network"] = serde_json::Value::String(node.wireguard_network.clone());
            }
            if !node.wireguard_reserved.is_empty() {
                outbound["reserved"] = serde_json::Value::Array(
                    parse_rule_numbers::<u8>("WireGuard reserved", &node.wireguard_reserved)?
                        .into_iter()
                        .map(|value| serde_json::Value::Number(value.into()))
                        .collect(),
                );
            }
        }
        "hysteria" => {
            if (node.up_mbps == 0 && node.up_bandwidth.is_empty())
                || (node.down_mbps == 0 && node.down_bandwidth.is_empty())
            {
                return Err(format!(
                    "出站 {} 的 Hysteria 上下行带宽必须大于 0",
                    node.tag
                ));
            }
            if !node.up_bandwidth.is_empty() {
                outbound["up"] = serde_json::Value::String(node.up_bandwidth.clone());
            } else {
                outbound["up_mbps"] = serde_json::Value::Number(node.up_mbps.into());
            }
            if !node.down_bandwidth.is_empty() {
                outbound["down"] = serde_json::Value::String(node.down_bandwidth.clone());
            } else {
                outbound["down_mbps"] = serde_json::Value::Number(node.down_mbps.into());
            }
            if !node.server_ports.is_empty() {
                outbound["server_ports"] = serde_json::Value::Array(
                    split_rule_values(&node.server_ports)
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                );
            }
            if !node.hop_interval.is_empty() {
                outbound["hop_interval"] = serde_json::Value::String(node.hop_interval.clone());
            }
            if !node.network.is_empty() {
                outbound["network"] = serde_json::Value::String(node.network.clone());
            }
            if !node.auth_base64.is_empty() {
                outbound["auth"] = serde_json::Value::String(node.auth_base64.clone());
            }
            if !node.password.is_empty() {
                outbound["auth_str"] = serde_json::Value::String(node.password.clone());
            }
            if !node.obfs_password.is_empty() {
                outbound["obfs"] = serde_json::Value::String(node.obfs_password.clone());
            }
        }
        "hysteria2" => {
            if node.up_mbps > 0 {
                outbound["up_mbps"] = serde_json::Value::Number(node.up_mbps.into());
            }
            if node.down_mbps > 0 {
                outbound["down_mbps"] = serde_json::Value::Number(node.down_mbps.into());
            }
            if !node.server_ports.is_empty() {
                outbound["server_ports"] = serde_json::Value::Array(
                    split_rule_values(&node.server_ports)
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                );
            }
            if !node.hop_interval.is_empty() {
                outbound["hop_interval"] = serde_json::Value::String(node.hop_interval.clone());
            }
            if !node.hop_interval_max.is_empty() {
                outbound["hop_interval_max"] =
                    serde_json::Value::String(node.hop_interval_max.clone());
            }
            if !node.network.is_empty() {
                outbound["network"] = serde_json::Value::String(node.network.clone());
            }
            if !node.password.is_empty() {
                outbound["password"] = serde_json::Value::String(node.password.clone());
            }
            if !node.obfs.is_empty() {
                outbound["obfs"] =
                    serde_json::json!({ "type": node.obfs, "password": node.obfs_password });
            }
        }
        "shadowtls" => {
            outbound["version"] = serde_json::Value::Number(
                (if node.version == 0 { 3 } else { node.version }).into(),
            );
            if !node.password.is_empty() {
                outbound["password"] = serde_json::Value::String(node.password.clone());
            }
        }
        "tuic" => {
            outbound["uuid"] = serde_json::Value::String(node.uuid.clone());
            outbound["password"] = serde_json::Value::String(node.password.clone());
            if !node.congestion_control.is_empty() {
                outbound["congestion_control"] =
                    serde_json::Value::String(node.congestion_control.clone());
            }
            if !node.udp_relay_mode.is_empty() {
                outbound["udp_relay_mode"] = serde_json::Value::String(node.udp_relay_mode.clone());
            }
            outbound["udp_over_stream"] = serde_json::Value::Bool(node.tuic_udp_over_stream);
            outbound["zero_rtt_handshake"] = serde_json::Value::Bool(node.zero_rtt_handshake);
            if !node.heartbeat.is_empty() {
                outbound["heartbeat"] = serde_json::Value::String(node.heartbeat.clone());
            }
            if !node.network.is_empty() {
                outbound["network"] = serde_json::Value::String(node.network.clone());
            }
        }
        "anytls" => {
            outbound["password"] = serde_json::Value::String(node.password.clone());
            if !node.idle_session_check_interval.is_empty() {
                outbound["idle_session_check_interval"] =
                    serde_json::Value::String(node.idle_session_check_interval.clone());
            }
            if !node.idle_session_expiration.is_empty() {
                outbound["idle_session_timeout"] =
                    serde_json::Value::String(node.idle_session_expiration.clone());
            }
            if node.min_idle_session > 0 {
                outbound["min_idle_session"] =
                    serde_json::Value::Number(node.min_idle_session.into());
            }
            if !node.anytls_client_metadata.is_empty() {
                outbound["client_metadata"] =
                    serde_json::Value::String(node.anytls_client_metadata.clone());
            }
        }
        "snell" => {
            outbound["version"] = serde_json::Value::Number(
                (if node.version == 0 { 4 } else { node.version }).into(),
            );
            outbound["psk"] = serde_json::Value::String(node.psk.clone());
            if !node.snell_userkey.is_empty() {
                outbound["userkey"] = serde_json::Value::String(node.snell_userkey.clone());
            }
            outbound["reuse"] = serde_json::Value::Bool(node.snell_reuse);
            if !node.snell_obfs_mode.is_empty() {
                outbound["obfs_mode"] = serde_json::Value::String(node.snell_obfs_mode.clone());
            }
            if !node.snell_obfs_host.is_empty() {
                outbound["obfs_host"] = serde_json::Value::String(node.snell_obfs_host.clone());
            }
            if !node.snell_mode.is_empty() {
                outbound["mode"] = serde_json::Value::String(node.snell_mode.clone());
            }
            if !node.network.is_empty() {
                outbound["network"] = serde_json::Value::String(node.network.clone());
            }
        }
        "ssh" => {
            if !node.username.is_empty() {
                outbound["user"] = serde_json::Value::String(node.username.clone());
            }
            if !node.password.is_empty() {
                outbound["password"] = serde_json::Value::String(node.password.clone());
            }
            if !node.private_key_path.is_empty() {
                outbound["private_key_path"] =
                    serde_json::Value::String(node.private_key_path.clone());
            }
            if !node.ssh_private_key.is_empty() {
                outbound["private_key"] = serde_json::Value::String(node.ssh_private_key.clone());
            }
            if !node.ssh_private_key_passphrase.is_empty() {
                outbound["private_key_passphrase"] =
                    serde_json::Value::String(node.ssh_private_key_passphrase.clone());
            }
            if !node.ssh_host_key.is_empty() {
                outbound["host_key"] = serde_json::Value::Array(
                    split_rule_values(&node.ssh_host_key)
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                );
            }
            if !node.ssh_host_key_algorithms.is_empty() {
                outbound["host_key_algorithms"] = serde_json::Value::Array(
                    split_rule_values(&node.ssh_host_key_algorithms)
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                );
            }
            if !node.ssh_client_version.is_empty() {
                outbound["client_version"] =
                    serde_json::Value::String(node.ssh_client_version.clone());
            }
            for (field, raw) in [
                ("cipher", &node.ssh_cipher),
                ("mac", &node.ssh_mac),
                ("kex_algorithm", &node.ssh_kex_algorithm),
            ] {
                if !raw.is_empty() {
                    outbound[field] = serde_json::Value::Array(
                        split_rule_values(raw)
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    );
                }
            }
        }
        "naive" => {
            if !node.username.is_empty() {
                outbound["username"] = serde_json::Value::String(node.username.clone());
            }
            if !node.password.is_empty() {
                outbound["password"] = serde_json::Value::String(node.password.clone());
            }
            outbound["quic"] = serde_json::Value::Bool(node.zero_rtt_handshake);
        }
        "tor" => {
            if !node.executable_path.is_empty() {
                outbound["executable_path"] =
                    serde_json::Value::String(node.executable_path.clone());
            }
            if !node.data_directory.is_empty() {
                outbound["data_directory"] = serde_json::Value::String(node.data_directory.clone());
            }
            if let Some(args) = parse_optional_json(&node.tor_args, "Tor args", &node.tag)? {
                outbound["args"] = args;
            }
        }
        _ => {
            return Err(format!(
                "出站 {} 使用了暂不支持的协议 {}",
                node.tag, node.kind
            ))
        }
    }

    apply_common_outbound_fields(&mut outbound, node)?;

    if node.tls_enabled
        && matches!(
            node.kind.as_str(),
            "trojan"
                | "vmess"
                | "vless"
                | "http"
                | "hysteria"
                | "hysteria2"
                | "shadowtls"
                | "tuic"
                | "anytls"
                | "naive"
        )
    {
        let mut tls = serde_json::json!({ "enabled": true });
        if !node.tls_engine.is_empty() {
            tls["engine"] = serde_json::Value::String(node.tls_engine.clone());
        }
        if node.tls_disable_sni {
            tls["disable_sni"] = serde_json::Value::Bool(true);
        }
        if !node.sni.is_empty() {
            tls["server_name"] = serde_json::Value::String(node.sni.clone());
        }
        if node.insecure {
            tls["insecure"] = serde_json::Value::Bool(true);
        }
        if !node.tls_alpn.is_empty() {
            tls["alpn"] = serde_json::Value::Array(
                split_rule_values(&node.tls_alpn)
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }
        if !node.tls_min_version.is_empty() {
            tls["min_version"] = serde_json::Value::String(node.tls_min_version.clone());
        }
        if !node.tls_max_version.is_empty() {
            tls["max_version"] = serde_json::Value::String(node.tls_max_version.clone());
        }
        if !node.tls_certificate_path.is_empty() {
            tls["certificate_path"] = serde_json::Value::String(node.tls_certificate_path.clone());
        }
        if !node.tls_certificate_public_key_sha256.is_empty() {
            tls["certificate_public_key_sha256"] = serde_json::Value::Array(
                split_rule_values(&node.tls_certificate_public_key_sha256)
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }
        if !node.tls_handshake_timeout.is_empty() {
            tls["handshake_timeout"] =
                serde_json::Value::String(node.tls_handshake_timeout.clone());
        }
        if !node.tls_utl_fingerprint.is_empty() {
            tls["utls"] =
                serde_json::json!({ "enabled": true, "fingerprint": node.tls_utl_fingerprint });
        }
        if !node.tls_reality_public_key.is_empty() || !node.tls_reality_short_id.is_empty() {
            let mut reality = serde_json::json!({ "enabled": true });
            if !node.tls_reality_public_key.is_empty() {
                reality["public_key"] =
                    serde_json::Value::String(node.tls_reality_public_key.clone());
            }
            if !node.tls_reality_short_id.is_empty() {
                reality["short_id"] = serde_json::Value::String(node.tls_reality_short_id.clone());
            }
            tls["reality"] = reality;
        }
        outbound["tls"] = tls;
    }
    if !matches!(
        node.kind.as_str(),
        "hysteria" | "hysteria2" | "tuic" | "snell"
    ) {
        let mut transport = match node.network.as_str() {
            "ws" => serde_json::json!({ "type": "ws" }),
            "http" => serde_json::json!({ "type": "http" }),
            "grpc" => serde_json::json!({ "type": "grpc" }),
            "quic" => serde_json::json!({ "type": "quic" }),
            "httpupgrade" => serde_json::json!({ "type": "httpupgrade" }),
            _ => serde_json::Value::Null,
        };
        if !transport.is_null() {
            match node.network.as_str() {
                "ws" => {
                    if !node.ws_path.is_empty() {
                        transport["path"] = serde_json::Value::String(node.ws_path.clone());
                    }
                    if !node.ws_host.is_empty() {
                        transport["headers"] = serde_json::json!({ "Host": node.ws_host });
                    }
                    if node.transport_max_early_data > 0 {
                        transport["max_early_data"] =
                            serde_json::Value::Number(node.transport_max_early_data.into());
                    }
                    if !node.transport_early_data_header_name.is_empty() {
                        transport["early_data_header_name"] = serde_json::Value::String(
                            node.transport_early_data_header_name.clone(),
                        );
                    }
                }
                "http" => {
                    if !node.ws_host.is_empty() {
                        transport["host"] = serde_json::Value::Array(
                            split_rule_values(&node.ws_host)
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        );
                    }
                    if !node.ws_path.is_empty() {
                        transport["path"] = serde_json::Value::String(node.ws_path.clone());
                    }
                    if !node.transport_method.is_empty() {
                        transport["method"] =
                            serde_json::Value::String(node.transport_method.clone());
                    }
                    if !node.transport_idle_timeout.is_empty() {
                        transport["idle_timeout"] =
                            serde_json::Value::String(node.transport_idle_timeout.clone());
                    }
                    if !node.transport_ping_timeout.is_empty() {
                        transport["ping_timeout"] =
                            serde_json::Value::String(node.transport_ping_timeout.clone());
                    }
                }
                "grpc" => {
                    if !node.transport_service_name.is_empty() {
                        transport["service_name"] =
                            serde_json::Value::String(node.transport_service_name.clone());
                    }
                    if !node.transport_idle_timeout.is_empty() {
                        transport["idle_timeout"] =
                            serde_json::Value::String(node.transport_idle_timeout.clone());
                    }
                    if !node.transport_ping_timeout.is_empty() {
                        transport["ping_timeout"] =
                            serde_json::Value::String(node.transport_ping_timeout.clone());
                    }
                    if node.transport_permit_without_stream {
                        transport["permit_without_stream"] = serde_json::Value::Bool(true);
                    }
                }
                "quic" => {
                    if !node.transport_quic_security.is_empty() {
                        transport["security"] =
                            serde_json::Value::String(node.transport_quic_security.clone());
                    }
                    if !node.transport_quic_key.is_empty() {
                        transport["key"] =
                            serde_json::Value::String(node.transport_quic_key.clone());
                    }
                }
                "httpupgrade" => {
                    if !node.ws_host.is_empty() {
                        transport["host"] = serde_json::Value::String(node.ws_host.clone());
                    }
                    if !node.ws_path.is_empty() {
                        transport["path"] = serde_json::Value::String(node.ws_path.clone());
                    }
                }
                _ => {}
            }
            if let Some(headers) =
                parse_optional_json(&node.transport_headers, "transport.headers", &node.tag)?
            {
                transport["headers"] = headers;
            }
            outbound["transport"] = transport;
        }
    }
    merge_extra_json(&mut outbound, &node.extra_json, &node.tag)?;
    Ok(outbound)
}

fn split_rule_values(raw: &str) -> Vec<String> {
    raw.lines()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn required_rule_values(field: &str, raw: &str) -> Result<Vec<String>, String> {
    let values = split_rule_values(raw);
    if values.is_empty() {
        return Err(format!("规则字段 {field} 不能为空"));
    }
    Ok(values)
}

fn parse_rule_numbers<T>(field: &str, raw: &str) -> Result<Vec<T>, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let values = split_rule_values(raw);
    if values.is_empty() {
        return Err(format!("规则字段 {field} 不能为空"));
    }
    values
        .iter()
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|error| format!("规则字段 {field} 包含无效数字 {value}：{error}"))
        })
        .collect()
}

fn parse_rule_bool(field: &str, raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "是" => Ok(true),
        "false" | "0" | "否" => Ok(false),
        _ => Err(format!("规则字段 {field} 只能填写 true 或 false")),
    }
}

fn parse_interface_addresses(field: &str, raw: &str) -> Result<serde_json::Value, String> {
    let mut addresses = serde_json::Map::new();
    for entry in raw.lines().flat_map(|line| line.split(',')) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (interface, address) = entry
            .split_once('=')
            .ok_or_else(|| format!("规则字段 {field} 应使用 interface=cidr 格式"))?;
        let interface = interface.trim();
        let address = address.trim();
        if interface.is_empty() || address.is_empty() {
            return Err(format!("规则字段 {field} 包含空的网卡或地址"));
        }
        let values = addresses
            .entry(interface.to_string())
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        values
            .as_array_mut()
            .expect("interface address values must be an array")
            .push(serde_json::Value::String(address.to_string()));
    }
    if addresses.is_empty() {
        return Err(format!("规则字段 {field} 不能为空"));
    }
    Ok(serde_json::Value::Object(addresses))
}

fn rule_field(field: &str, value: serde_json::Value) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(field.to_string(), value);
    serde_json::Value::Object(object)
}

fn render_field_condition(condition: &RuleCondition) -> Result<serde_json::Value, String> {
    let field = condition.field.trim();
    let value = condition.value.trim();
    if field.is_empty() {
        return Err("规则匹配字段不能为空".into());
    }

    let mut rendered = match field {
        "inbound" | "auth_user" | "protocol" | "client" | "network" | "domain"
        | "domain_suffix" | "domain_keyword" | "domain_regex" | "source_ip_cidr" | "ip_cidr"
        | "source_port_range" | "port_range" | "process_name" | "process_path"
        | "process_path_regex" | "package_name" | "user" | "network_type" | "wifi_ssid"
        | "wifi_bssid" | "preferred_by" | "rule_set" => rule_field(
            field,
            serde_json::json!(required_rule_values(field, value)?),
        ),
        "source_port" | "port" => rule_field(
            field,
            serde_json::json!(parse_rule_numbers::<u16>(field, value)?),
        ),
        "user_id" => rule_field(
            field,
            serde_json::json!(parse_rule_numbers::<u32>(field, value)?),
        ),
        "ip_version" => {
            let version = value
                .parse::<u8>()
                .map_err(|error| format!("规则字段 ip_version 无效：{error}"))?;
            if version != 4 && version != 6 {
                return Err("规则字段 ip_version 只能是 4 或 6".into());
            }
            rule_field(field, serde_json::json!(version))
        }
        "ip_is_private"
        | "source_ip_is_private"
        | "network_is_expensive"
        | "network_is_constrained"
        | "rule_set_ip_cidr_match_source" => {
            rule_field(field, serde_json::json!(parse_rule_bool(field, value)?))
        }
        "clash_mode" => {
            if value.is_empty() {
                return Err(format!("规则字段 {field} 不能为空"));
            }
            rule_field(field, serde_json::json!(value))
        }
        "interface_address" | "network_interface_address" => {
            rule_field(field, parse_interface_addresses(field, value)?)
        }
        "default_interface_address" => rule_field(
            field,
            serde_json::json!(required_rule_values(field, value)?),
        ),
        _ => return Err(format!("暂不支持 sing-box 规则字段：{field}")),
    };

    if condition.invert {
        rendered["invert"] = serde_json::Value::Bool(true);
    }
    Ok(rendered)
}

fn render_condition(condition: &RuleCondition) -> Result<serde_json::Value, String> {
    if condition.kind == "logical" {
        if condition.mode != "and" && condition.mode != "or" {
            return Err("逻辑规则模式只能是 AND 或 OR".into());
        }
        if condition.rules.is_empty() {
            return Err("逻辑规则至少需要一个子条件".into());
        }
        let rules = condition
            .rules
            .iter()
            .map(render_condition)
            .collect::<Result<Vec<_>, _>>()?;
        let mut rendered = serde_json::json!({
            "type": "logical",
            "mode": condition.mode,
            "rules": rules
        });
        if condition.invert {
            rendered["invert"] = serde_json::Value::Bool(true);
        }
        Ok(rendered)
    } else if condition.kind == "field" {
        render_field_condition(condition)
    } else {
        Err(format!("未知规则节点类型：{}", condition.kind))
    }
}

fn validate_rule_set_references(condition: &RuleCondition, tags: &[String]) -> Result<(), String> {
    if condition.kind == "logical" {
        for child in &condition.rules {
            validate_rule_set_references(child, tags)?;
        }
    } else if condition.kind == "field" && condition.field == "rule_set" {
        for tag in split_rule_values(&condition.value) {
            if !tags.iter().any(|known| known == &tag) {
                return Err(format!("规则集 {tag} 未配置"));
            }
        }
    }
    Ok(())
}

fn render_rule(rule: &ProxyRule, rule_set_tags: &[String]) -> Result<serde_json::Value, String> {
    let condition = rule
        .condition
        .as_ref()
        .ok_or_else(|| format!("规则 {} 缺少匹配条件", rule.id))?;
    validate_rule_set_references(condition, rule_set_tags)?;
    let mut rendered = render_condition(condition)?;
    match rule.action.as_str() {
        "route" => {
            if rule.outbound.trim().is_empty() {
                return Err(format!("规则 {} 未选择出站", rule.id));
            }
            rendered["action"] = serde_json::Value::String("route".into());
            rendered["outbound"] = serde_json::Value::String(rule.outbound.clone());
        }
        "reject" => rendered["action"] = serde_json::Value::String("reject".into()),
        "hijack-dns" => rendered["action"] = serde_json::Value::String("hijack-dns".into()),
        action => return Err(format!("规则 {} 使用了不支持的动作 {action}", rule.id)),
    }
    Ok(rendered)
}

fn render_rule_set(rule_set: &RuleSetConfig) -> Result<serde_json::Value, String> {
    if rule_set.tag.trim().is_empty() {
        return Err("规则集标签不能为空".into());
    }
    if rule_set.format != "source" && rule_set.format != "binary" {
        return Err(format!(
            "规则集 {} 的格式只能是 source 或 binary",
            rule_set.tag
        ));
    }
    let mut rendered = serde_json::json!({
        "type": rule_set.kind,
        "tag": rule_set.tag,
        "format": rule_set.format
    });
    match rule_set.kind.as_str() {
        "local" => {
            if rule_set.path.trim().is_empty() {
                return Err(format!("本地规则集 {} 缺少路径", rule_set.tag));
            }
            rendered["path"] = serde_json::Value::String(rule_set.path.clone());
        }
        "remote" => {
            if rule_set.url.trim().is_empty() {
                return Err(format!("远程规则集 {} 缺少 URL", rule_set.tag));
            }
            rendered["url"] = serde_json::Value::String(rule_set.url.clone());
            if !rule_set.update_interval.trim().is_empty() {
                rendered["update_interval"] =
                    serde_json::Value::String(rule_set.update_interval.clone());
            }
        }
        kind => return Err(format!("规则集 {} 使用了不支持的类型 {kind}", rule_set.tag)),
    }
    Ok(rendered)
}

#[cfg(test)]
fn render_runtime_config(
    settings: &RuntimeSettings,
    proxy: &ProxyConfig,
) -> Result<String, String> {
    render_runtime_config_for(settings, proxy, false)
}

fn render_runtime_config_for(
    settings: &RuntimeSettings,
    proxy: &ProxyConfig,
    guest: bool,
) -> Result<String, String> {
    validate_settings(settings)?;
    let use_fakeip = guest && settings.mode == "gateway" && settings.dns_mode == "fakeip";
    let upstream_dns_tag = if settings.dns_mode == "custom" {
        "custom-dns"
    } else {
        "system-dns"
    };
    let upstream_dns = if settings.dns_mode == "custom" {
        serde_json::json!({
            "type": "udp",
            "server": settings.dns_server.trim(),
            "tag": upstream_dns_tag
        })
    } else {
        serde_json::json!({
            "type": "local",
            "tag": upstream_dns_tag
        })
    };
    let dns_servers = if use_fakeip {
        vec![
            serde_json::json!({
                "type": "fakeip",
                "tag": "fakeip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            }),
            upstream_dns,
        ]
    } else {
        vec![upstream_dns]
    };
    let dns_rules = if use_fakeip {
        serde_json::json!([
            {
                "domain_suffix": ["lan", "local"],
                "server": upstream_dns_tag
            },
            {
                "domain": ["localhost"],
                "server": upstream_dns_tag
            },
            {
                "query_type": ["A", "AAAA"],
                "server": "fakeip"
            }
        ])
    } else {
        serde_json::json!([])
    };

    // 出站：direct + 用户节点 + 策略组
    let mut outbounds: Vec<serde_json::Value> = vec![serde_json::json!({
        "type": "direct",
        "tag": "direct"
    })];
    for node in &proxy.nodes {
        outbounds.push(render_outbound(node)?);
    }
    for group in &proxy.groups {
        let mut group_outbound = serde_json::json!({
            "type": group.kind,
            "tag": group.name,
            "outbounds": group.members
        });
        if group.kind == "selector" {
            group_outbound["default"] = serde_json::Value::String(group.default.clone());
            if group.interrupt_exist_connections {
                group_outbound["interrupt_exist_connections"] = serde_json::Value::Bool(true);
            }
        } else if group.kind == "urltest" {
            if !group.url.is_empty() {
                group_outbound["url"] = serde_json::Value::String(group.url.clone());
            }
            if !group.interval.is_empty() {
                group_outbound["interval"] = serde_json::Value::String(group.interval.clone());
            }
            if group.tolerance > 0 {
                group_outbound["tolerance"] = serde_json::Value::Number(group.tolerance.into());
            }
            if !group.idle_timeout.is_empty() {
                group_outbound["idle_timeout"] =
                    serde_json::Value::String(group.idle_timeout.clone());
            }
        }
        outbounds.push(group_outbound);
    }

    // 规则
    let mut rules: Vec<serde_json::Value> = vec![];
    let rule_set_tags = proxy
        .rule_sets
        .iter()
        .map(|rule_set| rule_set.tag.clone())
        .collect::<Vec<_>>();
    for rule in &proxy.rules {
        if rule.enabled {
            rules.push(render_rule(rule, &rule_set_tags)?);
        }
    }
    if guest && settings.mode == "gateway" {
        let mut gateway_rules = Vec::new();
        if use_fakeip {
            gateway_rules.push(serde_json::json!({
                "inbound": ["tun-in"],
                "action": "resolve"
            }));
        }
        gateway_rules.push(serde_json::json!({
            "action": "sniff",
            "sniffer": ["http", "tls", "quic", "dns"],
            "timeout": "300ms"
        }));
        gateway_rules.push(serde_json::json!({
            "inbound": ["tun-in"],
            "protocol": "dns",
            "action": "hijack-dns"
        }));
        gateway_rules.extend(rules);
        rules = gateway_rules;
    }

    let rendered_rule_sets = proxy
        .rule_sets
        .iter()
        .map(render_rule_set)
        .collect::<Result<Vec<_>, _>>()?;

    // 最终出站：优先用第一个策略组，否则 direct
    let final_outbound = proxy
        .groups
        .first()
        .map(|group| group.name.clone())
        .unwrap_or_else(|| "direct".into());

    let mut route = serde_json::json!({
        "rules": rules,
        "final": final_outbound,
        "default_domain_resolver": upstream_dns_tag
    });
    if !rendered_rule_sets.is_empty() {
        route["rule_set"] = serde_json::Value::Array(rendered_rule_sets);
    }

    let mut inbounds = vec![serde_json::json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": settings.listen.trim(),
        "listen_port": settings.port
    })];
    if guest && settings.mode == "gateway" {
        inbounds.insert(
            0,
            serde_json::json!({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "address": ["172.19.0.1/30"],
                "auto_route": false,
                "strict_route": false,
                "stack": "mixed"
            }),
        );
    }

    let mut route = route;
    if guest && settings.mode == "gateway" {
        route["auto_detect_interface"] = serde_json::Value::Bool(true);
    }

    let config = serde_json::json!({
        "log": {
            "level": settings.log_level,
            "timestamp": true
        },
        "experimental": {
            "clash_api": {
                "external_controller": CLASH_API_ADDR,
                "external_ui": "",
                "secret": "",
                "default_mode": "rule"
            }
        },
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": upstream_dns_tag,
            "strategy": "prefer_ipv4"
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route
    });
    serde_json::to_string_pretty(&config)
        .map_err(|error| format!("无法生成 sing-box 配置：{error}"))
}

fn apply_module_runtime_plan(
    rendered: &mut serde_json::Value,
    settings: &RuntimeSettings,
    module_plan: &ModuleRuntimePlan,
    guest: bool,
) -> Result<(), String> {
    if let Some(rules) = rendered["route"]["rules"].as_array_mut() {
        let mut module_rules = module_route_rules(module_plan);
        if module_plan_requires_mitm(module_plan) {
            module_rules.extend(module_mitm_route_rules(module_plan));
        }
        module_rules.append(rules);
        *rules = module_rules;
    }
    if module_plan_requires_mitm(module_plan) {
        let module_proxy_host = if guest {
            "127.0.0.1".to_string()
        } else {
            module_proxy_host(settings)
        };
        let module_proxy_port = module_proxy_port(module_plan);
        rendered["outbounds"]
            .as_array_mut()
            .expect("sing-box outbounds must be an array")
            .push(serde_json::json!({
                "type": "http",
                "tag": "module-mitm",
                "server": module_proxy_host,
                "server_port": module_proxy_port
            }));
    }
    Ok(())
}

fn render_runtime_config_document(
    settings: &RuntimeSettings,
    proxy: &ProxyConfig,
    module_plan: &ModuleRuntimePlan,
    guest: bool,
) -> Result<String, String> {
    let mut rendered: serde_json::Value =
        serde_json::from_str(&render_runtime_config_for(settings, proxy, guest)?)
            .map_err(|error| format!("运行配置不是有效 JSON：{error}"))?;
    apply_module_runtime_plan(&mut rendered, settings, module_plan, guest)?;
    if guest {
        let tun = rendered["inbounds"]
            .as_array_mut()
            .and_then(|inbounds| {
                inbounds
                    .iter_mut()
                    .find(|inbound| inbound["tag"].as_str() == Some("tun-in"))
            })
            .ok_or_else(|| "Linux guest 配置缺少 tun-in 入站".to_string())?;
        // auto_redirect is Linux-only; the host-side macOS config deliberately omits it.
        tun["interface_name"] = serde_json::Value::String("tun0".into());
        tun["auto_route"] = serde_json::Value::Bool(true);
        tun["strict_route"] = serde_json::Value::Bool(true);
        tun["auto_redirect"] = serde_json::Value::Bool(true);
        // Keep the guest data plane independent from sing-box defaults. The
        // explicit split default route and marks are required for forwarded
        // LAN packets, which do not originate from a local process.
        tun["route_address"] = serde_json::json!(["0.0.0.0/1", "128.0.0.0/1"]);
        tun["iproute2_table_index"] = serde_json::json!(2022);
        tun["iproute2_rule_index"] = serde_json::json!(9000);
        tun["auto_redirect_input_mark"] = serde_json::json!("0x2023");
        tun["auto_redirect_output_mark"] = serde_json::json!("0x2024");
        tun["auto_redirect_reset_mark"] = serde_json::json!("0x2025");
        if !tun
            .get("route_exclude_address")
            .map(serde_json::Value::is_array)
            .unwrap_or(false)
        {
            tun["route_exclude_address"] = serde_json::Value::Array(Vec::new());
        }
        let excluded_routes = tun["route_exclude_address"]
            .as_array_mut()
            .expect("route_exclude_address is initialized as an array");
        for cidr in [
            "223.86.225.0/24",
            settings.gateway_cidr.trim(),
            settings.gateway_host_cidr.trim(),
        ] {
            if !cidr.is_empty()
                && !excluded_routes
                    .iter()
                    .any(|value| value.as_str() == Some(cidr))
            {
                excluded_routes.push(serde_json::Value::String(cidr.to_string()));
            }
        }
    }
    let content = serde_json::to_string_pretty(&rendered)
        .map_err(|error| format!("无法序列化运行配置：{error}"))?;
    Ok(format!("{content}\n"))
}

fn write_runtime_config(
    app: &AppHandle,
    settings: &RuntimeSettings,
    module_plan: &ModuleRuntimePlan,
) -> Result<PathBuf, String> {
    let directory = app_data_dir(app)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let path = runtime_config_path(app)?;
    let proxy = load_proxy_config(app)?;
    let content = render_runtime_config_document(settings, &proxy, module_plan, false)?;
    write_private_file(&path, content.as_bytes())
        .map_err(|error| format!("无法写入运行配置 {}：{error}", path.display()))?;
    Ok(path)
}

fn write_gateway_guest_runtime_config(
    app: &AppHandle,
    settings: &RuntimeSettings,
    module_plan: &ModuleRuntimePlan,
) -> Result<PathBuf, String> {
    if settings.mode != "gateway" {
        return Err("只有 Gateway 模式可以生成 Linux guest 配置".into());
    }
    let directory = app_data_dir(app)?;
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let path = gateway_guest_runtime_config_path(app)?;
    let proxy = load_gateway_guest_proxy_config(app)?;
    let content = render_runtime_config_document(settings, &proxy, module_plan, true)?;
    write_private_file(&path, content.as_bytes())
        .map_err(|error| format!("无法写入 Linux guest 运行配置 {}：{error}", path.display()))?;
    Ok(path)
}

fn resolve_mitmproxy_binary(app: &AppHandle) -> PathBuf {
    if let Ok(path) = env::var("SONGSTERX_MITMDUMP_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return path;
        }
    }
    for resource_name in ["mitmdump", "mitmdump.exe"] {
        if let Ok(path) = app.path().resolve(resource_name, BaseDirectory::Resource) {
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("mitmdump")
}

fn resolve_mitmproxy_addon(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(path) = app
        .path()
        .resolve("scripts/mitm_minimal_addon.py", BaseDirectory::Resource)
    {
        if path.is_file() {
            return Ok(path);
        }
    }
    let workspace_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/mitm_minimal_addon.py");
    if workspace_path.is_file() {
        return Ok(workspace_path);
    }
    Err("找不到模块 MITM addon：scripts/mitm_minimal_addon.py".into())
}

fn module_plan_requires_mitm(plan: &ModuleRuntimePlan) -> bool {
    !plan.mitm_hostnames.is_empty()
        || !plan.url_rewrites.is_empty()
        || !plan.map_locals.is_empty()
        || !plan.header_rewrites.is_empty()
}

fn module_proxy_host(settings: &RuntimeSettings) -> String {
    if settings.mode == "gateway" {
        settings.gateway_host_ip.trim().to_string()
    } else {
        "127.0.0.1".into()
    }
}

fn module_proxy_probe_host(settings: &RuntimeSettings) -> &str {
    if settings.mode == "gateway" {
        // The host-only vmnet address is created by the Gateway supervisor
        // later in the startup transaction. The caller probes the configured
        // host first to catch a specific-address listener, then falls back to
        // the wildcard address only while the host-only address is unavailable.
        "0.0.0.0"
    } else {
        "127.0.0.1"
    }
}

fn module_proxy_port(plan: &ModuleRuntimePlan) -> u16 {
    plan.proxy_port.unwrap_or(DEFAULT_MODULE_PROXY_PORT)
}

fn bind_module_proxy_listener(
    settings: &RuntimeSettings,
    port: u16,
) -> Result<TcpListener, String> {
    let host = module_proxy_host(settings);
    let probe_host = module_proxy_probe_host(settings);
    match TcpListener::bind((host.as_str(), port)) {
        Ok(listener) => Ok(listener),
        Err(host_error)
            if settings.mode == "gateway"
                && host_error.kind() == io::ErrorKind::AddrNotAvailable =>
        {
            TcpListener::bind((probe_host, port)).map_err(|probe_error| {
                format!(
                    "{}:{} 不可用（{}）；{}:{} 也不可用（{}）",
                    host, port, host_error, probe_host, port, probe_error
                )
            })
        }
        Err(host_error) => Err(format!("{}:{} 不可用：{}", host, port, host_error)),
    }
}

fn select_module_proxy_port(settings: &RuntimeSettings) -> Result<u16, String> {
    let host = module_proxy_host(settings);
    let mut last_error = None;
    let candidates = std::iter::once(DEFAULT_MODULE_PROXY_PORT)
        .chain(FALLBACK_MODULE_PROXY_PORT_START..=FALLBACK_MODULE_PROXY_PORT_END);
    for port in candidates {
        match bind_module_proxy_listener(settings, port) {
            Ok(listener) => {
                drop(listener);
                return Ok(port);
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    if let Ok(listener) = bind_module_proxy_listener(settings, 0) {
        if let Ok(address) = listener.local_addr() {
            return Ok(address.port());
        }
    }
    Err(format!(
        "模块 MITM 监听地址 {} 无可用端口（已尝试 {} 和 {}-{}；最后错误：{}）",
        host,
        DEFAULT_MODULE_PROXY_PORT,
        FALLBACK_MODULE_PROXY_PORT_START,
        FALLBACK_MODULE_PROXY_PORT_END,
        last_error.unwrap_or_else(|| "无法申请临时端口".into())
    ))
}

fn module_proxy_endpoint(settings: &RuntimeSettings, port: u16) -> String {
    format!("{}:{port}", module_proxy_host(settings))
}

fn runtime_phase_is_active(state: &RuntimeState) -> Result<bool, String> {
    let phase = state
        .lifecycle_phase
        .lock()
        .map_err(|_| "Gateway 生命周期锁不可用".to_string())?;
    Ok(matches!(
        *phase,
        LifecyclePhase::Starting | LifecyclePhase::Running | LifecyclePhase::Stopping
    ))
}

fn runtime_mutation_allowed(state: &RuntimeState) -> Result<(), String> {
    let phase = state
        .lifecycle_phase
        .lock()
        .map_err(|_| "Gateway 生命周期锁不可用".to_string())?;
    if *phase == LifecyclePhase::Stopped {
        Ok(())
    } else {
        Err("请先停止运行时，再修改配置".into())
    }
}

fn spawn_mitmproxy(
    app: &AppHandle,
    plan_path: &Path,
    settings: &RuntimeSettings,
    port: u16,
) -> Result<Child, String> {
    let addon = resolve_mitmproxy_addon(app)?;
    let confdir = mitmproxy_confdir(app, settings)?;
    let binary = resolve_mitmproxy_binary(app);
    let host = module_proxy_host(settings);
    let mut command = Command::new(&binary);
    command
        .arg("--listen-host")
        .arg(&host)
        .arg("--listen-port")
        .arg(port.to_string())
        .arg("--set")
        .arg(format!("confdir={}", confdir.display()))
        .arg("-s")
        .arg(&addon)
        .env("SONGSTERX_MODULE_PLAN", plan_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.spawn().map_err(|error| {
        format!(
            "无法启动 mitmdump（{}）：{}；请重新打包应用内 mitmdump，或设置 SONGSTERX_MITMDUMP_BIN",
            binary.display(),
            error
        )
    })
}

fn wait_for_mitmproxy(
    child: &mut Child,
    endpoint: &str,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    let deadline = Instant::now() + MITM_STARTUP_TIMEOUT;
    loop {
        if cancellation() {
            return Err("启动已取消".into());
        }
        if let Some(exit) = child.try_wait().map_err(|error| error.to_string())? {
            let diagnostics = child_process_diagnostics(child);
            let diagnostics = if diagnostics.is_empty() {
                String::new()
            } else {
                format!("；输出：{diagnostics}")
            };
            return Err(format!(
                "mitmdump 在监听 {} 前退出，状态码 {:?}{diagnostics}",
                endpoint,
                exit.code()
            ));
        }
        if TcpStream::connect(endpoint).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("mitmdump 启动超时，未监听 {}", endpoint));
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn child_process_diagnostics(child: &mut Child) -> String {
    let mut output = Vec::new();
    drain_process_pipe(&mut child.stdout, &mut output);
    drain_process_pipe(&mut child.stderr, &mut output);
    let text = String::from_utf8_lossy(&output).trim().to_string();
    const MAX_DIAGNOSTIC_BYTES: usize = 4096;
    if text.len() <= MAX_DIAGNOSTIC_BYTES {
        return text;
    }
    let suffix = text
        .chars()
        .rev()
        .take(MAX_DIAGNOSTIC_BYTES)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("…{suffix}")
}

fn drain_process_pipe<T: Read>(pipe: &mut Option<T>, output: &mut Vec<u8>) {
    if let Some(mut pipe) = pipe.take() {
        let _ = pipe.read_to_end(output);
    }
}

fn sing_box_probe_endpoint(listen: &str, port: u16) -> String {
    let host = listen.trim();
    let probe_host = match host {
        "" | "0.0.0.0" => "127.0.0.1",
        "::" | "[::]" => "::1",
        _ => host,
    };
    if probe_host.contains(':') && !probe_host.starts_with('[') {
        format!("[{probe_host}]:{port}")
    } else {
        format!("{probe_host}:{port}")
    }
}

fn ensure_sing_box_listener_available(listen: &str, port: u16) -> Result<(), String> {
    let endpoint = if listen.trim().contains(':') && !listen.trim().starts_with('[') {
        format!("[{}]:{port}", listen.trim())
    } else {
        format!("{}:{port}", listen.trim())
    };
    TcpListener::bind(&endpoint)
        .map(|listener| drop(listener))
        .map_err(|error| {
            format!(
                "Mixed 监听地址 {} 不可用：{}；请先停止占用该端口的进程",
                endpoint, error
            )
        })
}

fn wait_for_sing_box(
    child: &mut Child,
    endpoint: &str,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    let mut consecutive_ready = 0;
    for _ in 0..30 {
        if cancellation() {
            return Err("启动已取消".into());
        }
        if let Some(exit) = child.try_wait().map_err(|error| error.to_string())? {
            let occupied = TcpStream::connect(endpoint).is_ok();
            return if occupied {
                Err(format!(
                    "sing-box 在监听 {} 前退出，状态码 {:?}；端口已被其他进程占用",
                    endpoint,
                    exit.code()
                ))
            } else {
                Err(format!(
                    "sing-box 在监听 {} 前退出，状态码 {:?}",
                    endpoint,
                    exit.code()
                ))
            };
        }
        if TcpStream::connect(endpoint).is_ok() {
            consecutive_ready += 1;
            if consecutive_ready >= 2 {
                return Ok(());
            }
        } else {
            consecutive_ready = 0;
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "sing-box 启动超时，未监听 {}；请检查端口是否被其他进程占用",
        endpoint
    ))
}

fn spawn_sing_box_process(
    binary: &Path,
    config: &Path,
    endpoint: &str,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<Child, (Option<Child>, String)> {
    let mut command = Command::new(binary);
    command
        .arg("run")
        .arg("-c")
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        (
            None,
            format!("无法启动 sing-box（{}）：{}", binary.display(), error),
        )
    })?;
    if let Err(error) = wait_for_sing_box(&mut child, endpoint, cancellation) {
        return match stop_unowned_child(child) {
            Ok(()) => Err((None, error)),
            Err((child, cleanup)) => Err((
                Some(child),
                format!("{error}；Mixed 启动阶段回收失败：{cleanup}"),
            )),
        };
    }
    Ok(child)
}

fn stop_unowned_child(mut child: Child) -> Result<(), (Child, String)> {
    let kill_error = child.kill().err();
    match child.wait() {
        Ok(_) => Ok(()),
        Err(error) => Err((
            child,
            match kill_error {
                Some(kill_error) => {
                    format!("终止未归属 Mixed 进程失败：{kill_error}；等待退出失败：{error}")
                }
                None => format!("等待未归属 Mixed 进程退出失败：{error}"),
            },
        )),
    }
}

fn adopt_unowned_child(state: &RuntimeState, failure: (Option<Child>, String)) -> String {
    let (child, message) = failure;
    let Some(child) = child else {
        return message;
    };
    match state.child.lock() {
        Ok(mut slot) if slot.is_none() => {
            *slot = Some(child);
            message
        }
        Ok(_) => format!("{message}；Mixed 所有权槽已被占用，无法登记残留进程"),
        Err(_) => format!("{message}；Mixed 所有权锁不可用，无法登记残留进程"),
    }
}

fn update_start_error_status(state: &RuntimeState, message: String) {
    let mut status = current_status(state).unwrap_or_default();
    status.state = "error".into();
    status.healthy = false;
    status.can_stop = runtime_owns_resources(state);
    status.message = message;
    update_status(state, status);
}

fn set_stopped(state: &RuntimeState, message: impl Into<String>) -> RuntimeStatus {
    let next = RuntimeStatus {
        message: message.into(),
        ..RuntimeStatus::default()
    };
    update_status(state, next.clone());
    next
}

fn status_after_stop_failure(
    mut current: RuntimeStatus,
    resources_owned: bool,
    message: impl Into<String>,
) -> RuntimeStatus {
    // A failed teardown that still owns a child, guest runtime, or proxy must
    // remain stoppable. Preserve the last runtime metadata and expose the
    // failure through the message while keeping the lifecycle state running.
    current.state = if resources_owned {
        "running".into()
    } else {
        "error".into()
    };
    current.healthy = false;
    current.can_stop = resources_owned;
    current.message = message.into();
    current
}

fn finalize_start_failure(
    app: &AppHandle,
    state: &RuntimeState,
    generation: u64,
    error: String,
) -> bool {
    let _gateway_transition = lock_gateway_transition(state);
    let mut phase = match state.lifecycle_phase.lock() {
        Ok(phase) => phase,
        Err(_) => return false,
    };
    if *phase != LifecyclePhase::Starting
        || state.lifecycle_generation.load(Ordering::SeqCst) != generation
    {
        return false;
    }
    let resources_owned = runtime_owns_resources(state);
    *phase = if resources_owned {
        LifecyclePhase::Running
    } else {
        LifecyclePhase::Stopped
    };
    if !resources_owned {
        state.metrics_generation.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut session) = state.metrics_session.lock() {
            *session = None;
        }
        if let Ok(mut sample) = state.system_connections.lock() {
            *sample = SystemConnectionSample::default();
        }
    }
    let current = current_status(state).unwrap_or_default();
    update_status(
        state,
        status_after_stop_failure(current, resources_owned, error.clone()),
    );
    let has_metrics_session = state
        .metrics_session
        .lock()
        .map(|session| session.is_some())
        .unwrap_or(false);
    if resources_owned && has_metrics_session {
        restart_runtime_observers(app, state);
    }
    drop(phase);
    emit_log(app, "error", error);
    true
}

fn finalize_unexpected_runtime_exit(
    app: &AppHandle,
    state: &RuntimeState,
    exit_message: String,
    cleanup_result: Result<(), String>,
) -> RuntimeStatus {
    state.metrics_generation.fetch_add(1, Ordering::SeqCst);
    match cleanup_result {
        Ok(()) => {
            if let Ok(mut session) = state.metrics_session.lock() {
                *session = None;
            }
            mark_lifecycle_phase(state, LifecyclePhase::Stopped);
            set_stopped(state, exit_message)
        }
        Err(cleanup_error) => {
            let resources_owned = runtime_owns_resources(state);
            let message = format!("{exit_message}；清理失败：{cleanup_error}");
            let phase = if resources_owned {
                LifecyclePhase::Running
            } else {
                LifecyclePhase::Stopped
            };
            mark_lifecycle_phase(state, phase);
            if !resources_owned {
                if let Ok(mut session) = state.metrics_session.lock() {
                    *session = None;
                }
            }
            let current = current_status(state).unwrap_or_default();
            let next = status_after_stop_failure(current, resources_owned, message.clone());
            update_status(state, next.clone());
            if resources_owned {
                restart_runtime_observers(app, state);
            }
            emit_log(app, "error", message);
            next
        }
    }
}

fn resolve_sing_box_binary(app: &AppHandle, settings: &RuntimeSettings) -> PathBuf {
    if let Ok(path) = app.path().resolve("sing-box", BaseDirectory::Resource) {
        if path.is_file() {
            return path;
        }
    }

    if !settings.sing_box_path.trim().is_empty() {
        return settings.sing_box_path.trim().into();
    }

    env::var("SONGSTERX_SING_BOX_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("sing-box"))
}

fn resolve_vmnet_helper_binary(
    app: &AppHandle,
    settings: &RuntimeSettings,
) -> Result<(PathBuf, bool), String> {
    let configured = settings.vmnet_helper_path.trim();
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        if !path.is_file() {
            return Err(format!("vmnet-helper 不存在或不是文件：{}", path.display()));
        }
        return Ok((path, false));
    }
    if let Ok(candidate) = env::var("SONGSTERX_VMNET_HELPER_BIN") {
        if !candidate.trim().is_empty() {
            let path = PathBuf::from(candidate.trim());
            if !path.is_file() {
                return Err(format!("vmnet-helper 不存在或不是文件：{}", path.display()));
            }
            return Ok((path, false));
        }
    }
    let bundled = app
        .path()
        .resolve("vmnet-helper", BaseDirectory::Resource)
        .map_err(|error| format!("无法定位应用内 vmnet-helper：{error}"))?;
    if bundled.is_file() {
        return Ok((bundled, true));
    }
    Ok((PathBuf::from("vmnet-helper"), false))
}

fn resolve_vfkit_binary(app: &AppHandle, settings: &RuntimeSettings) -> Result<PathBuf, String> {
    let configured = settings.vfkit_path.trim();
    if !configured.is_empty() {
        return Ok(PathBuf::from(configured));
    }
    if let Ok(candidate) = env::var("SONGSTERX_VFKIT_BIN") {
        if !candidate.trim().is_empty() {
            return Ok(PathBuf::from(candidate.trim()));
        }
    }
    if let Ok(bundled) = app.path().resolve("vfkit", BaseDirectory::Resource) {
        if bundled.is_file() {
            return Ok(bundled);
        }
    }
    Ok(PathBuf::from("vfkit"))
}

fn build_vfkit_gateway_plan(
    app: &AppHandle,
    settings: &RuntimeSettings,
    runtime_dir: &Path,
) -> Result<vfkit::VfkitGatewayPlan, String> {
    let (vmnet_helper, _) = resolve_vmnet_helper_binary(app, settings)?;
    let gateway_ip = parse_ipv4(&settings.gateway_ip, "VM Gateway IP")?;
    let gateway_cidr = settings.gateway_cidr.trim().to_string();
    let upstream_gateway = parse_ipv4(
        &settings.gateway_upstream_gateway,
        "VM Gateway upstream IPv4",
    )?;
    let host_ip = parse_ipv4(&settings.gateway_host_ip, "vfkit host-only host IP")?;
    let guest_host_ip = parse_ipv4(&settings.gateway_guest_host_ip, "vfkit host-only guest IP")?;
    let kernel_path = resolve_gateway_guest_artifact(
        app,
        &settings.gateway_guest_kernel_path,
        "kernel",
        "Linux kernel",
    )?;
    let initrd_path = resolve_gateway_guest_artifact(
        app,
        &settings.gateway_guest_initrd_path,
        "initrd",
        "Linux initrd",
    )?;
    let config = vfkit::VfkitGatewayConfig {
        vfkit_path: resolve_vfkit_binary(app, settings)?,
        vmnet_helper_path: vmnet_helper,
        kernel_path,
        initrd_path,
        guest_cmdline: settings.gateway_guest_cmdline.trim().to_string(),
        cpus: settings.gateway_guest_cpus,
        memory_mib: settings.gateway_guest_memory_mib,
        bridge_interface: settings.gateway_lan_interface.trim().to_string(),
        gateway_ip,
        gateway_cidr,
        upstream_gateway,
        dns_server: settings.dns_server.trim().to_string(),
        guest_lan_selector: settings.gateway_guest_lan_selector.trim().to_string(),
        guest_host_selector: settings.gateway_guest_host_selector.trim().to_string(),
        host_ip,
        guest_host_ip,
        host_network_cidr: settings.gateway_host_cidr.trim().to_string(),
        guest_agent_port: settings.gateway_guest_agent_port,
        lan_socket_path: runtime_dir.join("vfkit-lan.sock"),
        host_socket_path: runtime_dir.join("vfkit-host.sock"),
    };
    vfkit::build_plan(&config)
}

/// Start the Linux guest runtime. Entity LAN packet-path acceptance remains a
/// separate fail-closed forwarding gate until a real client is verified.
///
/// The caller holds `gateway_transition` for the whole runtime start. Keeping
/// the slot assignment under that lock prevents stop/start races from leaving
/// a live vfkit process without an owner in `RuntimeState`.
fn start_gateway_runtime_supervisor(
    app: &AppHandle,
    state: &RuntimeState,
    settings: &RuntimeSettings,
    config_path: &Path,
    module_plan_path: &Path,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    let startup_started_at = Instant::now();
    if !GATEWAY_GUEST_PACKET_PATH_RELEASE_GATE {
        return Err(GATEWAY_PACKET_PATH_UNAVAILABLE.into());
    }
    ensure_vmnet_launch_supported()?;
    ensure_gateway_ip_is_not_in_use(settings)?;

    if state
        .gateway_runtime
        .lock()
        .map_err(|_| "Gateway runtime 锁不可用".to_string())?
        .is_some()
    {
        return Err("Gateway supervisor 已经在运行".into());
    }

    if let Ok(mut readiness) = state.gateway_readiness.lock() {
        readiness.mark_starting();
    }

    let runtime_dir =
        process_group::unique_runtime_dir(process_group::runtime_parent_dir(env::temp_dir()));
    let vfkit_plan = match build_vfkit_gateway_plan(app, settings, &runtime_dir) {
        Ok(plan) => plan,
        Err(error) => {
            if let Ok(mut readiness) = state.gateway_readiness.lock() {
                readiness.mark_failed(error.clone());
            }
            return Err(format!("构造 vfkit Gateway 启动计划失败：{error}"));
        }
    };
    let endpoint = match gateway_guest_agent_endpoint(app, settings) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            if let Ok(mut readiness) = state.gateway_readiness.lock() {
                readiness.mark_failed(error.clone());
            }
            return Err(format!("guest-agent 配置无效：{error}"));
        }
    };
    let bridged_socket = runtime_dir.join("vfkit-lan.sock");
    let host_only_socket = runtime_dir.join("vfkit-host.sock");
    let guest_probe_endpoint = endpoint.clone();
    let guest_probe = gateway_runtime::FnProbe::new(move || {
        // The guest-agent intentionally reports unhealthy until the host
        // uploads this session's config. Bootstrap only requires an
        // authenticated status response and networkReady; the full
        // healthy/ready check runs after config activation below.
        guest_agent::query_status(&guest_probe_endpoint, GATEWAY_AGENT_PROBE_TIMEOUT)
            .and_then(|status| {
                if guest_agent::status_is_bootstrap_ready(&status) {
                    Ok(true)
                } else {
                    Err(guest_agent_status_diagnostic(&status))
                }
            })
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))
    });
    let runtime_plan = match vfkit::build_runtime_plan(
        vfkit_plan,
        runtime_dir,
        bridged_socket.clone(),
        host_only_socket.clone(),
        Box::new(gateway_runtime::UnixSocketPathProbe::new(bridged_socket)),
        Box::new(gateway_runtime::UnixSocketPathProbe::new(host_only_socket)),
        Box::new(guest_probe),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            if let Ok(mut readiness) = state.gateway_readiness.lock() {
                readiness.mark_failed(error.clone());
            }
            return Err(format!("准备 vfkit Gateway runtime 失败：{error}"));
        }
    };

    let runtime = match gateway_runtime::GatewayRuntime::start_with_cancellation(
        runtime_plan,
        cancellation,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            let message = adopt_gateway_start_failure(state, error);
            if let Ok(mut readiness) = state.gateway_readiness.lock() {
                readiness.mark_failed(message.clone());
            }
            return Err(format!("启动 vfkit Gateway supervisor 失败：{message}"));
        }
    };
    emit_log(
        app,
        "info",
        format!(
            "VM 基础运行时已就绪，耗时 {} ms；正在同步 guest 配置",
            startup_started_at.elapsed().as_millis()
        ),
    );

    let session_result = match guest_agent::sync_session_with_cancellation(
        &endpoint,
        config_path,
        module_plan_path,
        GATEWAY_CONFIG_SYNC_TIMEOUT,
        cancellation,
    ) {
        Ok(result) => result,
        Err(error) => {
            if let Ok(mut readiness) = state.gateway_readiness.lock() {
                readiness.mark_failed(error.clone());
            }
            return Err(runtime_failure_with_cleanup(
                format!("guest Gateway session 激活失败：{error}"),
                runtime,
                state,
            ));
        }
    };
    if let Some(certificate_pem) = session_result.certificate_pem.as_deref() {
        if let Err(error) = persist_guest_mitm_certificate(app, certificate_pem) {
            emit_log(
                app,
                "warn",
                format!("guest Module Engine 已启动，但保存 MITM 根证书失败：{error}"),
            );
        }
    }
    emit_log(
        app,
        "info",
        format!(
            "guest Gateway session 已原子激活（配置 + Module Engine 计划），耗时 {} ms",
            startup_started_at.elapsed().as_millis()
        ),
    );
    if let Err(error) = commit_gateway_runtime(&state, runtime) {
        if let Ok(mut readiness) = state.gateway_readiness.lock() {
            readiness.mark_failed(error.clone());
        }
        return Err(error);
    }
    if let Ok(mut baseline) = state.gateway_packet_baseline.lock() {
        *baseline = session_result.packet_stats.clone();
    }
    if let Ok(mut readiness) = state.gateway_readiness.lock() {
        readiness.mark_runtime_started();
        readiness.mark_guest_packet_path_not_ready(GATEWAY_PACKET_PATH_UNAVAILABLE);
    }
    emit_log(
        app,
        "info",
        format!(
            "vfkit Gateway supervisor 已启动：bridged LAN、host-only、vfkit 和 guest-agent 均就绪（配置已激活；实体 LAN packet path 尚未现场验收；总耗时 {} ms）",
            startup_started_at.elapsed().as_millis()
        ),
    );
    Ok(())
}

fn guest_agent_status_diagnostic(status: &guest_agent::GuestAgentStatus) -> String {
    format!(
        "healthy={} ready={} networkReady={} lastError={}",
        status.healthy,
        status.ready,
        status.network_ready,
        status.last_error.as_deref().unwrap_or("<none>")
    )
}

/// Commit a fully bootstrapped Gateway only after every startup phase has
/// succeeded. Until this function returns, the caller owns the runtime; if
/// the state lock is poisoned or already occupied, explicitly stop the
/// uncommitted runtime before returning the error instead of relying on Drop.
fn commit_gateway_runtime(
    state: &RuntimeState,
    runtime: gateway_runtime::GatewayRuntime,
) -> Result<(), String> {
    let mut slot = match state.gateway_runtime.lock() {
        Ok(slot) => slot,
        Err(_) => {
            return Err(runtime_failure_with_cleanup(
                "Gateway runtime 锁不可用".into(),
                runtime,
                state,
            ));
        }
    };
    if slot.is_some() {
        drop(slot);
        return Err(runtime_failure_with_cleanup(
            "Gateway supervisor 已经在运行".into(),
            runtime,
            state,
        ));
    }
    *slot = Some(runtime);
    Ok(())
}

fn interface_packet_progressed(
    before: &guest_agent::GuestInterfaceStats,
    after: &guest_agent::GuestInterfaceStats,
) -> bool {
    after.rx_packets > before.rx_packets
        || after.tx_packets > before.tx_packets
        || after.rx_bytes > before.rx_bytes
        || after.tx_bytes > before.tx_bytes
}

fn guest_packet_path_progressed(
    before: &guest_agent::GuestPacketStats,
    after: &guest_agent::GuestPacketStats,
) -> bool {
    let Some(before_lan) = before.lan.as_ref() else {
        return false;
    };
    let Some(after_lan) = after.lan.as_ref() else {
        return false;
    };
    let Some(before_tun) = before.tun.as_ref() else {
        return false;
    };
    let Some(after_tun) = after.tun.as_ref() else {
        return false;
    };
    interface_packet_progressed(before_lan, after_lan)
        && interface_packet_progressed(before_tun, after_tun)
}

fn observe_gateway_packet_path(
    app: &AppHandle,
    session: &MetricsSession,
    generation: &AtomicU64,
    expected: u64,
) {
    if generation.load(Ordering::SeqCst) != expected {
        return;
    }
    let state = app.state::<RuntimeState>();
    let baseline = match state.gateway_packet_baseline.lock() {
        Ok(baseline) => baseline.clone(),
        Err(_) => return,
    };
    let Some(baseline) = baseline else {
        return;
    };
    let Some(endpoint) = session.guest_endpoint.clone() else {
        return;
    };
    let current = match guest_agent::query_status(&endpoint, Duration::from_secs(1)) {
        Ok(status) => status.packet_stats,
        Err(_) => return,
    };
    if generation.load(Ordering::SeqCst) != expected {
        return;
    }
    let Some(current) = current else {
        return;
    };
    if !guest_packet_path_progressed(&baseline, &current) {
        return;
    }

    let _transition = lock_gateway_transition(&state);
    if generation.load(Ordering::SeqCst) != expected {
        return;
    }
    let was_ready = state
        .gateway_readiness
        .lock()
        .map(|mut readiness| {
            if generation.load(Ordering::SeqCst) != expected {
                return true;
            }
            if readiness.guest_packet_path.is_ready() {
                true
            } else {
                readiness.mark_guest_packet_path_ready();
                false
            }
        })
        .unwrap_or(true);
    if was_ready {
        return;
    }

    if let Ok(mut status) = state.status.lock() {
        if generation.load(Ordering::SeqCst) != expected {
            return;
        }
        if status.mode.contains("gateway") {
            status.state = "running".into();
            status.healthy = true;
            status.can_stop = true;
            status.gateway_packet_path_ready = true;
            status.message = if status.module_proxy.is_some() {
                "Mixed 入口与 Linux guest 局域网网关已启动；实体 LAN packet path 已验收；模块 MITM 已挂接".into()
            } else {
                "Mixed 入口与 Linux guest 局域网网关已启动；实体 LAN packet path 已验收".into()
            };
        }
    }
    emit_log(
        app,
        "info",
        "Guest packet path 已验收：LAN 与 tun0 均观察到启动后的新增流量",
    );
}

fn runtime_failure_with_cleanup(
    primary: String,
    mut runtime: gateway_runtime::GatewayRuntime,
    state: &RuntimeState,
) -> String {
    match runtime.stop() {
        Ok(()) => primary,
        Err(cleanup) => {
            if let Ok(mut slot) = state.gateway_runtime.lock() {
                if slot.is_none() {
                    *slot = Some(runtime);
                    return format!(
                        "{primary}；回收失败：{cleanup}；残留 Gateway 已登记，可再次停止"
                    );
                }
            }
            format!("{primary}；回收失败：{cleanup}；残留 Gateway 无法登记")
        }
    }
}

fn adopt_gateway_start_failure(
    state: &RuntimeState,
    failure: gateway_runtime::GatewayStartupFailure,
) -> String {
    let message = failure.message;
    let Some(runtime) = failure.residual else {
        return message;
    };
    match state.gateway_runtime.lock() {
        Ok(mut slot) if slot.is_none() => {
            *slot = Some(runtime);
            format!("{message}；残留 Gateway 已登记，可再次停止")
        }
        Ok(_) => format!("{message}；Gateway 所有权槽已被占用，无法登记残留 runtime"),
        Err(_) => format!("{message}；Gateway 所有权锁不可用，无法登记残留 runtime"),
    }
}

#[cfg(target_os = "macos")]
fn ensure_vmnet_launch_supported() -> Result<(), String> {
    let output = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .map_err(|error| format!("无法读取 macOS 版本：{error}"))?;
    if !output.status.success() {
        return Err("sw_vers -productVersion 执行失败".into());
    }
    let version = String::from_utf8_lossy(&output.stdout);
    let major = version
        .trim()
        .split('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| format!("无法解析 macOS 版本：{}", version.trim()))?;
    if major < 26 {
        return Err(format!(
            "当前 macOS {} 不支持 SongsterX 的无特权 vmnet-helper 启动路径；macOS 15 及更早需要受信任的 root helper。当前版本拒绝以普通 LaunchAgent 启动，以避免误报 VMNET_FAILURE",
            version.trim()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn ensure_vmnet_launch_supported() -> Result<(), String> {
    Ok(())
}

fn vfkit_gateway_preflight_message(app: &AppHandle, settings: &RuntimeSettings) -> String {
    let runtime_dir =
        process_group::unique_runtime_dir(process_group::runtime_parent_dir(env::temp_dir()));
    match build_vfkit_gateway_plan(app, settings, &runtime_dir) {
        Ok(_) => "vfkit Gateway 启动计划有效；vmnet、vfkit 和 guest-agent readiness 将由 supervisor 在运行时检查；实体 LAN packet path 仍需手机/电脑现场验收".into(),
        Err(error) => format!("vfkit Gateway 配置未就绪：{error}"),
    }
}

#[tauri::command]
fn get_runtime_settings(app: AppHandle) -> Result<RuntimeSettings, String> {
    load_settings(&app)
}

#[tauri::command]
fn save_runtime_settings(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    settings: RuntimeSettings,
) -> Result<RuntimeSettings, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再保存设置".into());
    }
    persist_settings(&app, &settings)
}

#[tauri::command]
fn reset_runtime_settings(
    app: AppHandle,
    state: State<'_, RuntimeState>,
) -> Result<RuntimeSettings, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再恢复默认设置".into());
    }
    persist_settings(&app, &RuntimeSettings::default())
}

fn resolve_gateway_guest_artifact(
    app: &AppHandle,
    configured: &str,
    artifact_name: &str,
    label: &str,
) -> Result<PathBuf, String> {
    if !configured.trim().is_empty() {
        let path = PathBuf::from(configured.trim());
        if !path.is_file() {
            return Err(format!("{label} 不存在或不是文件：{}", path.display()));
        }
        return Ok(path);
    }

    let bundled = app
        .path()
        .resolve(
            format!("gateway-guest/{artifact_name}"),
            BaseDirectory::Resource,
        )
        .map_err(|error| format!("无法定位应用内 Gateway {label}：{error}"))?;
    if bundled.is_file() {
        return Ok(bundled);
    }

    Err(format!(
        "{label} 未配置，且应用内缺少 gateway-guest/{artifact_name}；请填写路径或重新打包应用"
    ))
}

fn gateway_guest_agent_token(
    app: &AppHandle,
    settings: &RuntimeSettings,
) -> Result<String, String> {
    if let Ok(token) = env::var("SONGSTERX_GATEWAY_AGENT_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(token.trim().to_string());
        }
    }
    if let Ok(path) = env::var("SONGSTERX_GATEWAY_AGENT_TOKEN_FILE") {
        if !path.trim().is_empty() {
            let token = fs::read_to_string(path.trim())
                .map_err(|error| format!("无法读取 SONGSTERX_GATEWAY_AGENT_TOKEN_FILE：{error}"))?;
            if !token.trim().is_empty() {
                return Ok(token.trim().to_string());
            }
        }
    }

    if !settings.gateway_guest_initrd_path.trim().is_empty() {
        let initrd = PathBuf::from(settings.gateway_guest_initrd_path.trim());
        let token_path = initrd
            .parent()
            .map(|parent| parent.join("agent.token"))
            .ok_or_else(|| {
                format!(
                    "自定义 Linux initrd 无法确定 agent.token 目录：{}",
                    initrd.display()
                )
            })?;
        let token = fs::read_to_string(&token_path).map_err(|error| {
            format!(
                "自定义 Linux initrd 缺少同目录 agent.token：{} ({error})",
                token_path.display()
            )
        })?;
        if token.trim().is_empty() {
            return Err(format!(
                "自定义 Linux initrd 的 agent.token 为空：{}",
                token_path.display()
            ));
        }
        return Ok(token.trim().to_string());
    }

    let bundled = app
        .path()
        .resolve("gateway-guest/agent.token", BaseDirectory::Resource)
        .map_err(|error| format!("无法定位应用内 Gateway agent token：{error}"))?;
    if bundled.is_file() {
        let token = fs::read_to_string(&bundled)
            .map_err(|error| format!("无法读取应用内 Gateway agent token：{error}"))?;
        if !token.trim().is_empty() {
            return Ok(token.trim().to_string());
        }
    }

    Err("guest agent 认证未配置；请设置 SONGSTERX_GATEWAY_AGENT_TOKEN、SONGSTERX_GATEWAY_AGENT_TOKEN_FILE，或重新打包包含 gateway-guest 的应用".into())
}

fn gateway_guest_agent_endpoint(
    app: &AppHandle,
    settings: &RuntimeSettings,
) -> Result<guest_agent::GuestAgentEndpoint, String> {
    if settings.mode != "gateway" {
        return Err("只有 Gateway 模式可以访问 guest agent".into());
    }
    validate_vfkit_settings(settings)?;
    Ok(guest_agent::GuestAgentEndpoint {
        host: settings.gateway_guest_host_ip.trim().into(),
        port: settings.gateway_guest_agent_port,
        auth_token: gateway_guest_agent_token(app, settings)?,
    })
}

#[tauri::command]
async fn get_gateway_guest_status(app: AppHandle) -> Result<guest_agent::GuestAgentStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let settings = load_settings(&app)?;
        let endpoint = gateway_guest_agent_endpoint(&app, &settings)?;
        // This command is called by the UI polling loop. Keep an unreachable
        // guest from holding the Tauri main thread for seconds, while the
        // blocking socket work itself runs on the async runtime's blocking
        // pool.
        guest_agent::query_status(&endpoint, Duration::from_millis(500))
    })
    .await
    .map_err(|error| format!("guest agent 状态探测任务失败：{error}"))?
}

#[tauri::command]
fn generate_gateway_guest_config(app: AppHandle) -> Result<String, String> {
    let settings = load_settings(&app)?;
    validate_settings(&settings)?;
    let module_plan = write_module_runtime_plan(&app)?;
    write_gateway_guest_runtime_config(&app, &settings, &module_plan)
        .map(|path| path.display().to_string())
}

#[tauri::command]
fn upgrade_gateway_sing_box(
    app: AppHandle,
    artifact_path: String,
    version: String,
    architecture: String,
) -> Result<guest_agent::GuestUpgradeResult, String> {
    let settings = load_settings(&app)?;
    let endpoint = gateway_guest_agent_endpoint(&app, &settings)?;
    guest_agent::upgrade_sing_box(
        &endpoint,
        Path::new(artifact_path.trim()),
        &version,
        &architecture,
        Duration::from_secs(30),
    )
}

#[tauri::command]
fn get_runtime_status(
    app: AppHandle,
    state: State<'_, RuntimeState>,
) -> Result<RuntimeStatus, String> {
    let phase = state
        .lifecycle_phase
        .lock()
        .map_err(|_| "Gateway 生命周期锁不可用".to_string())?;
    if matches!(*phase, LifecyclePhase::Starting | LifecyclePhase::Stopping) {
        drop(phase);
        return current_status(&state);
    }
    drop(phase);
    let _gateway_transition = lock_gateway_transition(&state);

    let sing_box_exit = {
        let mut child_guard = state
            .child
            .lock()
            .map_err(|_| "运行时锁不可用".to_string())?;
        match child_guard.as_mut() {
            Some(child) => child
                .try_wait()
                .map_err(|error| error.to_string())?
                .map(|exit| {
                    *child_guard = None;
                    format!("sing-box 已退出，状态码 {:?}", exit.code())
                }),
            None => None,
        }
    };
    if let Some(message) = sing_box_exit {
        state.metrics_generation.fetch_add(1, Ordering::SeqCst);
        let cleanup = stop_runtime_processes_locked(&app, &state);
        return Ok(finalize_unexpected_runtime_exit(
            &app, &state, message, cleanup,
        ));
    }

    let mitm_exit = {
        let mut mitm_guard = state
            .mitm_child
            .lock()
            .map_err(|_| "运行时锁不可用".to_string())?;
        match mitm_guard.as_mut() {
            Some(child) => child
                .try_wait()
                .map_err(|error| error.to_string())?
                .map(|exit| {
                    *mitm_guard = None;
                    format!("mitmdump 已退出，状态码 {:?}", exit.code())
                }),
            None => None,
        }
    };
    if let Some(message) = mitm_exit {
        state.metrics_generation.fetch_add(1, Ordering::SeqCst);
        let cleanup = stop_runtime_processes_locked(&app, &state);
        return Ok(finalize_unexpected_runtime_exit(
            &app, &state, message, cleanup,
        ));
    }

    let gateway_supervisor_exit = {
        let mut gateway_runtime = state
            .gateway_runtime
            .lock()
            .map_err(|_| "Gateway runtime 锁不可用".to_string())?;
        let exited = match gateway_runtime.as_mut() {
            Some(runtime) => !runtime
                .leaders_running()
                .map_err(|error| format!("检查 Gateway supervisor 失败：{error}"))?,
            None => false,
        };
        exited
    };
    if gateway_supervisor_exit {
        state.metrics_generation.fetch_add(1, Ordering::SeqCst);
        let cleanup = stop_runtime_processes_locked(&app, &state);
        return Ok(finalize_unexpected_runtime_exit(
            &app,
            &state,
            "vfkit Gateway supervisor 已退出".into(),
            cleanup,
        ));
    }

    state
        .status
        .lock()
        .map(|status| status.clone())
        .map_err(|_| "状态锁不可用".to_string())
}

#[tauri::command]
fn start_mix_direct(
    app: AppHandle,
    state: State<'_, RuntimeState>,
) -> Result<RuntimeStatus, String> {
    let settings = load_settings(&app)?;
    if runtime_phase_is_active(&state)? {
        return current_status(&state);
    }
    let Some(lifecycle_generation) = begin_lifecycle_start(&state)? else {
        return current_status(&state);
    };
    let starting = lifecycle_starting_status(&settings);
    update_status(&state, starting.clone());
    let worker_app = app.clone();
    thread::spawn(move || {
        let worker_state = worker_app.state::<RuntimeState>();
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            start_mix_direct_blocking(
                worker_app.clone(),
                &worker_state,
                settings,
                lifecycle_generation,
            )
        })) {
            Ok(result) => result,
            Err(_) => {
                let cleanup = stop_runtime_processes(&worker_app, &worker_state);
                Err(match cleanup {
                    Ok(()) => "启动 worker 异常退出，已完成回收".into(),
                    Err(error) => format!("启动 worker 异常退出；回收失败：{error}"),
                })
            }
        };
        let cancelled =
            worker_state.lifecycle_generation.load(Ordering::SeqCst) != lifecycle_generation;
        if cancelled {
            finish_cancelled_start(&worker_state);
            return;
        }
        match result {
            Ok(next) => {
                let _ = complete_start_success(&worker_state, lifecycle_generation, next);
            }
            Err(error) => {
                let _ =
                    finalize_start_failure(&worker_app, &worker_state, lifecycle_generation, error);
            }
        }
    });
    Ok(starting)
}

fn start_mix_direct_blocking(
    app: AppHandle,
    state: &RuntimeState,
    settings: RuntimeSettings,
    lifecycle_generation: u64,
) -> Result<RuntimeStatus, String> {
    let cleanup_app = app.clone();
    let transaction_result = {
        let _gateway_transition = lock_gateway_transition(state);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            start_mix_direct_transaction(app, state, settings, lifecycle_generation)
        }))
    };
    match transaction_result {
        Ok(result) => result,
        Err(_) => {
            let cleanup = stop_runtime_processes(&cleanup_app, state);
            Err(match cleanup {
                Ok(()) => "启动事务异常退出，已完成回收".into(),
                Err(error) => format!("启动事务异常退出；回收失败：{error}"),
            })
        }
    }
}

fn start_mix_direct_transaction(
    app: AppHandle,
    state: &RuntimeState,
    settings: RuntimeSettings,
    lifecycle_generation: u64,
) -> Result<RuntimeStatus, String> {
    if lifecycle_cancelled(state, lifecycle_generation) {
        return Err("启动已取消".into());
    }
    let metrics_generation = Arc::clone(&state.metrics_generation);
    let metrics_generation_id = metrics_generation.fetch_add(1, Ordering::SeqCst) + 1;

    let gateway_mode = settings.mode == "gateway";
    if gateway_mode {
        validate_settings(&settings)?;
        emit_log(
            &app,
            "info",
            vfkit_gateway_preflight_message(&app, &settings),
        );
    }
    let mut module_plan = write_module_runtime_plan(&app)?;
    if module_plan_requires_mitm(&module_plan) {
        let port = if gateway_mode {
            // Gateway Module Engine is inside the Linux guest and is reached by
            // guest sing-box over loopback. Do not probe/bind a host-only port.
            DEFAULT_MODULE_PROXY_PORT
        } else {
            select_module_proxy_port(&settings)?
        };
        module_plan.proxy_port = Some(port);
    }
    persist_module_runtime_plan(&app, &module_plan)?;
    let config = write_runtime_config(&app, &settings, &module_plan)?;
    let gateway_config = if gateway_mode {
        Some(write_gateway_guest_runtime_config(
            &app,
            &settings,
            &module_plan,
        )?)
    } else {
        None
    };
    let plan_path = module_runtime_plan_path(&app)?;
    let binary = resolve_sing_box_binary(&app, &settings);
    if lifecycle_cancelled(state, lifecycle_generation) {
        return Err("启动已取消".into());
    }
    update_status(
        &state,
        RuntimeStatus {
            state: "starting".into(),
            healthy: false,
            can_stop: false,
            mode: if gateway_mode {
                "lan-gateway no-dhcp"
            } else {
                "mixed direct"
            }
            .into(),
            listen: format!("{}:{}", settings.listen.trim(), settings.port),
            dns: dns_status(&settings),
            gateway_ip: gateway_mode.then(|| settings.gateway_ip.trim().to_string()),
            gateway_dns_ip: gateway_mode.then(|| {
                if settings.gateway_dns_ip.trim().is_empty() {
                    if settings.dns_mode == "fakeip" {
                        "198.18.0.2".into()
                    } else {
                        settings.gateway_ip.trim().into()
                    }
                } else {
                    settings.gateway_dns_ip.trim().into()
                }
            }),
            gateway_packet_path_ready: false,
            pid: None,
            module_proxy: None,
            message: if gateway_mode {
                format!(
                    "正在启动 Mixed + 局域网网关（无 DHCP）：{}",
                    config.display()
                )
            } else {
                format!("正在启动 {}", config.display())
            },
        },
    );
    emit_log(
        &app,
        "info",
        if gateway_mode {
            format!("启动 Mixed + 局域网网关（无 DHCP）：{}", config.display())
        } else {
            format!("启动 mixed 直连：{}", config.display())
        },
    );

    let metrics_session = metrics_session_for_runtime(&app, &settings);
    if let Ok(mut current) = state.metrics_session.lock() {
        *current = Some(metrics_session.clone());
    }
    spawn_runtime_observers(
        app.clone(),
        metrics_generation.clone(),
        metrics_generation_id,
        metrics_session,
    );

    if !gateway_mode {
        if let Err(error) = ensure_sing_box_listener_available(&settings.listen, settings.port) {
            let message = format!("Mixed 入口启动失败：{error}");
            update_start_error_status(&state, message.clone());
            emit_log(&app, "error", message.clone());
            return Err(message);
        }
    }

    // Gateway is a single guest data plane. The host intentionally does not
    // start either a second sing-box or a host mitmdump process.
    if gateway_mode {
        let startup_cancelled = || lifecycle_cancelled(state, lifecycle_generation);
        if let Err(error) = start_gateway_runtime_supervisor(
            &app,
            &state,
            &settings,
            gateway_config
                .as_deref()
                .expect("gateway config is prepared for gateway mode"),
            &plan_path,
            &startup_cancelled,
        ) {
            update_start_error_status(&state, error.clone());
            emit_log(&app, "error", error.clone());
            return Err(error);
        }
        if lifecycle_cancelled(state, lifecycle_generation) {
            let _ = stop_runtime_processes_locked(&app, state);
            return Err("启动已取消".into());
        }
        let guest_status =
            gateway_guest_agent_endpoint(&app, &settings)
                .ok()
                .and_then(|endpoint| {
                    guest_agent::query_status(&endpoint, GATEWAY_AGENT_PROBE_TIMEOUT).ok()
                });
        let module_proxy = module_plan_requires_mitm(&module_plan)
            .then(|| format!("VM 内 127.0.0.1:{}", module_proxy_port(&module_plan)));
        let next = RuntimeStatus {
            state: "starting".into(),
            healthy: false,
            can_stop: true,
            mode: "lan-gateway no-dhcp".into(),
            listen: format!("VM tun0 + {}:{}", settings.gateway_ip.trim(), settings.port),
            dns: dns_status(&settings),
            gateway_ip: Some(settings.gateway_ip.trim().to_string()),
            gateway_dns_ip: Some(if settings.gateway_dns_ip.trim().is_empty() {
                if settings.dns_mode == "fakeip" {
                    "198.18.0.2".into()
                } else {
                    settings.gateway_ip.trim().into()
                }
            } else {
                settings.gateway_dns_ip.trim().into()
            }),
            gateway_packet_path_ready: false,
            pid: guest_status.as_ref().and_then(|status| status.pid),
            module_proxy,
            message: if module_plan_requires_mitm(&module_plan) {
                "Linux VM 单数据面已启动：guest sing-box + guest mitmdump；等待 LAN packet path 验收".into()
            } else {
                "Linux VM 单 sing-box 数据面已启动；等待 LAN packet path 验收".into()
            },
        };
        update_status(&state, next.clone());
        emit_log(
            &app,
            "info",
            format!(
                "Linux VM 单数据面已启动：guest sing-box PID {}{}；主机不再启动第二个 sing-box/mitmdump",
                next.pid.map(|pid| pid.to_string()).unwrap_or_else(|| "未知".into()),
                if module_plan_requires_mitm(&module_plan) {
                    "，guest mitmdump 已挂接 127.0.0.1:8080"
                } else {
                    ""
                }
            ),
        );
        return Ok(next);
    }

    let sing_box_endpoint = sing_box_probe_endpoint(&settings.listen, settings.port);

    // Mixed and Gateway own different processes and sockets. Start their
    // independent bootstrap phases in parallel, then publish both only after
    // each side has passed its readiness probe. GatewayRuntime itself still
    // starts its vfkit guest only after both vmnet helper sockets are ready.
    let startup_cancelled = || lifecycle_cancelled(state, lifecycle_generation);
    let (gateway_result, local_result) = thread::scope(|scope| {
        let gateway_task = gateway_mode.then(|| {
            let gateway_config = gateway_config
                .as_deref()
                .expect("gateway config is prepared for gateway mode");
            scope.spawn(|| {
                start_gateway_runtime_supervisor(
                    &app,
                    &state,
                    &settings,
                    gateway_config,
                    &plan_path,
                    &startup_cancelled,
                )
            })
        });
        let local_task = scope.spawn(|| {
            spawn_sing_box_process(&binary, &config, &sing_box_endpoint, &startup_cancelled)
        });
        let gateway_result = gateway_task.map(|task| match task.join() {
            Ok(result) => result,
            Err(_) => Err("Gateway 启动线程异常退出".into()),
        });
        let local_result = match local_task.join() {
            Ok(result) => result,
            Err(_) => Err((None, "Mixed 启动线程异常退出".into())),
        };
        (gateway_result, local_result)
    });

    if lifecycle_cancelled(state, lifecycle_generation) {
        let local_message = match local_result {
            Ok(child) => match stop_unowned_child(child) {
                Ok(()) => None,
                Err((child, error)) => {
                    if let Ok(mut slot) = state.child.lock() {
                        *slot = Some(child);
                    }
                    Some(error)
                }
            },
            Err(failure) => Some(adopt_unowned_child(state, failure)),
        };
        let _ = stop_runtime_processes_locked(&app, state);
        return Err(match local_message {
            Some(error) => format!("启动已取消；{error}"),
            None => "启动已取消".into(),
        });
    }

    let mut child = match (gateway_result, local_result) {
        (Some(Err(error)), Ok(child)) => {
            let unowned_cleanup = match stop_unowned_child(child) {
                Ok(()) => None,
                Err((child, error)) => {
                    if let Ok(mut slot) = state.child.lock() {
                        *slot = Some(child);
                    }
                    Some(error)
                }
            };
            let cleanup = stop_runtime_processes_locked(&app, &state).err();
            let message = match cleanup {
                Some(cleanup) => match unowned_cleanup {
                    Some(unowned_cleanup) => {
                        format!("{error}；Mixed 回收失败：{unowned_cleanup}；回收失败：{cleanup}")
                    }
                    None => format!("{error}；回收失败：{cleanup}"),
                },
                None => match unowned_cleanup {
                    Some(unowned_cleanup) => format!("{error}；Mixed 回收失败：{unowned_cleanup}"),
                    None => error,
                },
            };
            update_start_error_status(&state, message.clone());
            emit_log(&app, "error", message.clone());
            return Err(message);
        }
        (Some(Err(error)), Err(local_error)) => {
            let local_error = adopt_unowned_child(&state, local_error);
            let cleanup = stop_runtime_processes_locked(&app, &state).err();
            let message = match cleanup {
                Some(cleanup) => {
                    format!("{error}；Mixed 启动失败：{local_error}；回收失败：{cleanup}")
                }
                None => format!("{error}；Mixed 启动失败：{local_error}"),
            };
            update_start_error_status(&state, message.clone());
            emit_log(&app, "error", message.clone());
            return Err(message);
        }
        (Some(Ok(())), Err(error)) => {
            let error = adopt_unowned_child(&state, error);
            let cleanup = stop_runtime_processes_locked(&app, &state).err();
            let message = match cleanup {
                Some(cleanup) => format!("Mixed 入口启动失败：{error}；回收失败：{cleanup}"),
                None => format!("Mixed 入口启动失败：{error}"),
            };
            update_start_error_status(&state, message.clone());
            emit_log(&app, "error", message.clone());
            return Err(message);
        }
        (Some(Ok(())), Ok(child)) => child,
        (None, Ok(child)) => child,
        (None, Err(error)) => {
            let error = adopt_unowned_child(&state, error);
            let message = format!("Mixed 入口启动失败：{error}");
            update_start_error_status(&state, message.clone());
            emit_log(&app, "error", message.clone());
            return Err(message);
        }
    };
    let pid = child.id();

    if let Some(stdout) = child.stdout.take() {
        let app_handle = app.clone();
        thread::spawn(move || forward_output(app_handle, stdout, "info"));
    }
    if let Some(stderr) = child.stderr.take() {
        let app_handle = app.clone();
        thread::spawn(move || forward_output(app_handle, stderr, "error"));
    }

    if lifecycle_cancelled(state, lifecycle_generation) {
        let unowned_cleanup = match stop_unowned_child(child) {
            Ok(()) => None,
            Err((child, error)) => {
                if let Ok(mut slot) = state.child.lock() {
                    *slot = Some(child);
                }
                Some(error)
            }
        };
        let cleanup = stop_runtime_processes_locked(&app, state).err();
        return Err(match (unowned_cleanup, cleanup) {
            (Some(unowned), Some(cleanup)) => format!("启动已取消；{unowned}；回收失败：{cleanup}"),
            (Some(unowned), None) => format!("启动已取消；{unowned}"),
            (None, Some(cleanup)) => format!("启动已取消；回收失败：{cleanup}"),
            (None, None) => "启动已取消".into(),
        });
    }
    *state
        .child
        .lock()
        .map_err(|_| "运行时锁不可用".to_string())? = Some(child);
    let module_proxy = if module_plan_requires_mitm(&module_plan) {
        let port = module_proxy_port(&module_plan);
        let endpoint = module_proxy_endpoint(&settings, port);
        match spawn_mitmproxy(&app, &plan_path, &settings, port) {
            Ok(mut mitm_child) => {
                if let Err(error) =
                    wait_for_mitmproxy(&mut mitm_child, &endpoint, &startup_cancelled)
                {
                    let unowned_cleanup = match stop_unowned_child(mitm_child) {
                        Ok(()) => None,
                        Err((mitm_child, error)) => {
                            if let Ok(mut slot) = state.mitm_child.lock() {
                                *slot = Some(mitm_child);
                            }
                            Some(error)
                        }
                    };
                    let message = format!("模块 MITM 引擎启动失败：{error}");
                    let message = match stop_runtime_processes_locked(&app, &state) {
                        Ok(()) => match unowned_cleanup {
                            Some(cleanup) => format!("{message}；模块引擎回收失败：{cleanup}"),
                            None => message,
                        },
                        Err(cleanup) => {
                            match unowned_cleanup {
                                Some(unowned) => {
                                    format!("{message}；模块引擎回收失败：{unowned}；回收失败：{cleanup}")
                                }
                                None => format!("{message}；回收失败：{cleanup}"),
                            }
                        }
                    };
                    update_start_error_status(&state, message.clone());
                    emit_log(&app, "error", message.clone());
                    return Err(message);
                }
                if lifecycle_cancelled(state, lifecycle_generation) {
                    let unowned_cleanup = match stop_unowned_child(mitm_child) {
                        Ok(()) => None,
                        Err((mitm_child, error)) => {
                            if let Ok(mut slot) = state.mitm_child.lock() {
                                *slot = Some(mitm_child);
                            }
                            Some(error)
                        }
                    };
                    let cleanup = stop_runtime_processes_locked(&app, state).err();
                    return Err(match (unowned_cleanup, cleanup) {
                        (Some(unowned), Some(cleanup)) => {
                            format!("启动已取消；{unowned}；回收失败：{cleanup}")
                        }
                        (Some(unowned), None) => format!("启动已取消；{unowned}"),
                        (None, Some(cleanup)) => format!("启动已取消；回收失败：{cleanup}"),
                        (None, None) => "启动已取消".into(),
                    });
                }
                let mitm_pid = mitm_child.id();
                if let Some(stdout) = mitm_child.stdout.take() {
                    let app_handle = app.clone();
                    thread::spawn(move || forward_output(app_handle, stdout, "info"));
                }
                if let Some(stderr) = mitm_child.stderr.take() {
                    let app_handle = app.clone();
                    thread::spawn(move || forward_output(app_handle, stderr, "error"));
                }
                *state
                    .mitm_child
                    .lock()
                    .map_err(|_| "运行时锁不可用".to_string())? = Some(mitm_child);
                emit_log(
                    &app,
                    "info",
                    format!(
                        "Module Engine 已启动，mitmdump PID {}，监听 {}；HTTPS 客户端需信任 SongsterX MITM 根证书，否则匹配域名会连接失败",
                        mitm_pid, endpoint
                    ),
                );
                Some(endpoint)
            }
            Err(error) => {
                let message = format!("模块 MITM 引擎启动失败：{error}");
                let message = match stop_runtime_processes_locked(&app, &state) {
                    Ok(()) => message,
                    Err(cleanup) => format!("{message}；回收失败：{cleanup}"),
                };
                update_start_error_status(&state, message.clone());
                emit_log(&app, "error", message.clone());
                return Err(message);
            }
        }
    } else {
        None
    };
    if lifecycle_cancelled(state, lifecycle_generation) {
        let _ = stop_runtime_processes_locked(&app, state);
        return Err("启动已取消".into());
    }
    let next = RuntimeStatus {
        state: if gateway_mode { "starting" } else { "running" }.into(),
        healthy: !gateway_mode,
        can_stop: true,
        mode: if gateway_mode {
            "lan-gateway no-dhcp"
        } else {
            "mixed direct"
        }
        .into(),
        listen: format!("{}:{}", settings.listen.trim(), settings.port),
        dns: dns_status(&settings),
        gateway_ip: gateway_mode.then(|| settings.gateway_ip.trim().to_string()),
        gateway_dns_ip: gateway_mode.then(|| {
            if settings.gateway_dns_ip.trim().is_empty() {
                if settings.dns_mode == "fakeip" {
                    "198.18.0.2".into()
                } else {
                    settings.gateway_ip.trim().into()
                }
            } else {
                settings.gateway_dns_ip.trim().into()
            }
        }),
        gateway_packet_path_ready: false,
        pid: Some(pid),
        module_proxy: module_proxy.clone(),
        message: if gateway_mode {
            if module_proxy.is_some() {
                "Mixed 入口已启动，等待真实 LAN packet path 验收；模块 MITM 已挂接".into()
            } else {
                "Mixed 入口已启动，等待真实 LAN packet path 验收".into()
            }
        } else if module_proxy.is_some() {
            "mixed 监听已启动；模块 MITM 已挂接到统一入口；不会自动接管流量".into()
        } else {
            "mixed 监听已启动；不会自动接管流量".into()
        },
    };
    update_status(&state, next.clone());
    emit_log(
        &app,
        "info",
        format!(
            "sing-box 已启动，PID {}，Mixed 监听 {}:{}{}",
            pid,
            settings.listen.trim(),
            settings.port,
            if gateway_mode {
                "；vfkit Gateway supervisor 已就绪".to_string()
            } else {
                String::new()
            }
        ),
    );
    Ok(next)
}

fn strip_ansi_escape_codes(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            output.push(character);
            continue;
        }

        match characters.next() {
            Some('[') => {
                for control in characters.by_ref() {
                    if ('@'..='~').contains(&control) {
                        break;
                    }
                }
            }
            Some(']') => {
                for control in characters.by_ref() {
                    if control == '\u{7}' {
                        break;
                    }
                }
            }
            Some(_) | None => {}
        }
    }
    output
}

fn has_log_level_token(message: &str, token: &str) -> bool {
    message
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|part| part.eq_ignore_ascii_case(token))
}

fn classify_runtime_log(message: &str, fallback: &str) -> (String, String) {
    let clean_message = strip_ansi_escape_codes(message)
        .trim_end_matches('\r')
        .to_string();
    let level = if has_log_level_token(&clean_message, "FATAL")
        || has_log_level_token(&clean_message, "PANIC")
        || has_log_level_token(&clean_message, "ERROR")
    {
        "error"
    } else if has_log_level_token(&clean_message, "WARN")
        || has_log_level_token(&clean_message, "WARNING")
    {
        "warn"
    } else if has_log_level_token(&clean_message, "DEBUG")
        || has_log_level_token(&clean_message, "TRACE")
    {
        "debug"
    } else if has_log_level_token(&clean_message, "INFO") {
        "info"
    } else if matches!(fallback, "debug" | "info" | "warn" | "error") {
        fallback
    } else {
        "info"
    };
    (level.into(), clean_message)
}

fn forward_output<R: std::io::Read>(app: AppHandle, output: R, fallback_level: &str) {
    for line in BufReader::new(output).lines() {
        match line {
            Ok(message) => {
                let (level, clean_message) = classify_runtime_log(&message, fallback_level);
                emit_log(&app, &level, clean_message);
            }
            Err(error) => emit_log(&app, "error", format!("读取 sing-box 日志失败：{}", error)),
        }
    }
}

fn fetch_metrics(_app: &AppHandle, session: &MetricsSession) -> Option<RuntimeMetrics> {
    let mut metrics = RuntimeMetrics {
        upload_total: 0,
        download_total: 0,
        active_connections: 0,
        memory: 0,
        connections: Vec::new(),
        host_snapshot_valid: false,
        host_snapshot_error: Some("Host Clash API 尚未返回连接快照".into()),
        guest_snapshot_valid: !session.guest_required,
        guest_snapshot_error: session.guest_error.clone(),
        // Activity/metrics only expose connections reported by SongsterX's
        // Host sing-box or Gateway guest. macOS lsof snapshots are not merged
        // here because they also contain applications that bypass SongsterX.
        system_snapshot_valid: true,
        system_snapshot_error: None,
    };

    match ureq::get(&format!("http://{CLASH_API_ADDR}/connections"))
        .timeout(std::time::Duration::from_secs(2))
        .call()
    {
        Ok(response) => match response.into_string() {
            Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(host_value) => {
                    let host = runtime_metrics_from_clash_value(&host_value, "host");
                    merge_runtime_metrics_snapshot(&mut metrics, host, "host");
                    metrics.host_snapshot_valid = true;
                    metrics.host_snapshot_error = None;
                }
                Err(error) => {
                    metrics.host_snapshot_error =
                        Some(format!("Host Clash API 返回了无法解析的连接快照：{error}"));
                }
            },
            Err(error) => {
                metrics.host_snapshot_error =
                    Some(format!("读取 Host Clash API 响应失败：{error}"));
            }
        },
        Err(error) => {
            metrics.host_snapshot_error = Some(format!("Host Clash API 请求失败：{error}"));
        }
    }

    if session.guest_required {
        if let Some(endpoint) = session.guest_endpoint.as_ref() {
            match guest_agent::query_connections(&endpoint, Duration::from_secs(1)) {
                Ok(guest_value) => {
                    let guest = runtime_metrics_from_clash_value(&guest_value, "guest");
                    merge_runtime_metrics_snapshot(&mut metrics, guest, "guest");
                }
                Err(error) => {
                    metrics.guest_snapshot_valid = false;
                    metrics.guest_snapshot_error = Some(error.to_string());
                }
            }
        }
    }

    metrics.active_connections = metrics.connections.len();

    Some(metrics)
}

#[allow(dead_code)]
fn managed_system_endpoints(
    settings: Option<&RuntimeSettings>,
    module_proxy_port: Option<u16>,
) -> Vec<ManagedSystemEndpoint> {
    let mut endpoints = settings
        .filter(|value| !value.listen.trim().is_empty())
        .map(|value| {
            let host = value.listen.trim();
            ManagedSystemEndpoint {
                host: host.to_string(),
                port: value.port,
                wildcard_host: matches!(host, "0.0.0.0" | "::" | "*"),
                family: if host == "*" {
                    ManagedAddressFamily::Any
                } else {
                    managed_address_family(host)
                },
            }
        })
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(module_proxy_port) = module_proxy_port {
        if let Some(settings) = settings {
            let host = module_proxy_host(settings);
            endpoints.push(ManagedSystemEndpoint {
                family: managed_address_family(&host),
                host,
                port: module_proxy_port,
                wildcard_host: false,
            });
        }
    }
    endpoints
}

fn metrics_session_for_runtime(app: &AppHandle, settings: &RuntimeSettings) -> MetricsSession {
    if settings.mode != "gateway" {
        return MetricsSession {
            guest_endpoint: None,
            guest_required: false,
            guest_error: None,
        };
    }

    match gateway_guest_agent_endpoint(app, settings) {
        Ok(endpoint) => MetricsSession {
            guest_endpoint: Some(endpoint),
            guest_required: true,
            guest_error: None,
        },
        Err(error) => MetricsSession {
            guest_endpoint: None,
            guest_required: true,
            guest_error: Some(error),
        },
    }
}

fn runtime_metrics_from_clash_value(value: &serde_json::Value, runtime: &str) -> RuntimeMetrics {
    let upload_total = value["uploadTotal"].as_u64().unwrap_or(0);
    let download_total = value["downloadTotal"].as_u64().unwrap_or(0);
    let memory = value["memory"].as_u64().unwrap_or(0);

    let connections: Vec<ConnectionInfo> = value["connections"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let metadata = &item["metadata"];
                    ConnectionInfo {
                        id: item["id"]
                            .as_str()
                            .map(str::to_string)
                            .or_else(|| item["id"].as_u64().map(|id| id.to_string()))
                            .unwrap_or_default(),
                        runtime: runtime.to_string(),
                        source: format!(
                            "{}:{}",
                            metadata["sourceIP"].as_str().unwrap_or(""),
                            metadata["sourcePort"].as_str().unwrap_or("")
                        ),
                        destination: format!(
                            "{}:{}",
                            metadata["destinationIP"].as_str().unwrap_or(""),
                            metadata["destinationPort"].as_str().unwrap_or("")
                        ),
                        host: metadata["host"].as_str().unwrap_or("").to_string(),
                        network: metadata["network"].as_str().unwrap_or("").to_string(),
                        outbound: item["chains"]
                            .as_array()
                            .and_then(|chains| chains.last())
                            .and_then(|last| last.as_str())
                            .unwrap_or("")
                            .to_string(),
                        upload: Some(item["upload"].as_u64().unwrap_or(0)),
                        download: Some(item["download"].as_u64().unwrap_or(0)),
                        start: item["start"].as_str().unwrap_or("").to_string(),
                        process: String::new(),
                        pid: None,
                        state: "active".into(),
                        system_socket_key: None,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    RuntimeMetrics {
        upload_total,
        download_total,
        active_connections: connections.len(),
        memory,
        connections,
        host_snapshot_valid: runtime == "host",
        host_snapshot_error: None,
        guest_snapshot_valid: true,
        guest_snapshot_error: None,
        system_snapshot_valid: false,
        system_snapshot_error: None,
    }
}

fn merge_runtime_metrics_snapshot(
    target: &mut RuntimeMetrics,
    snapshot: RuntimeMetrics,
    runtime: &str,
) {
    if runtime == "host" {
        target.upload_total = snapshot.upload_total;
        target.download_total = snapshot.download_total;
        target.memory = snapshot.memory;
        target.connections = snapshot.connections;
        target.host_snapshot_valid = snapshot.host_snapshot_valid;
        target.host_snapshot_error = snapshot.host_snapshot_error;
    } else if runtime == "guest" {
        target.upload_total = target.upload_total.saturating_add(snapshot.upload_total);
        target.download_total = target
            .download_total
            .saturating_add(snapshot.download_total);
        target.memory = target.memory.saturating_add(snapshot.memory);
        target.connections.extend(snapshot.connections);
        target.guest_snapshot_valid = snapshot.guest_snapshot_valid;
        target.guest_snapshot_error = snapshot.guest_snapshot_error;
    }
    target.active_connections = target.connections.len();
}

fn split_system_endpoint(value: &str) -> (String, String) {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host.to_string(), port.to_string());
        }
    }
    value
        .rsplit_once(':')
        .map(|(host, port)| (host.to_string(), port.to_string()))
        .unwrap_or_else(|| (value.to_string(), String::new()))
}

fn system_connection_id(socket_key: &str, instance_generation: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(socket_key.as_bytes());
    digest.update(instance_generation.to_be_bytes());
    format!("system:{:x}", digest.finalize())
}

fn system_connection_socket_key(
    process: &str,
    pid: u32,
    network: &str,
    source: &str,
    destination: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(process.as_bytes());
    digest.update(pid.to_be_bytes());
    digest.update(network.as_bytes());
    digest.update(source.as_bytes());
    digest.update(destination.as_bytes());
    format!("system-socket:{:x}", digest.finalize())
}

fn system_connection_from_socket(
    timestamp: &str,
    process: &str,
    pid: u32,
    socket_kind: &str,
    socket: &str,
    state: &str,
) -> Option<ConnectionInfo> {
    let socket_kind = socket_kind.to_ascii_lowercase();
    if socket_kind != "tcp" && socket_kind != "udp" {
        return None;
    }
    let socket_without_state = socket
        .split_once(" (")
        .map(|(value, _)| value)
        .unwrap_or(socket);
    let (source, destination) = socket_without_state.split_once("->")?;
    let source = source.trim();
    let destination = destination.trim();
    if source.is_empty() || destination.is_empty() || destination == "*:*" || destination == "?" {
        return None;
    }
    let (host, _) = split_system_endpoint(destination);
    if host.is_empty() || host == "?" || host == "*" {
        return None;
    }
    let state = if state.is_empty() {
        if socket_kind == "udp" {
            "CONNECTED"
        } else {
            "UNKNOWN"
        }
    } else {
        state
    };
    if socket_kind == "tcp" && state != "ESTABLISHED" {
        return None;
    }
    let socket_key = system_connection_socket_key(process, pid, &socket_kind, source, destination);
    Some(ConnectionInfo {
        id: socket_key.clone(),
        runtime: "system".into(),
        source: source.into(),
        destination: destination.into(),
        host,
        network: socket_kind,
        outbound: "SYSTEM".into(),
        upload: None,
        download: None,
        start: timestamp.into(),
        process: process.into(),
        pid: Some(pid),
        state: state.into(),
        system_socket_key: Some(socket_key),
    })
}

#[cfg(test)]
fn system_connection_from_lsof_line(
    line: &str,
    timestamp: &str,
    process: &str,
    pid: u32,
) -> Option<ConnectionInfo> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 9 || fields.first().copied() == Some("COMMAND") {
        return None;
    }
    let socket_kind = fields.get(7)?.to_ascii_lowercase();
    let socket = fields[8..].join(" ");
    let state = socket
        .split_once(" (")
        .and_then(|(_, value)| value.strip_suffix(')'))
        .unwrap_or("");
    system_connection_from_socket(timestamp, process, pid, &socket_kind, &socket, state)
}

#[derive(Clone)]
struct ManagedSystemEndpoint {
    host: String,
    port: u16,
    wildcard_host: bool,
    family: ManagedAddressFamily,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManagedAddressFamily {
    Any,
    V4,
    V6,
}

fn managed_address_family(host: &str) -> ManagedAddressFamily {
    match host.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => ManagedAddressFamily::V4,
        Ok(IpAddr::V6(_)) => ManagedAddressFamily::V6,
        Err(_) => ManagedAddressFamily::Any,
    }
}

fn managed_address_family_matches(expected: ManagedAddressFamily, actual: &str) -> bool {
    let Ok(actual) = actual.parse::<IpAddr>() else {
        return true;
    };
    match (expected, actual) {
        (ManagedAddressFamily::Any, _) => true,
        (ManagedAddressFamily::V4, IpAddr::V4(_)) => true,
        (ManagedAddressFamily::V6, IpAddr::V6(_)) => true,
        _ => false,
    }
}

#[derive(Clone)]
struct MetricsSession {
    guest_endpoint: Option<guest_agent::GuestAgentEndpoint>,
    guest_required: bool,
    guest_error: Option<String>,
}

fn normalize_endpoint_host(value: &str) -> String {
    value.trim().trim_matches(['[', ']']).to_ascii_lowercase()
}

fn is_loopback_endpoint_host(value: &str) -> bool {
    let host = normalize_endpoint_host(value);
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn endpoint_host_matches(expected: &str, actual: &str) -> bool {
    let expected = normalize_endpoint_host(expected);
    let actual = normalize_endpoint_host(actual);
    if expected == "localhost" {
        return actual == "localhost" || actual == "127.0.0.1" || actual == "::1";
    }
    expected == actual
}

fn is_managed_local_destination(
    destination: &str,
    managed_endpoints: &[ManagedSystemEndpoint],
    local_addresses: &HashSet<String>,
) -> bool {
    let (host, port) = split_system_endpoint(destination);
    let normalized_host = normalize_endpoint_host(&host);
    managed_endpoints.iter().any(|endpoint| {
        endpoint.port == port.parse::<u16>().unwrap_or_default()
            && managed_address_family_matches(endpoint.family, &normalized_host)
            && ((endpoint.wildcard_host
                && (is_loopback_endpoint_host(&normalized_host)
                    || local_addresses.contains(&normalized_host)))
                || (!endpoint.wildcard_host
                    && endpoint_host_matches(&endpoint.host, &normalized_host)))
    })
}

fn is_managed_network_process(process: &str) -> bool {
    matches!(
        process.to_ascii_lowercase().as_str(),
        "sing-box"
            | "sing-box-linux"
            | "mitmdump"
            | "mitmproxy"
            | "songsterx"
            | "songsterx-gateway-agent"
    )
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn local_interface_addresses() -> HashSet<String> {
    let mut addresses = HashSet::from(["127.0.0.1".into(), "::1".into()]);
    let mut ifaddrs = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return addresses;
    }
    let mut current = ifaddrs;
    while !current.is_null() {
        let interface = unsafe { &*current };
        if !interface.ifa_addr.is_null() {
            let family = unsafe { (*interface.ifa_addr).sa_family as i32 };
            let address = unsafe {
                match family {
                    libc::AF_INET => {
                        let sockaddr = &*(interface.ifa_addr as *const libc::sockaddr_in);
                        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            sockaddr.sin_addr.s_addr,
                        ))))
                    }
                    libc::AF_INET6 => {
                        let sockaddr = &*(interface.ifa_addr as *const libc::sockaddr_in6);
                        Some(IpAddr::V6(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr)))
                    }
                    _ => None,
                }
            };
            if let Some(address) = address {
                addresses.insert(address.to_string().to_ascii_lowercase());
            }
        }
        current = unsafe { (*current).ifa_next };
    }
    unsafe { libc::freeifaddrs(ifaddrs) };
    addresses
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn local_interface_addresses() -> HashSet<String> {
    HashSet::from(["127.0.0.1".into(), "::1".into()])
}

#[derive(Default)]
struct LsofFileRecord {
    socket: Option<String>,
    state: String,
}

fn append_lsof_file_record(
    file: &mut LsofFileRecord,
    process: &str,
    pid: u32,
    network: &str,
    timestamp: &str,
    managed_endpoints: &[ManagedSystemEndpoint],
    local_addresses: &HashSet<String>,
    connections: &mut Vec<ConnectionInfo>,
) {
    let Some(socket) = file.socket.take() else {
        file.state.clear();
        return;
    };
    if let Some(connection) =
        system_connection_from_socket(timestamp, process, pid, network, &socket, &file.state)
    {
        if !is_managed_network_process(process)
            && !is_managed_local_destination(
                &connection.destination,
                managed_endpoints,
                local_addresses,
            )
        {
            connections.push(connection);
        }
    }
    file.state.clear();
}

fn parse_lsof_machine_output(
    output: &str,
    network: &str,
    timestamp: &str,
    managed_endpoints: &[ManagedSystemEndpoint],
    local_addresses: &HashSet<String>,
) -> Vec<ConnectionInfo> {
    let mut process = String::new();
    let mut pid = 0;
    let mut file = LsofFileRecord::default();
    let mut connections = Vec::new();

    for line in output.lines().filter(|line| !line.is_empty()) {
        let (field, value) = line.split_at(1);
        match field {
            "p" => {
                append_lsof_file_record(
                    &mut file,
                    &process,
                    pid,
                    network,
                    timestamp,
                    managed_endpoints,
                    local_addresses,
                    &mut connections,
                );
                process.clear();
                process.push_str(value);
                pid = value.parse().unwrap_or_default();
            }
            "c" => process = value.to_string(),
            "f" => append_lsof_file_record(
                &mut file,
                &process,
                pid,
                network,
                timestamp,
                managed_endpoints,
                local_addresses,
                &mut connections,
            ),
            "n" => file.socket = Some(value.to_string()),
            "T" if value.starts_with("ST=") => file.state = value[3..].to_string(),
            _ => {}
        }
    }
    append_lsof_file_record(
        &mut file,
        &process,
        pid,
        network,
        timestamp,
        managed_endpoints,
        local_addresses,
        &mut connections,
    );
    connections
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn fetch_system_connections(managed_endpoints: &[ManagedSystemEndpoint]) -> SystemConnectionSample {
    let (timestamp, _) = now_timestamp();
    let local_addresses = local_interface_addresses();
    let mut connections = Vec::new();
    for (flag, network) in [("-iTCP", "tcp"), ("-iUDP", "udp")] {
        let output = match Command::new("/usr/sbin/lsof")
            .args(["-nP", "-FpcfnT", flag])
            .output()
        {
            Ok(output) if output.status.success() => output,
            Ok(output)
                if output.status.code() == Some(1)
                    && output.stdout.is_empty()
                    && output.stderr.is_empty() =>
            {
                continue;
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return SystemConnectionSample {
                    connections: Vec::new(),
                    valid: false,
                    error: Some(if error.is_empty() {
                        format!("lsof {network} 退出码 {:?}", output.status.code())
                    } else {
                        error
                    }),
                };
            }
            Err(error) => {
                return SystemConnectionSample {
                    connections: Vec::new(),
                    valid: false,
                    error: Some(error.to_string()),
                };
            }
        };
        connections.extend(parse_lsof_machine_output(
            &String::from_utf8_lossy(&output.stdout),
            network,
            &timestamp,
            managed_endpoints,
            &local_addresses,
        ));
    }
    SystemConnectionSample {
        connections,
        valid: true,
        error: None,
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn fetch_system_connections(
    _managed_endpoints: &[ManagedSystemEndpoint],
) -> SystemConnectionSample {
    SystemConnectionSample {
        connections: Vec::new(),
        valid: true,
        error: None,
    }
}

fn assign_system_connection_instances(
    mut sample: SystemConnectionSample,
    identities: &mut SystemConnectionIdentityState,
) -> SystemConnectionSample {
    if !sample.valid {
        return sample;
    }
    let mut next_instances = HashMap::new();
    let mut seen_socket_keys = HashSet::new();
    let mut connections = Vec::with_capacity(sample.connections.len());
    for mut connection in sample.connections {
        let Some(socket_key) = connection.system_socket_key.clone() else {
            connections.push(connection);
            continue;
        };
        if !seen_socket_keys.insert(socket_key.clone()) {
            continue;
        }
        let instance_id = identities
            .active_instances
            .get(&socket_key)
            .cloned()
            .unwrap_or_else(|| {
                identities.next_generation = identities.next_generation.saturating_add(1);
                system_connection_id(&socket_key, identities.next_generation)
            });
        next_instances.insert(socket_key, instance_id.clone());
        connection.id = instance_id;
        connections.push(connection);
    }
    identities.active_instances = next_instances;
    sample.connections = connections;
    sample
}

#[allow(dead_code)]
fn spawn_system_connection_sampler(
    app: AppHandle,
    generation: Arc<AtomicU64>,
    expected: u64,
    managed_endpoints: Vec<ManagedSystemEndpoint>,
) {
    thread::spawn(move || {
        let mut identities = SystemConnectionIdentityState::default();
        loop {
            if generation.load(Ordering::SeqCst) != expected {
                break;
            }
            let sample = fetch_system_connections(&managed_endpoints);
            let sample = assign_system_connection_instances(sample, &mut identities);
            if generation.load(Ordering::SeqCst) != expected {
                break;
            }
            if let Ok(mut current) = app.state::<RuntimeState>().system_connections.lock() {
                if generation.load(Ordering::SeqCst) == expected {
                    *current = sample;
                } else {
                    break;
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
}

fn spawn_runtime_observers(
    app: AppHandle,
    generation: Arc<AtomicU64>,
    expected: u64,
    session: MetricsSession,
) {
    spawn_metrics_poller(app, generation, expected, session);
}

fn spawn_metrics_poller(
    app: AppHandle,
    generation: Arc<AtomicU64>,
    expected: u64,
    session: MetricsSession,
) {
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(1));
        if generation.load(Ordering::SeqCst) != expected {
            break;
        }
        let metrics = fetch_metrics(&app, &session);
        if generation.load(Ordering::SeqCst) != expected {
            break;
        }
        if let Some(metrics) = metrics {
            let state = app.state::<RuntimeState>();
            let _transition = lock_gateway_transition(&state);
            if generation.load(Ordering::SeqCst) != expected {
                break;
            }
            let _ = app.emit("runtime-metrics", metrics);
        }
        if generation.load(Ordering::SeqCst) != expected {
            break;
        }
        observe_gateway_packet_path(&app, &session, &generation, expected);
    });
}

fn restart_runtime_observers(app: &AppHandle, state: &RuntimeState) {
    let session = state
        .metrics_session
        .lock()
        .ok()
        .and_then(|current| current.clone());
    let Some(session) = session else {
        return;
    };
    let generation = Arc::clone(&state.metrics_generation);
    let expected = generation.fetch_add(1, Ordering::SeqCst) + 1;
    spawn_runtime_observers(app.clone(), generation, expected, session);
}

#[tauri::command]
fn stop_runtime(app: AppHandle, state: State<'_, RuntimeState>) -> Result<RuntimeStatus, String> {
    let mut phase = state
        .lifecycle_phase
        .lock()
        .map_err(|_| "Gateway 生命周期锁不可用".to_string())?;
    match *phase {
        LifecyclePhase::Stopped => return Ok(set_stopped(&state, "已停止")),
        LifecyclePhase::Stopping => return current_status(&state),
        LifecyclePhase::Starting | LifecyclePhase::Running => {
            *phase = LifecyclePhase::Stopping;
        }
    }
    drop(phase);
    state.lifecycle_generation.fetch_add(1, Ordering::SeqCst);
    let mut stopping = current_status(&state)?;
    stopping.state = "stopping".into();
    stopping.healthy = false;
    stopping.can_stop = runtime_owns_resources(&state);
    stopping.message = "正在停止运行时".into();
    update_status(&state, stopping.clone());

    let worker_app = app.clone();
    thread::spawn(move || {
        let worker_state = worker_app.state::<RuntimeState>();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stop_runtime_processes(&worker_app, &worker_state)
        }));
        match result {
            Ok(Ok(())) => {
                mark_lifecycle_phase(&worker_state, LifecyclePhase::Stopped);
                let _ = set_stopped(&worker_state, "已停止");
            }
            Ok(Err(error)) => {
                let resources_owned = runtime_owns_resources(&worker_state);
                mark_lifecycle_phase(
                    &worker_state,
                    if resources_owned {
                        LifecyclePhase::Running
                    } else {
                        LifecyclePhase::Stopped
                    },
                );
                let current = current_status(&worker_state).unwrap_or_default();
                update_status(
                    &worker_state,
                    status_after_stop_failure(current, resources_owned, error.clone()),
                );
                if resources_owned {
                    restart_runtime_observers(&worker_app, &worker_state);
                }
                emit_log(&worker_app, "error", error);
            }
            Err(_) => {
                let resources_owned = runtime_owns_resources(&worker_state);
                mark_lifecycle_phase(
                    &worker_state,
                    if resources_owned {
                        LifecyclePhase::Running
                    } else {
                        LifecyclePhase::Stopped
                    },
                );
                let error = if resources_owned {
                    "停止 worker 异常退出，仍有运行时资源未回收；请再次停止".to_string()
                } else {
                    "停止 worker 异常退出，已确认没有运行时资源".to_string()
                };
                let current = current_status(&worker_state).unwrap_or_default();
                update_status(
                    &worker_state,
                    status_after_stop_failure(current, resources_owned, error.clone()),
                );
                if resources_owned {
                    restart_runtime_observers(&worker_app, &worker_state);
                }
                emit_log(&worker_app, "error", error);
            }
        }
    });
    Ok(stopping)
}

fn stop_runtime_processes(app: &AppHandle, state: &RuntimeState) -> Result<(), String> {
    state.metrics_generation.fetch_add(1, Ordering::SeqCst);
    let _gateway_transition = lock_gateway_transition(state);
    let guest_endpoint = state
        .metrics_session
        .lock()
        .ok()
        .and_then(|session| {
            session
                .as_ref()
                .and_then(|current| current.guest_endpoint.clone())
        })
        .or_else(|| match load_settings(app) {
            Ok(settings) if settings.mode == "gateway" => {
                match gateway_guest_agent_endpoint(app, &settings) {
                    Ok(endpoint) => Some(endpoint),
                    Err(error) => {
                        emit_log(
                            app,
                            "warn",
                            format!("无法发送 guest-agent 停止提示：{error}"),
                        );
                        None
                    }
                }
            }
            _ => None,
        });
    if let Some(endpoint) = guest_endpoint {
        let guest_app = app.clone();
        thread::spawn(move || {
            match guest_agent::stop_guest_runtime(&endpoint, GATEWAY_AGENT_STOP_TIMEOUT) {
                Ok(()) => {}
                Err(error) => emit_log(
                    &guest_app,
                    "warn",
                    format!("guest-agent 停止数据面未及时确认，已继续回收 VM：{error}"),
                ),
            }
        });
    }
    let result = stop_runtime_processes_locked(app, state);
    if result.is_ok() || !runtime_owns_resources(state) {
        if let Ok(mut session) = state.metrics_session.lock() {
            *session = None;
        }
    }
    result
}

fn stop_runtime_processes_locked(app: &AppHandle, state: &RuntimeState) -> Result<(), String> {
    if let Ok(mut baseline) = state.gateway_packet_baseline.lock() {
        *baseline = None;
    }
    if let Ok(mut sample) = state.system_connections.lock() {
        *sample = SystemConnectionSample::default();
    }
    let managed_gateway = state
        .gateway_runtime
        .lock()
        .map_err(|_| "Gateway runtime 锁不可用".to_string())?
        .take();
    let mitm_child = state
        .mitm_child
        .lock()
        .map_err(|_| "运行时锁不可用".to_string())?
        .take();
    let local_child = state
        .child
        .lock()
        .map_err(|_| "运行时锁不可用".to_string())?
        .take();
    let (gateway_result, mitm_result, local_result) = thread::scope(|scope| {
        let gateway_task = managed_gateway.map(|mut runtime| {
            scope.spawn(move || {
                let result = runtime.stop();
                (runtime, result)
            })
        });
        let mitm_task = mitm_child.map(|mut child| {
            scope.spawn(move || {
                let kill = child.kill();
                let wait = child.wait();
                (child, kill, wait)
            })
        });
        let local_task = local_child.map(|mut child| {
            scope.spawn(move || {
                let kill = child.kill();
                let wait = child.wait();
                (child, kill, wait)
            })
        });
        (
            gateway_task.map(|task| task.join()),
            mitm_task.map(|task| task.join()),
            local_task.map(|task| task.join()),
        )
    });

    let mut errors = Vec::new();
    if let Some(result) = gateway_result {
        match result {
            Ok((_runtime, Ok(()))) => {
                if let Ok(mut readiness) = state.gateway_readiness.lock() {
                    readiness.mark_stopped();
                }
                emit_log(app, "info", "vfkit Gateway supervisor 已停止");
            }
            Ok((runtime, Err(error))) => {
                if let Ok(mut slot) = state.gateway_runtime.lock() {
                    *slot = Some(runtime);
                }
                errors.push(format!("停止 vfkit Gateway supervisor 失败：{error}"));
            }
            Err(_) => errors.push("停止 vfkit Gateway supervisor 的回收线程异常退出".into()),
        }
    }
    if let Some(result) = mitm_result {
        match result {
            Ok((child, Ok(()), Ok(_))) => {
                emit_log(app, "info", "Module Engine 已停止");
                drop(child);
            }
            Ok((child, kill, wait)) => {
                if let Err(error) = kill {
                    errors.push(format!("停止 Module Engine 失败：{error}"));
                }
                if let Err(error) = wait {
                    errors.push(format!("等待 Module Engine 停止失败：{error}"));
                }
                if let Ok(mut slot) = state.mitm_child.lock() {
                    *slot = Some(child);
                }
            }
            Err(_) => errors.push("停止 Module Engine 的回收线程异常退出".into()),
        }
    }
    if let Some(result) = local_result {
        match result {
            Ok((child, Ok(()), Ok(_))) => {
                emit_log(app, "info", "Mixed 入口已停止");
                drop(child);
            }
            Ok((child, kill, wait)) => {
                if let Err(error) = kill {
                    errors.push(format!("停止 Mixed 入口失败：{error}"));
                }
                if let Err(error) = wait {
                    errors.push(format!("等待 Mixed 入口停止失败：{error}"));
                }
                if let Ok(mut slot) = state.child.lock() {
                    *slot = Some(child);
                }
            }
            Err(_) => errors.push("停止 Mixed 入口的回收线程异常退出".into()),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

#[tauri::command]
fn get_app_info() -> serde_json::Value {
    serde_json::json!({
        "product": "SongsterX",
        "version": "0.1.0",
        "platform": env::consts::OS,
        "mode": "mixed-direct-or-gateway-no-dhcp"
    })
}

#[tauri::command]
fn get_config_documents(app: AppHandle) -> Result<Vec<ConfigDocument>, String> {
    let settings = load_settings(&app)?;
    let module_plan = load_module_runtime_plan(&app)?;
    let songsterx_path = songsterx_config_path(&app)?;
    let runtime_path = runtime_config_path(&app)?;
    let songsterx_config = ensure_songsterx_config(&app)?;
    let sing_box_config = if runtime_path.is_file() {
        fs::read_to_string(&runtime_path).map_err(|error| {
            format!("无法读取 sing-box 配置 {}：{error}", runtime_path.display())
        })?
    } else {
        write_runtime_config(&app, &settings, &module_plan)?;
        fs::read_to_string(&runtime_path).map_err(|error| {
            format!(
                "无法读取生成的 sing-box 配置 {}：{error}",
                runtime_path.display()
            )
        })?
    };
    let mut documents = vec![
        ConfigDocument {
            id: "songsterx-config".into(),
            title: "用户配置 · SongsterX.conf".into(),
            path: songsterx_path.display().to_string(),
            content: songsterx_config,
        },
        ConfigDocument {
            id: "sing-box-runtime".into(),
            title: "运行时 JSON · sing-box".into(),
            path: runtime_path.display().to_string(),
            content: sing_box_config,
        },
    ];
    if settings.mode == "gateway" {
        let gateway_path = write_gateway_guest_runtime_config(&app, &settings, &module_plan)?;
        let gateway_config = fs::read_to_string(&gateway_path).map_err(|error| {
            format!(
                "无法读取 Gateway guest sing-box 配置 {}：{error}",
                gateway_path.display()
            )
        })?;
        documents.push(ConfigDocument {
            id: "sing-box-gateway-guest".into(),
            title: "Gateway guest JSON · sing-box".into(),
            path: gateway_path.display().to_string(),
            content: gateway_config,
        });
    }
    Ok(documents)
}

#[tauri::command]
fn reload_songsterx_config(
    app: AppHandle,
    state: State<'_, RuntimeState>,
) -> Result<ConfigReloadResult, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再从 SongsterX.conf 重载配置".into());
    }
    let path = songsterx_config_path(&app)?;
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取 SongsterX 配置 {}：{error}", path.display()))?;
    let parsed = parse_songsterx_config(&content)?;
    let SongsterXUserConfig {
        settings,
        proxy_config,
        ..
    } = parsed;
    Ok(ConfigReloadResult {
        settings,
        proxy_config,
        modules: load_modules(&app)?,
    })
}

#[tauri::command]
fn get_modules(app: AppHandle) -> Result<Vec<ModuleInfo>, String> {
    load_modules(&app)
}

#[tauri::command]
fn get_mitm_certificate_info(app: AppHandle) -> Result<MitmCertificateInfo, String> {
    match mitm_certificate_path(&app) {
        Ok(path) => Ok(MitmCertificateInfo {
            available: true,
            path: path.display().to_string(),
            client_note: "HTTPS MITM 的每台客户端都必须信任此根证书；Gateway 模式下本机安装不会替 LAN 客户端安装。".into(),
        }),
        Err(_) => Ok(MitmCertificateInfo {
            available: false,
            path: String::new(),
            client_note: "启动一次包含 MITM 主机的模块后，SongsterX 才会生成根证书。".into(),
        }),
    }
}

#[tauri::command]
fn open_mitm_certificate(app: AppHandle) -> Result<(), String> {
    let path = mitm_certificate_path(&app)?;
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("/usr/bin/open")
            .arg(&path)
            .status()
            .map_err(|error| format!("无法打开 MITM 根证书：{error}"))?;
        if !status.success() {
            return Err(format!("打开 MITM 根证书失败，状态码：{status}"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("当前平台暂不支持从 SongsterX 打开证书安装器；请手工分发 MITM 根证书。".into())
    }
}

#[tauri::command]
fn install_mitm_certificate(app: AppHandle) -> Result<(), String> {
    let path = mitm_certificate_path(&app)?;
    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "无法定位当前用户 HOME 目录".to_string())?;
        let keychain = home.join("Library/Keychains/login.keychain-db");
        if !keychain.is_file() {
            return Err(format!("当前用户登录钥匙串不存在：{}", keychain.display()));
        }
        let output = Command::new("/usr/bin/security")
            .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
            .arg(&keychain)
            .arg(&path)
            .output()
            .map_err(|error| format!("无法调用 macOS 证书工具：{error}"))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(if detail.is_empty() {
                format!("安装 MITM 根证书失败，状态码：{}", output.status)
            } else {
                format!("安装 MITM 根证书失败：{detail}")
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("当前平台暂不支持自动安装 MITM 根证书；请手工导入并信任证书。".into())
    }
}

#[tauri::command]
fn import_module(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    files: Vec<ImportedFile>,
) -> Result<Vec<ModuleInfo>, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再导入模块".into());
    }
    persist_imported_module_files(&app, files)
}

fn persist_imported_module_files(
    app: &AppHandle,
    files: Vec<ImportedFile>,
) -> Result<Vec<ModuleInfo>, String> {
    if files.is_empty() {
        return Err("没有选择模块文件".into());
    }
    let total_size: usize = files.iter().map(|file| file.content.len()).sum();
    if total_size > 16 * 1024 * 1024 {
        return Err("模块及其资源不能超过 16 MiB".into());
    }
    let module_index = files
        .iter()
        .position(|file| {
            let lower_name = file.name.to_ascii_lowercase();
            lower_name.ends_with(".sgmodule")
                || lower_name.ends_with(".module")
                || (file.content.contains("#!name") && file.content.contains('['))
        })
        .ok_or_else(|| {
            "请选择 .sgmodule 或 .module 文件；脚本和规则集可同时多选导入".to_string()
        })?;
    let module_file = files[module_index].clone();
    let (
        parsed_name,
        _description,
        _version,
        sections,
        _scripts,
        _hosts,
        _rule_count,
        _script_count,
    ) = parse_module_source(&module_file.content);
    let display_name = if parsed_name.trim().is_empty() {
        Path::new(&module_file.name)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("模块")
            .to_string()
    } else {
        parsed_name
    };
    let module_hash = sha256_bytes(module_file.content.as_bytes());
    let mut id = safe_module_filename(&display_name);
    if id.is_empty() {
        id = format!("module-{}", &module_hash[..8]);
    }
    let module_root = module_root(app)?;
    let module_directory = module_root.join(&id);
    let assets_directory = module_directory.join("assets");
    fs::create_dir_all(&assets_directory)
        .map_err(|error| format!("无法创建模块资源目录：{error}"))?;
    let module_relative = format!("modules/{id}/{id}.sgmodule");
    let module_path = module_root.join(&id).join(format!("{id}.sgmodule"));
    write_private_file(&module_path, module_file.content.as_bytes())
        .map_err(|error| format!("无法保存模块 {}：{error}", module_path.display()))?;

    let references = module_asset_references(&module_file.content);
    let mut assets = load_imported_assets(app)?;
    assets.retain(|asset| asset.module != id);
    for (kind, source) in references {
        let source_name = asset_basename(&source);
        let matching_assets: Vec<&ImportedFile> = files
            .iter()
            .enumerate()
            .filter(|(index, file)| {
                *index != module_index
                    && (file.name.eq_ignore_ascii_case(&source)
                        || asset_basename(&file.name).eq_ignore_ascii_case(&source_name))
            })
            .map(|(_, file)| file)
            .collect();
        if matching_assets.len() > 1 {
            return Err(format!(
                "模块资源 {} 存在多个同名候选，拒绝绑定不明确的资源",
                source
            ));
        }
        let Some(asset_file) = matching_assets.into_iter().next() else {
            continue;
        };
        let filename = safe_asset_filename(&asset_file.name);
        let asset_path = assets_directory.join(&filename);
        write_private_file(&asset_path, asset_file.content.as_bytes())
            .map_err(|error| format!("无法保存模块资源 {}：{error}", asset_path.display()))?;
        assets.push(ModuleAssetEntry {
            kind,
            module: id.clone(),
            source,
            local_file: format!("modules/{id}/assets/{filename}"),
            sha256: sha256_bytes(asset_file.content.as_bytes()),
        });
    }

    let mut manifest = load_imported_manifest(app)?;
    let content_replaced = manifest
        .iter()
        .find(|item| item.id == id)
        .is_some_and(|item| item.sha256 != module_hash);
    let entry = ModuleManifestEntry {
        id: id.clone(),
        source: module_file.name,
        local_file: module_relative,
        sha256: module_hash,
        sections,
    };
    if let Some(existing) = manifest.iter_mut().find(|item| item.id == id) {
        *existing = entry;
    } else {
        manifest.push(entry);
    }
    persist_imported_manifest(app, &manifest)?;
    persist_imported_assets(app, &assets)?;
    if content_replaced {
        let mut preferences = load_module_preferences(app)?;
        for preference in &mut preferences.modules {
            if preference.id == id {
                preference.enabled = false;
            }
        }
        persist_module_preferences(app, &preferences)?;
    } else {
        write_songsterx_config_from_current_state(app)?;
    }
    load_modules(app)
}

fn download_module_text(url: &str) -> Result<String, String> {
    const MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;
    let mut current_url = url.to_string();
    for redirect_count in 0..=5 {
        let parsed =
            url::Url::parse(&current_url).map_err(|error| format!("模块 URL 无效：{error}"))?;
        if parsed.scheme() != "https" {
            return Err("模块资源只允许通过 HTTPS 导入".into());
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| "模块 URL 缺少主机名".to_string())?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addresses: Vec<std::net::SocketAddr> =
            std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                .map_err(|error| format!("无法解析模块 URL 主机：{error}"))?
                .collect();
        if addresses.is_empty() {
            return Err("模块 URL 主机没有可用地址".into());
        }
        for address in &addresses {
            let ip = address.ip();
            let blocked = match ip {
                std::net::IpAddr::V4(value) => {
                    value.is_private()
                        || value.is_loopback()
                        || value.is_link_local()
                        || value.is_broadcast()
                        || value.is_unspecified()
                        || value.is_multicast()
                }
                std::net::IpAddr::V6(value) => {
                    value.is_loopback()
                        || value.is_unspecified()
                        || value.is_multicast()
                        || value.is_unique_local()
                        || value.is_unicast_link_local()
                }
            };
            if blocked {
                return Err("模块资源 URL 不允许访问本机或私有网络地址".into());
            }
        }

        // Disable ureq's implicit redirects and pin this request to the
        // already-validated address set. Every redirect is parsed, checked,
        // resolved and pinned again before it can be followed.
        let pinned_addresses = addresses.clone();
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .resolver(move |_netloc: &str| Ok(pinned_addresses.clone()))
            .timeout(std::time::Duration::from_secs(30))
            .build();
        let response = agent
            .get(&current_url)
            .call()
            .map_err(|error| format!("下载失败：{error}"))?;
        if (300..400).contains(&response.status()) {
            if redirect_count == 5 {
                return Err("模块 URL 重定向次数超过 5 次".into());
            }
            let location = response
                .header("Location")
                .ok_or_else(|| "模块 URL 重定向缺少 Location".to_string())?;
            current_url = parsed
                .join(location)
                .map_err(|error| format!("模块重定向 URL 无效：{error}"))?
                .to_string();
            continue;
        }
        if response.status() != 200 {
            return Err(format!("模块下载返回 HTTP {}", response.status()));
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_DOWNLOAD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("读取下载内容失败：{error}"))?;
        if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
            return Err("下载内容超过 8 MiB 限制".into());
        }
        return String::from_utf8(bytes).map_err(|_| "模块资源必须是 UTF-8 文本".into());
    }
    Err("模块下载失败：重定向流程未完成".into())
}

fn resolve_module_reference(base: &str, reference: &str) -> Option<String> {
    let reference = reference.trim();
    if reference.starts_with("https://") || reference.starts_with("http://") {
        return Some(reference.to_string());
    }
    let scheme_end = base.find("://")?;
    let authority_start = scheme_end + 3;
    let authority_end = base[authority_start..]
        .find('/')
        .map(|index| authority_start + index)
        .unwrap_or(base.len());
    let origin = &base[..authority_end];
    if reference.starts_with("//") {
        return Some(format!("{}:{}", &base[..scheme_end], reference));
    }
    if reference.starts_with('/') {
        return Some(format!("{origin}{reference}"));
    }
    let base_directory = base
        .rsplit_once('/')
        .map(|(directory, _)| directory)
        .unwrap_or(base);
    Some(format!("{base_directory}/{reference}"))
}

#[tauri::command]
fn import_module_url(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    url: String,
) -> Result<Vec<ModuleInfo>, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再导入模块".into());
    }
    let url = url.trim().to_string();
    if url::Url::parse(&url)
        .ok()
        .is_none_or(|parsed| parsed.scheme() != "https")
    {
        return Err("模块 URL 必须使用 https://".into());
    }
    let module_content = download_module_text(&url)?;
    let mut files = vec![ImportedFile {
        name: url.clone(),
        content: module_content.clone(),
    }];
    let mut downloaded = module_content.len();
    for (_kind, source) in module_asset_references(&module_content) {
        let Some(dependency_url) = resolve_module_reference(&url, &source) else {
            continue;
        };
        let dependency_content = download_module_text(&dependency_url)
            .map_err(|error| format!("模块依赖下载失败：{dependency_url}：{error}"))?;
        downloaded = downloaded.saturating_add(dependency_content.len());
        if downloaded > 16 * 1024 * 1024 {
            return Err("模块及其远程依赖不能超过 16 MiB".into());
        }
        files.push(ImportedFile {
            name: asset_basename(&source),
            content: dependency_content,
        });
    }
    persist_imported_module_files(&app, files)
}

#[tauri::command]
fn set_module_enabled(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    id: String,
    enabled: bool,
) -> Result<Vec<ModuleInfo>, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再修改模块启用状态".into());
    }
    let modules = load_modules(&app)?;
    let module = modules
        .iter()
        .find(|module| module.id == id)
        .ok_or_else(|| format!("找不到模块：{id}"))?;
    if enabled && !module.verified {
        return Err(format!("模块 {} 未通过完整性校验，不能启用", module.name));
    }
    let mut preferences = load_module_preferences(&app)?;
    if let Some(preference) = preferences
        .modules
        .iter_mut()
        .find(|preference| preference.id == id)
    {
        preference.enabled = enabled;
    } else {
        preferences.modules.push(ModulePreference { id, enabled });
    }
    persist_module_preferences(&app, &preferences)?;
    load_modules(&app)
}

#[tauri::command]
fn set_module_argument(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    id: String,
    key: String,
    value: String,
) -> Result<Vec<ModuleInfo>, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再修改模块参数".into());
    }
    if value.len() > 64 * 1024 {
        return Err("模块参数不能超过 64 KiB".into());
    }
    let modules = load_modules(&app)?;
    let module = modules
        .iter()
        .find(|module| module.id == id)
        .ok_or_else(|| format!("找不到模块：{id}"))?;
    if !module.arguments.iter().any(|argument| argument.name == key) {
        return Err(format!("模块 {} 不存在参数：{}", module.name, key));
    }
    let mut preferences = load_module_preferences(&app)?;
    preferences
        .argument_values
        .entry(id)
        .or_default()
        .insert(key, value);
    persist_module_preferences(&app, &preferences)?;
    load_modules(&app)
}

#[tauri::command]
fn get_proxy_config(app: AppHandle) -> Result<ProxyConfig, String> {
    load_proxy_config(&app)
}

#[tauri::command]
fn get_gateway_guest_proxy_config(app: AppHandle) -> Result<ProxyConfig, String> {
    load_gateway_guest_proxy_config(&app)
}

#[tauri::command]
fn save_proxy_config(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    config: ProxyConfig,
) -> Result<ProxyConfig, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再保存代理配置".into());
    }
    persist_proxy_config(&app, &config)
}

#[tauri::command]
fn save_gateway_guest_proxy_config(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    config: ProxyConfig,
) -> Result<ProxyConfig, String> {
    if runtime_mutation_allowed(&state).is_err() {
        return Err("请先停止运行时，再保存 Gateway guest 策略".into());
    }
    persist_gateway_guest_proxy_config(&app, &config)
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyInfo {
    name: String,
    kind: String,
    now: String,
    all: Vec<String>,
}

fn parse_proxy_info(value: serde_json::Value) -> Result<Vec<ProxyInfo>, String> {
    let value = value
        .as_object()
        .ok_or_else(|| "解析代理数据失败：响应不是 JSON object".to_string())?;

    let mut result: Vec<ProxyInfo> = vec![];
    if let Some(proxies) = value.get("proxies").and_then(serde_json::Value::as_object) {
        for (name, info) in proxies {
            let kind = info["type"].as_str().unwrap_or("").to_string();
            let now = info["now"].as_str().unwrap_or("").to_string();
            let all = info["all"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            result.push(ProxyInfo {
                name: name.clone(),
                kind,
                now,
                all,
            });
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

fn fetch_proxies() -> Result<Vec<ProxyInfo>, String> {
    let body = ureq::get(&format!("http://{CLASH_API_ADDR}/proxies"))
        .timeout(std::time::Duration::from_secs(2))
        .call()
        .map_err(|error| format!("无法连接 sing-box API：{error}"))?
        .into_string()
        .map_err(|error| error.to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|error| format!("解析代理数据失败：{error}"))?;
    parse_proxy_info(value)
}

fn require_guest_proxy_target(
    app: &AppHandle,
    target: &str,
) -> Result<guest_agent::GuestAgentEndpoint, String> {
    if target != "guest" {
        return Err("不是 Gateway guest 策略目标".into());
    }
    let settings = load_settings(app)?;
    if settings.mode != "gateway" || settings.gateway_policy_mode != "separate" {
        return Err("只有 Gateway 独立策略可以操作 guest 实时 API".into());
    }
    gateway_guest_agent_endpoint(app, &settings)
}

#[tauri::command]
fn get_proxies(app: AppHandle, target: Option<String>) -> Result<Vec<ProxyInfo>, String> {
    if target.as_deref() == Some("guest") {
        let endpoint = require_guest_proxy_target(&app, "guest")?;
        let value = guest_agent::query_proxies(&endpoint, Duration::from_secs(2))?;
        return parse_proxy_info(value);
    }
    fetch_proxies()
}

fn percent_encode_query(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        let byte = *byte;
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[tauri::command]
fn test_proxy_delay(
    app: AppHandle,
    name: String,
    url: Option<String>,
    timeout_ms: Option<u64>,
    target: Option<String>,
) -> Result<u64, String> {
    let target_url = url.unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
    let timeout = timeout_ms.unwrap_or(5_000).clamp(1_000, 60_000);
    if target.as_deref() == Some("guest") {
        let endpoint = require_guest_proxy_target(&app, "guest")?;
        return guest_agent::test_proxy_delay(
            &endpoint,
            &name,
            target_url.trim(),
            timeout,
            Duration::from_millis(timeout + 1_000),
        );
    }
    let endpoint = format!(
        "http://{CLASH_API_ADDR}/proxies/{}/delay?timeout={timeout}&url={}",
        percent_encode_query(&name),
        percent_encode_query(target_url.trim()),
    );
    let response = ureq::get(&endpoint)
        .timeout(std::time::Duration::from_millis(timeout + 1_000))
        .call()
        .map_err(|error| format!("测试节点 {name} 失败：{error}"))?;
    let body = response
        .into_string()
        .map_err(|error| format!("读取节点 {name} 测试结果失败：{error}"))?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| format!("解析节点 {name} 测试结果失败：{error}"))?;
    value["delay"]
        .as_u64()
        .ok_or_else(|| format!("节点 {name} 未返回有效延迟：{body}"))
}

#[tauri::command]
fn select_proxy(
    app: AppHandle,
    group: String,
    name: String,
    target: Option<String>,
) -> Result<(), String> {
    if target.as_deref() == Some("guest") {
        let endpoint = require_guest_proxy_target(&app, "guest")?;
        return guest_agent::select_proxy(&endpoint, &group, &name, Duration::from_secs(2));
    }
    let body = serde_json::json!({ "name": name });
    let response = ureq::put(&format!("http://{CLASH_API_ADDR}/proxies/{group}"))
        .timeout(std::time::Duration::from_secs(2))
        .send_json(body)
        .map_err(|error| format!("切换策略失败：{error}"))?;
    if response.status() >= 400 {
        return Err(format!("切换策略失败，状态码 {}", response.status()));
    }
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .manage(RuntimeState::default())
        .invoke_handler(tauri::generate_handler![
            get_runtime_status,
            get_runtime_settings,
            save_runtime_settings,
            reset_runtime_settings,
            get_gateway_guest_status,
            generate_gateway_guest_config,
            upgrade_gateway_sing_box,
            get_mitm_certificate_info,
            open_mitm_certificate,
            install_mitm_certificate,
            start_mix_direct,
            stop_runtime,
            get_app_info,
            get_config_documents,
            reload_songsterx_config,
            get_modules,
            import_module,
            import_module_url,
            set_module_enabled,
            set_module_argument,
            get_proxy_config,
            get_gateway_guest_proxy_config,
            save_proxy_config,
            save_gateway_guest_proxy_config,
            get_proxies,
            test_proxy_delay,
            select_proxy
        ])
        .build(tauri::generate_context!())
        .expect("error while building SongsterX")
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let state = app_handle.state::<RuntimeState>();
                if let Err(error) = stop_runtime_processes(app_handle, &state) {
                    eprintln!("退出时停止运行时失败：{error}");
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_runtime_release_gate_is_open_and_not_a_prelaunch_readiness_probe() {
        assert!(GATEWAY_GUEST_PACKET_PATH_RELEASE_GATE);
        assert!(GATEWAY_PACKET_PATH_UNAVAILABLE.contains("等待验收"));
        assert!(GATEWAY_PACKET_PATH_UNAVAILABLE.contains("LAN 与 tun0"));
    }

    #[test]
    fn stop_failure_with_owned_resources_remains_stoppable() {
        let mut current = RuntimeStatus::default();
        current.mode = "lan-gateway no-dhcp".into();
        current.pid = Some(42);
        let next = status_after_stop_failure(current, true, "child refused to exit");
        assert_eq!(next.state, "running");
        assert!(!next.healthy);
        assert!(next.can_stop);
        assert_eq!(next.mode, "lan-gateway no-dhcp");
        assert_eq!(next.pid, Some(42));
        assert_eq!(next.message, "child refused to exit");
    }

    #[test]
    fn stop_failure_without_owned_resources_is_error() {
        let next = status_after_stop_failure(RuntimeStatus::default(), false, "teardown failed");
        assert_eq!(next.state, "error");
        assert!(!next.healthy);
        assert!(!next.can_stop);
        assert_eq!(next.message, "teardown failed");
    }

    #[test]
    fn host_metrics_merge_preserves_guest_failure_state() {
        let mut metrics = RuntimeMetrics {
            upload_total: 0,
            download_total: 0,
            active_connections: 0,
            memory: 0,
            connections: Vec::new(),
            host_snapshot_valid: false,
            host_snapshot_error: Some("Host 尚未返回".into()),
            guest_snapshot_valid: false,
            guest_snapshot_error: Some("Guest endpoint 不可用".into()),
            system_snapshot_valid: false,
            system_snapshot_error: None,
        };
        let host = runtime_metrics_from_clash_value(
            &serde_json::json!({"uploadTotal": 4, "downloadTotal": 8, "memory": 16, "connections": []}),
            "host",
        );

        merge_runtime_metrics_snapshot(&mut metrics, host, "host");

        assert!(metrics.host_snapshot_valid);
        assert_eq!(metrics.host_snapshot_error, None);
        assert!(!metrics.guest_snapshot_valid);
        assert_eq!(
            metrics.guest_snapshot_error.as_deref(),
            Some("Guest endpoint 不可用")
        );
        assert_eq!(metrics.upload_total, 4);
        assert_eq!(metrics.download_total, 8);
        assert_eq!(metrics.memory, 16);
    }

    #[test]
    fn runtime_mutation_gate_uses_lifecycle_phase_only() {
        let state = RuntimeState::default();
        assert!(runtime_mutation_allowed(&state).is_ok());
        assert!(!runtime_phase_is_active(&state).unwrap());

        mark_lifecycle_phase(&state, LifecyclePhase::Stopping);
        assert!(runtime_mutation_allowed(&state).is_err());
        assert!(runtime_phase_is_active(&state).unwrap());

        mark_lifecycle_phase(&state, LifecyclePhase::Running);
        assert!(runtime_mutation_allowed(&state).is_err());
        assert!(runtime_phase_is_active(&state).unwrap());
    }

    fn interface_stats(
        interface: &str,
        rx_packets: u64,
        tx_packets: u64,
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> guest_agent::GuestInterfaceStats {
        guest_agent::GuestInterfaceStats {
            interface: interface.into(),
            rx_packets,
            tx_packets,
            rx_bytes,
            tx_bytes,
        }
    }

    #[test]
    fn gateway_packet_path_requires_both_lan_and_tun_progress() {
        let before = guest_agent::GuestPacketStats {
            lan: Some(interface_stats("eth0", 10, 10, 1_000, 1_000)),
            tun: Some(interface_stats("tun0", 20, 20, 2_000, 2_000)),
        };
        let lan_only = guest_agent::GuestPacketStats {
            lan: Some(interface_stats("eth0", 11, 10, 1_100, 1_000)),
            tun: before.tun.clone(),
        };
        let both = guest_agent::GuestPacketStats {
            lan: lan_only.lan.clone(),
            tun: Some(interface_stats("tun0", 21, 20, 2_100, 2_000)),
        };

        assert!(!guest_packet_path_progressed(&before, &lan_only));
        assert!(guest_packet_path_progressed(&before, &both));
    }

    #[test]
    fn gateway_packet_path_is_not_ready_without_both_interface_snapshots() {
        let before = guest_agent::GuestPacketStats {
            lan: Some(interface_stats("eth0", 10, 10, 1_000, 1_000)),
            tun: None,
        };
        let after = guest_agent::GuestPacketStats {
            lan: Some(interface_stats("eth0", 11, 10, 1_100, 1_000)),
            tun: Some(interface_stats("tun0", 1, 0, 100, 0)),
        };

        assert!(!guest_packet_path_progressed(&before, &after));
    }

    #[test]
    fn runtime_logs_use_embedded_level_instead_of_stream_level() {
        let (level, message) = classify_runtime_log(
            "unix:1786870907 +0800 \u{1b}[36mINFO\u{1b}[0m sing-box started",
            "error",
        );
        assert_eq!(level, "info");
        assert_eq!(message, "unix:1786870907 +0800 INFO sing-box started");

        let (level, _) =
            classify_runtime_log("unix:1786870907 +0800 ERROR failed to start", "info");
        assert_eq!(level, "error");
    }

    #[test]
    fn system_lsof_parser_keeps_process_endpoint_and_state_metadata() {
        let connection = system_connection_from_lsof_line(
            "Safari 123 bq 8u IPv4 0x1 0t0 TCP 192.168.88.241:53124->1.2.3.4:443 (ESTABLISHED)",
            "unix:1786871205.123456",
            "Safari",
            123,
        )
        .expect("established TCP socket should be recorded");

        assert_eq!(connection.runtime, "system");
        assert_eq!(connection.process, "Safari");
        assert_eq!(connection.pid, Some(123));
        assert_eq!(connection.source, "192.168.88.241:53124");
        assert_eq!(connection.destination, "1.2.3.4:443");
        assert_eq!(connection.host, "1.2.3.4");
        assert_eq!(connection.network, "tcp");
        assert_eq!(connection.state, "ESTABLISHED");
        assert_eq!(connection.outbound, "SYSTEM");
    }

    #[test]
    fn system_lsof_parser_ignores_unconnected_udp_listeners() {
        let connection = system_connection_from_lsof_line(
            "dns 123 bq 3u IPv4 0x1 0t0 UDP 127.0.0.1:5301",
            "unix:1786871205.123456",
            "dns",
            123,
        );
        assert!(connection.is_none());
    }

    #[test]
    fn system_lsof_parser_ignores_non_established_tcp() {
        let connection = system_connection_from_lsof_line(
            "Safari 123 bq 8u IPv4 0x1 0t0 TCP 192.168.88.241:53124->1.2.3.4:443 (CLOSE_WAIT)",
            "unix:1786871205.123456",
            "Safari",
            123,
        );
        assert!(connection.is_none());
    }

    #[test]
    fn system_lsof_parser_keeps_connected_udp_and_ipv6_endpoints() {
        let connection = system_connection_from_lsof_line(
            "Safari 123 bq 8u IPv6 0x1 0t0 UDP [fe80::20]:53000->[2001:db8::53]:53",
            "unix:1786871205.123456",
            "Safari",
            123,
        )
        .expect("connected UDP socket should be recorded");
        assert_eq!(connection.network, "udp");
        assert_eq!(connection.source, "[fe80::20]:53000");
        assert_eq!(connection.destination, "[2001:db8::53]:53");
        assert_eq!(connection.host, "2001:db8::53");
    }

    #[test]
    fn system_observer_excludes_owned_listener_destinations() {
        let endpoints = vec![ManagedSystemEndpoint {
            host: "0.0.0.0".into(),
            port: 2080,
            wildcard_host: true,
            family: ManagedAddressFamily::V4,
        }];
        let local_addresses = HashSet::from(["127.0.0.1".into(), "::1".into()]);
        assert!(is_managed_local_destination(
            "127.0.0.1:2080",
            &endpoints,
            &local_addresses
        ));
        assert!(!is_managed_local_destination(
            "[::1]:2080",
            &endpoints,
            &local_addresses
        ));
        assert!(!is_managed_local_destination(
            "1.2.3.4:2080",
            &endpoints,
            &local_addresses
        ));
        assert!(!is_managed_local_destination(
            "127.0.0.1:443",
            &endpoints,
            &local_addresses
        ));

        let ipv6_endpoints = vec![ManagedSystemEndpoint {
            host: "::".into(),
            port: 2080,
            wildcard_host: true,
            family: ManagedAddressFamily::V6,
        }];
        assert!(is_managed_local_destination(
            "[::1]:2080",
            &ipv6_endpoints,
            &local_addresses
        ));
    }

    #[test]
    fn system_observer_excludes_wildcard_listener_on_local_lan_address() {
        let endpoints = vec![ManagedSystemEndpoint {
            host: "0.0.0.0".into(),
            port: 2080,
            wildcard_host: true,
            family: ManagedAddressFamily::V4,
        }];
        let local_addresses = HashSet::from(["192.168.1.20".into(), "fe80::1".into()]);
        assert!(is_managed_local_destination(
            "192.168.1.20:2080",
            &endpoints,
            &local_addresses
        ));
        assert!(!is_managed_local_destination(
            "[fe80::1]:2080",
            &endpoints,
            &local_addresses
        ));
        assert!(!is_managed_local_destination(
            "192.168.1.21:2080",
            &endpoints,
            &local_addresses
        ));
    }

    #[test]
    fn system_observer_machine_lsof_parser_keeps_connected_socket_metadata() {
        let endpoints = Vec::new();
        let local_addresses = HashSet::new();
        let connections = parse_lsof_machine_output(
            "p123\ncSafari\nf8u\nn192.168.1.20:53124->1.2.3.4:443\nTST=ESTABLISHED\n",
            "tcp",
            "unix:1786871205.123456",
            &endpoints,
            &local_addresses,
        );
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].process, "Safari");
        assert_eq!(connections[0].pid, Some(123));
        assert_eq!(connections[0].network, "tcp");
        assert_eq!(
            connections[0]
                .system_socket_key
                .as_deref()
                .unwrap()
                .starts_with("system-socket:"),
            true
        );
    }

    #[test]
    fn system_connection_tuple_reappearance_gets_new_instance_id() {
        let mut identities = SystemConnectionIdentityState::default();
        let connection = system_connection_from_socket(
            "unix:1786871205.123456",
            "Safari",
            123,
            "udp",
            "192.168.1.20:53000->1.1.1.1:53",
            "CONNECTED",
        )
        .unwrap();
        let first = assign_system_connection_instances(
            SystemConnectionSample {
                connections: vec![connection.clone()],
                valid: true,
                error: None,
            },
            &mut identities,
        )
        .connections[0]
            .id
            .clone();
        let _ = assign_system_connection_instances(
            SystemConnectionSample {
                connections: Vec::new(),
                valid: true,
                error: None,
            },
            &mut identities,
        );
        let second = assign_system_connection_instances(
            SystemConnectionSample {
                connections: vec![connection],
                valid: true,
                error: None,
            },
            &mut identities,
        )
        .connections[0]
            .id
            .clone();
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_system_snapshot_does_not_clear_active_identity() {
        let mut identities = SystemConnectionIdentityState::default();
        let connection = system_connection_from_socket(
            "unix:1786871205.123456",
            "Safari",
            123,
            "tcp",
            "192.168.1.20:53000->1.1.1.1:443",
            "ESTABLISHED",
        )
        .unwrap();
        let first = assign_system_connection_instances(
            SystemConnectionSample {
                connections: vec![connection.clone()],
                valid: true,
                error: None,
            },
            &mut identities,
        )
        .connections[0]
            .id
            .clone();
        let invalid = assign_system_connection_instances(
            SystemConnectionSample {
                connections: Vec::new(),
                valid: false,
                error: Some("permission denied".into()),
            },
            &mut identities,
        );
        assert!(!invalid.valid);
        let second = assign_system_connection_instances(
            SystemConnectionSample {
                connections: vec![connection],
                valid: true,
                error: None,
            },
            &mut identities,
        )
        .connections[0]
            .id
            .clone();
        assert_eq!(first, second);
    }

    #[test]
    fn managed_proxy_processes_are_not_duplicated_by_system_observer() {
        assert!(is_managed_network_process("sing-box"));
        assert!(is_managed_network_process("mitmdump"));
        assert!(!is_managed_network_process("Safari"));
    }

    #[test]
    fn gateway_transition_lock_recovers_after_worker_panic() {
        let state = Arc::new(RuntimeState::default());
        let worker_state = Arc::clone(&state);
        let _ = thread::spawn(move || {
            let _guard = worker_state.gateway_transition.lock().unwrap();
            panic!("simulated startup transaction panic");
        })
        .join();

        let _guard = lock_gateway_transition(&state);
    }

    #[test]
    fn sing_box_probe_uses_loopback_for_wildcard_listeners() {
        assert_eq!(sing_box_probe_endpoint("0.0.0.0", 2080), "127.0.0.1:2080");
        assert_eq!(sing_box_probe_endpoint("::", 2080), "[::1]:2080");
        assert_eq!(sing_box_probe_endpoint("127.0.0.1", 2080), "127.0.0.1:2080");
    }

    #[test]
    fn sing_box_startup_reports_an_occupied_listener() {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("test listener should bind");
        let endpoint = listener
            .local_addr()
            .expect("test listener should have an address")
            .to_string();
        let port = listener
            .local_addr()
            .expect("test listener should have an address")
            .port();
        assert!(ensure_sing_box_listener_available("127.0.0.1", port).is_err());
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 17"])
            .spawn()
            .expect("test child should spawn");

        let _ = child.wait();
        let never_cancelled = || false;
        let error = wait_for_sing_box(&mut child, &endpoint, &never_cancelled)
            .expect_err("child should fail");
        assert!(error.contains("端口已被其他进程占用"));
    }

    #[test]
    fn default_settings_render_a_local_mixed_config() {
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config(&RuntimeSettings::default(), &ProxyConfig::default())
                .expect("default settings should render"),
        )
        .expect("rendered config should be valid JSON");

        assert_eq!(config["inbounds"][0]["type"], "mixed");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["listen_port"], 2080);
        assert_eq!(config["dns"]["servers"][0]["type"], "local");
        assert_eq!(config["route"]["final"], "Final");
    }

    #[test]
    fn gateway_guest_settings_render_tun_without_dhcp_mode() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.1".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            gateway_clients: "192.168.88.20,aa:bb:cc:dd:ee:ff".into(),
            ..RuntimeSettings::default()
        };
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config_for(&settings, &ProxyConfig::default(), true)
                .expect("gateway settings should render"),
        )
        .expect("rendered gateway config should be valid JSON");

        assert_eq!(config["inbounds"][0]["type"], "tun");
        assert_eq!(config["inbounds"][0]["tag"], "tun-in");
        assert_eq!(config["inbounds"][0]["interface_name"], "tun0");
        assert_eq!(config["inbounds"][1]["type"], "mixed");
        assert_eq!(config["route"]["auto_detect_interface"], true);
    }

    #[test]
    fn linux_guest_settings_render_a_real_auto_routed_tun() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.1".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            gateway_clients: "192.168.88.20,aa:bb:cc:dd:ee:ff".into(),
            ..RuntimeSettings::default()
        };
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config_document(
                &settings,
                &ProxyConfig::default(),
                &ModuleRuntimePlan::default(),
                true,
            )
            .expect("Linux guest settings should render"),
        )
        .expect("rendered Linux guest config should be valid JSON");

        assert_eq!(config["inbounds"][0]["interface_name"], "tun0");
        assert_eq!(config["inbounds"][0]["auto_route"], true);
        assert_eq!(config["inbounds"][0]["strict_route"], true);
        assert_eq!(config["inbounds"][0]["auto_redirect"], true);
        assert_eq!(
            config["inbounds"][0]["route_address"],
            serde_json::json!(["0.0.0.0/1", "128.0.0.0/1"])
        );
        assert_eq!(config["inbounds"][0]["iproute2_table_index"], 2022);
        assert_eq!(config["inbounds"][0]["iproute2_rule_index"], 9000);
        assert_eq!(config["inbounds"][0]["auto_redirect_input_mark"], "0x2023");
        assert_eq!(config["inbounds"][0]["auto_redirect_output_mark"], "0x2024");
        assert_eq!(config["inbounds"][0]["auto_redirect_reset_mark"], "0x2025");
        let excluded_routes = config["inbounds"][0]["route_exclude_address"]
            .as_array()
            .unwrap();
        assert!(excluded_routes
            .iter()
            .any(|value| value.as_str() == Some("192.168.88.0/24")));
        assert!(excluded_routes
            .iter()
            .any(|value| value.as_str() == Some("192.168.250.0/24")));
        assert!(excluded_routes
            .iter()
            .any(|value| value.as_str() == Some("223.86.225.0/24")));
    }

    #[test]
    fn macos_gateway_settings_do_not_create_a_host_tun() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.1".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            gateway_clients: "192.168.88.20,aa:bb:cc:dd:ee:ff".into(),
            ..RuntimeSettings::default()
        };
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config_document(
                &settings,
                &ProxyConfig::default(),
                &ModuleRuntimePlan::default(),
                false,
            )
            .expect("macOS Gateway settings should render"),
        )
        .expect("rendered macOS Gateway config should be valid JSON");

        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(config["inbounds"][0]["tag"], "mixed-in");
        assert!(config["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|rule| rule["inbound"].as_array().is_none()));
    }

    #[test]
    fn gateway_fakeip_settings_render_dns_mapping_and_resolve_rule() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            dns_mode: "fakeip".into(),
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.1".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            gateway_clients: "192.168.88.20,aa:bb:cc:dd:ee:ff".into(),
            ..RuntimeSettings::default()
        };
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config_for(&settings, &ProxyConfig::default(), true)
                .expect("FakeIP settings should render"),
        )
        .expect("rendered FakeIP config should be valid JSON");

        assert_eq!(config["dns"]["servers"][0]["type"], "fakeip");
        assert_eq!(config["dns"]["servers"][0]["inet4_range"], "198.18.0.0/15");
        assert_eq!(config["dns"]["servers"][0]["inet6_range"], "fc00::/18");
        assert_eq!(config["dns"]["rules"][2]["server"], "fakeip");
        assert_eq!(config["route"]["rules"][0]["action"], "resolve");
        assert_eq!(config["route"]["rules"][0]["inbound"][0], "tun-in");
        assert_eq!(config["route"]["rules"][2]["action"], "hijack-dns");
    }

    #[test]
    fn fakeip_is_restricted_to_gateway_mode() {
        let settings = RuntimeSettings {
            dns_mode: "fakeip".into(),
            ..RuntimeSettings::default()
        };
        assert_eq!(
            validate_settings(&settings),
            Err("FakeIP 只允许在网关模式使用".into())
        );
    }

    #[test]
    fn gateway_network_settings_require_an_addressable_vm_gateway() {
        let valid = RuntimeSettings {
            mode: "gateway".into(),
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.1".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            ..RuntimeSettings::default()
        };
        assert!(validate_settings(&valid).is_ok());

        let allowlist_without_clients = RuntimeSettings {
            gateway_client_policy: "allowlist".into(),
            ..valid.clone()
        };
        assert_eq!(
            validate_settings(&allowlist_without_clients),
            Err(
                "Gateway 客户端 allowlist 尚未接入 Linux guest，当前只能使用 client-policy = all"
                    .into()
            )
        );

        let outside_subnet = RuntimeSettings {
            gateway_ip: "192.168.89.1".into(),
            ..valid.clone()
        };
        assert_eq!(
            validate_settings(&outside_subnet),
            Err("局域网网关 IP 不在物理局域网网段内".into())
        );
    }

    #[test]
    fn vfkit_gateway_defaults_use_a_small_guest_and_isolated_network() {
        let settings = RuntimeSettings::default();
        assert_eq!(settings.gateway_guest_cpus, 1);
        assert_eq!(settings.gateway_guest_memory_mib, 512);
        assert_eq!(settings.gateway_host_ip, "192.168.250.1");
        assert_eq!(settings.gateway_guest_host_ip, "192.168.250.2");
        assert_eq!(
            settings.gateway_guest_lan_selector,
            vfkit::DEFAULT_GATEWAY_GUEST_LAN_SELECTOR
        );
        assert_eq!(
            settings.gateway_guest_host_selector,
            vfkit::DEFAULT_GATEWAY_GUEST_HOST_SELECTOR
        );
        assert!(validate_vfkit_settings(&settings).is_ok());

        let gateway = RuntimeSettings {
            mode: "gateway".into(),
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.2".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            ..settings
        };
        assert!(validate_settings(&gateway).is_ok());
    }

    #[test]
    fn empty_gateway_selectors_are_migrated_to_guest_interface_defaults() {
        let parsed = parse_songsterx_config(
            "[General]\n\
gateway-guest-lan-selector = \"\"\n\
gateway-guest-host-selector = \"\"\n",
        )
        .expect("empty selectors should use defaults");
        assert_eq!(
            parsed.settings.gateway_guest_lan_selector,
            vfkit::DEFAULT_GATEWAY_GUEST_LAN_SELECTOR
        );
        assert_eq!(
            parsed.settings.gateway_guest_host_selector,
            vfkit::DEFAULT_GATEWAY_GUEST_HOST_SELECTOR
        );
    }

    #[test]
    fn gateway_module_proxy_uses_host_only_address() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            gateway_host_ip: "192.168.250.1".into(),
            ..RuntimeSettings::default()
        };
        assert_eq!(module_proxy_endpoint(&settings, 8080), "192.168.250.1:8080");
        assert_eq!(module_proxy_host(&RuntimeSettings::default()), "127.0.0.1");
    }

    #[test]
    fn module_proxy_plan_port_overrides_default_without_changing_host() {
        let settings = RuntimeSettings::default();
        let plan = ModuleRuntimePlan {
            proxy_port: Some(18080),
            ..ModuleRuntimePlan::default()
        };
        assert_eq!(module_proxy_port(&plan), 18080);
        assert_eq!(
            module_proxy_endpoint(&settings, module_proxy_port(&plan)),
            "127.0.0.1:18080"
        );
    }

    #[test]
    fn gateway_module_proxy_port_probe_does_not_require_vmnet_address_yet() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            gateway_host_ip: "192.168.250.1".into(),
            ..RuntimeSettings::default()
        };
        assert_eq!(module_proxy_probe_host(&settings), "0.0.0.0");
        assert_eq!(
            module_proxy_probe_host(&RuntimeSettings::default()),
            "127.0.0.1"
        );
    }

    #[test]
    fn module_proxy_port_probe_detects_existing_listener_on_configured_host() {
        let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
        let port = occupied
            .local_addr()
            .expect("read test listener address")
            .port();
        let error = bind_module_proxy_listener(&RuntimeSettings::default(), port)
            .expect_err("occupied configured host port must be rejected");
        assert!(error.contains("127.0.0.1"));
        assert!(error.contains(&port.to_string()));
    }

    #[test]
    fn gateway_module_proxy_port_probe_falls_back_when_host_only_address_is_not_ready() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            gateway_host_ip: "203.0.113.1".into(),
            ..RuntimeSettings::default()
        };
        let listener = bind_module_proxy_listener(&settings, 0)
            .expect("wildcard probe should work before vmnet host-only address exists");
        assert_eq!(
            listener.local_addr().expect("read wildcard address").ip(),
            "0.0.0.0".parse::<IpAddr>().expect("parse wildcard address")
        );
    }

    #[test]
    fn gateway_fakeip_dns_is_fixed_to_surge_address() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            dns_mode: "fakeip".into(),
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.1".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            gateway_clients: "192.168.88.20,aa:bb:cc:dd:ee:ff".into(),
            gateway_dns_ip: "223.5.5.5".into(),
            ..RuntimeSettings::default()
        };
        assert_eq!(
            validate_settings(&settings),
            Err("VM Gateway 的 FakeIP DNS 固定为 198.18.0.2".into())
        );
    }

    #[test]
    fn custom_dns_settings_render_udp_dns() {
        let settings = RuntimeSettings {
            dns_mode: "custom".into(),
            dns_server: "223.5.5.5".into(),
            port: 3080,
            ..RuntimeSettings::default()
        };
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config(&settings, &ProxyConfig::default())
                .expect("custom DNS settings should render"),
        )
        .expect("rendered config should be valid JSON");

        assert_eq!(config["dns"]["servers"][0]["type"], "udp");
        assert_eq!(config["dns"]["servers"][0]["server"], "223.5.5.5");
        assert_eq!(config["inbounds"][0]["listen_port"], 3080);
    }

    #[test]
    fn proxy_nodes_and_rules_render() {
        let proxy = ProxyConfig {
            nodes: vec![ProxyNode {
                tag: "hk".into(),
                kind: "trojan".into(),
                server: "1.2.3.4".into(),
                server_port: 443,
                password: "secret".into(),
                sni: "example.com".into(),
                network: "ws".into(),
                ws_path: "/path".into(),
                ws_host: "example.com".into(),
                insecure: true,
                username: String::new(),
                ..Default::default()
            }],
            groups: vec![PolicyGroup {
                name: "Final".into(),
                kind: "selector".into(),
                members: vec!["hk".into(), "direct".into()],
                default: "hk".into(),
                ..Default::default()
            }],
            rules: vec![ProxyRule {
                id: "r1".into(),
                name: "OpenAI".into(),
                action: "route".into(),
                outbound: "Final".into(),
                enabled: true,
                condition: Some(RuleCondition {
                    id: "r1-condition".into(),
                    kind: "field".into(),
                    field: "domain_suffix".into(),
                    value: "openai.com".into(),
                    mode: String::new(),
                    invert: false,
                    rules: vec![],
                }),
                legacy_kind: String::new(),
                legacy_value: String::new(),
            }],
            rule_sets: vec![],
        };
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config(&RuntimeSettings::default(), &proxy).expect("should render"),
        )
        .expect("valid JSON");

        assert_eq!(config["outbounds"][1]["type"], "trojan");
        assert_eq!(config["outbounds"][1]["tag"], "hk");
        assert_eq!(config["outbounds"][2]["type"], "selector");
        assert_eq!(
            config["route"]["rules"][0]["domain_suffix"][0],
            "openai.com"
        );
        assert_eq!(config["route"]["final"], "Final");
    }

    #[test]
    fn expanded_outbound_types_render() {
        let proxy: ProxyConfig = serde_json::from_value(serde_json::json!({
            "nodes": [
                {
                    "tag": "wg",
                    "type": "wireguard",
                    "server": "198.51.100.10",
                    "serverPort": 51820,
                    "privateKey": "private-key",
                    "peerPublicKey": "peer-key",
                    "localAddress": "10.0.0.2/32"
                },
                {
                    "tag": "hy2",
                    "type": "hysteria2",
                    "server": "hy2.example.com",
                    "serverPort": 443,
                    "password": "secret",
                    "sni": "hy2.example.com",
                    "obfs": "salamander",
                    "obfsPassword": "obfs-secret"
                },
                {
                    "tag": "hy1",
                    "type": "hysteria",
                    "server": "hy1.example.com",
                    "serverPort": 443,
                    "upMbps": 100,
                    "downMbps": 300,
                    "password": "auth-secret",
                    "obfsPassword": "obfs-secret"
                },
                {
                    "tag": "tor",
                    "type": "tor",
                    "server": "",
                    "serverPort": 0,
                    "executablePath": "/usr/local/bin/tor"
                }
            ],
            "groups": [],
            "rules": []
        }))
        .expect("expanded outbound config should deserialize");
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config(&RuntimeSettings::default(), &proxy)
                .expect("expanded outbounds should render"),
        )
        .expect("valid JSON");

        assert_eq!(config["outbounds"][1]["type"], "wireguard");
        assert_eq!(config["outbounds"][1]["local_address"][0], "10.0.0.2/32");
        assert_eq!(config["outbounds"][2]["obfs"]["type"], "salamander");
        assert_eq!(config["outbounds"][3]["auth_str"], "auth-secret");
        assert_eq!(config["outbounds"][3]["obfs"], "obfs-secret");
        assert_eq!(
            config["outbounds"][4]["executable_path"],
            "/usr/local/bin/tor"
        );
    }

    #[test]
    fn extended_outbound_fields_render() {
        let proxy: ProxyConfig = serde_json::from_value(serde_json::json!({
            "nodes": [
                {
                    "tag": "vmess-http",
                    "type": "vmess",
                    "server": "example.com",
                    "serverPort": 443,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                    "network": "http",
                    "wsPath": "/api",
                    "wsHost": "cdn.example.com",
                    "transportMethod": "GET",
                    "tlsAlpn": "h2, http/1.1",
                    "tlsMinVersion": "1.2",
                    "tlsRealityPublicKey": "public-key",
                    "tlsRealityShortId": "0123456789abcdef",
                    "detour": "direct",
                    "multiplexEnabled": true,
                    "multiplexProtocol": "h2mux",
                    "multiplexMaxConnections": 4
                },
                {
                    "tag": "ss-plugin",
                    "type": "shadowsocks",
                    "server": "ss.example.com",
                    "serverPort": 443,
                    "method": "aes-256-gcm",
                    "password": "secret",
                    "plugin": "obfs-local",
                    "pluginOptions": "obfs=http"
                },
                {
                    "tag": "hy2-hop",
                    "type": "hysteria2",
                    "server": "hy2.example.com",
                    "serverPort": 443,
                    "serverPorts": "2000:3000",
                    "hopInterval": "30s",
                    "hopIntervalMax": "60s",
                    "network": "udp",
                    "password": "secret"
                },
                {
                    "tag": "anytls-timeout",
                    "type": "anytls",
                    "server": "anytls.example.com",
                    "serverPort": 443,
                    "password": "secret",
                    "idleSessionCheckInterval": "30s",
                    "idleSessionExpiration": "2m"
                }
            ],
            "groups": [],
            "rules": []
        }))
        .expect("extended fields should deserialize");
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config(&RuntimeSettings::default(), &proxy)
                .expect("extended fields should render"),
        )
        .expect("valid JSON");

        let vmess = &config["outbounds"][1];
        assert_eq!(vmess["transport"]["type"], "http");
        assert_eq!(vmess["transport"]["method"], "GET");
        assert_eq!(vmess["tls"]["alpn"][0], "h2");
        assert_eq!(vmess["tls"]["reality"]["short_id"], "0123456789abcdef");
        assert_eq!(vmess["multiplex"]["max_connections"], 4);
        assert_eq!(config["outbounds"][2]["plugin_opts"], "obfs=http");
        assert_eq!(config["outbounds"][3]["server_ports"][0], "2000:3000");
        assert_eq!(config["outbounds"][3]["hop_interval_max"], "60s");
        assert_eq!(config["outbounds"][4]["idle_session_timeout"], "2m");
    }

    #[test]
    fn logical_rules_and_rule_sets_render() {
        let proxy = ProxyConfig {
            nodes: vec![],
            groups: vec![PolicyGroup {
                name: "Final".into(),
                kind: "selector".into(),
                members: vec!["direct".into()],
                default: "direct".into(),
                ..Default::default()
            }],
            rules: vec![ProxyRule {
                id: "logical-1".into(),
                name: "逻辑规则".into(),
                action: "route".into(),
                outbound: "Final".into(),
                enabled: true,
                condition: Some(RuleCondition {
                    id: "logical-1-condition".into(),
                    kind: "logical".into(),
                    field: String::new(),
                    value: String::new(),
                    mode: "and".into(),
                    invert: false,
                    rules: vec![
                        RuleCondition {
                            id: "logical-1-condition-1".into(),
                            kind: "field".into(),
                            field: "rule_set".into(),
                            value: "openai".into(),
                            mode: String::new(),
                            invert: false,
                            rules: vec![],
                        },
                        RuleCondition {
                            id: "logical-1-condition-2".into(),
                            kind: "field".into(),
                            field: "port".into(),
                            value: "443".into(),
                            mode: String::new(),
                            invert: false,
                            rules: vec![],
                        },
                    ],
                }),
                legacy_kind: String::new(),
                legacy_value: String::new(),
            }],
            rule_sets: vec![RuleSetConfig {
                kind: "remote".into(),
                tag: "openai".into(),
                format: "binary".into(),
                path: String::new(),
                url: "https://example.com/openai.srs".into(),
                update_interval: "1d".into(),
            }],
        };
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config(&RuntimeSettings::default(), &proxy)
                .expect("logical rule should render"),
        )
        .expect("valid JSON");

        assert_eq!(config["route"]["rules"][0]["type"], "logical");
        assert_eq!(config["route"]["rules"][0]["mode"], "and");
        assert_eq!(config["route"]["rules"][0]["rules"][1]["port"][0], 443);
        assert_eq!(config["route"]["rule_set"][0]["tag"], "openai");
    }

    #[test]
    fn disabled_rules_are_not_compiled_into_runtime_config() {
        let proxy: ProxyConfig = serde_json::from_value(serde_json::json!({
            "nodes": [],
            "groups": [],
            "rules": [
                {
                    "id": "disabled",
                    "name": "停用规则",
                    "enabled": false,
                    "action": "reject",
                    "condition": {"type": "field", "field": "domain_suffix", "value": "disabled.example"}
                },
                {
                    "id": "enabled",
                    "name": "启用规则",
                    "enabled": true,
                    "action": "reject",
                    "condition": {"type": "field", "field": "domain_suffix", "value": "enabled.example"}
                }
            ]
        }))
        .expect("proxy config should deserialize");
        let config: serde_json::Value = serde_json::from_str(
            &render_runtime_config(&RuntimeSettings::default(), &proxy)
                .expect("config should render"),
        )
        .expect("valid JSON");

        let rules = config["route"]["rules"]
            .as_array()
            .expect("route rules should be an array");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["domain_suffix"][0], "enabled.example");
    }

    #[test]
    fn legacy_flat_rules_are_migrated_to_condition_nodes() {
        let mut config: ProxyConfig = serde_json::from_value(serde_json::json!({
            "nodes": [],
            "groups": [],
            "rules": [{
                "id": "legacy-1",
                "type": "domain_suffix",
                "value": "example.com",
                "outbound": "direct",
                "enabled": true
            }]
        }))
        .expect("legacy config should deserialize");
        let normalized = normalize_proxy_config(&mut config);
        let condition = normalized.rules[0]
            .condition
            .as_ref()
            .expect("legacy rule should have a condition");
        assert_eq!(condition.field, "domain_suffix");
        assert_eq!(condition.value, "example.com");
        assert_eq!(condition.id, "legacy-1-condition");
        assert!(normalized.rules[0].legacy_kind.is_empty());
        assert!(normalized.rules[0].legacy_value.is_empty());
    }

    #[test]
    fn invalid_settings_are_rejected() {
        let settings = RuntimeSettings {
            port: 0,
            ..RuntimeSettings::default()
        };
        assert!(validate_settings(&settings).is_err());
    }

    #[test]
    fn module_source_extracts_metadata_sections_and_assets() {
        let source = r#"#!name = Demo Module
#!desc = first line\nsecond line
#!version = 1.2.3

[URL Rewrite]
^https://example.com - reject

[Script]
demo = type=http-response,script-path=https://example.com/demo.js

[MITM]
hostname = %APPEND% example.com, api.example.com
"#;
        let (name, description, version, sections, scripts, hosts, rules, script_count) =
            parse_module_source(source);
        assert_eq!(name, "Demo Module");
        assert_eq!(description, "first line\nsecond line");
        assert_eq!(version, "1.2.3");
        assert_eq!(sections, vec!["URL Rewrite", "Script", "MITM"]);
        assert_eq!(scripts, vec!["https://example.com/demo.js"]);
        assert_eq!(hosts, vec!["example.com", "api.example.com"]);
        assert_eq!(rules, 1);
        assert_eq!(script_count, 1);
    }

    #[test]
    fn module_argument_descriptions_parse_escaped_blocks() {
        let source = r#"#!arguments-desc = Splash: [开屏] 去除广告\n是否启用此处修改\n\nFeed.AD: [推荐] 去除广告\n是否启用此处修改\n\nLogLevel: [调试] 日志等级\n    ├ OFF: 关闭\n    └ ALL: 全部\n选择脚本日志的输出等级。"#;
        let descriptions = parse_module_argument_descriptions(source);
        assert_eq!(descriptions["Splash"], "[开屏] 去除广告\n是否启用此处修改");
        assert_eq!(descriptions["Feed.AD"], "[推荐] 去除广告\n是否启用此处修改");
        assert_eq!(
            descriptions["LogLevel"],
            "[调试] 日志等级\n    ├ OFF: 关闭\n    └ ALL: 全部\n选择脚本日志的输出等级。"
        );
    }

    #[test]
    fn module_runtime_plan_adapts_static_http_operations_without_executing_scripts() {
        let source = r#"
[Rule]
DOMAIN,example.com,REJECT
URL-REGEX,^https://example.com/ad,REJECT

[URL Rewrite]
^https://example.com/old - reject

[Map Local]
^https://example.com/blank data-type=text data="{}" header="application/json"

[Header Rewrite]
http-request ^https://example.com/ header-del if-none-match

[Body Rewrite]
http-response-jq ^https://example.com/ 'del(.ad)'

[Script]
demo = type=http-response,script-path=https://example.com/demo.js

[MITM]
hostname = %APPEND% example.com, *.example.net
"#;
        let entry = ModuleManifestEntry {
            id: "demo".into(),
            ..Default::default()
        };
        let mut plan = ModuleRuntimePlan {
            version: 1,
            ..Default::default()
        };
        parse_module_runtime_source(&entry, source, Path::new("/tmp"), &[], &mut plan);
        assert_eq!(plan.static_rules.len(), 2);
        assert_eq!(plan.static_rules[0]["kind"], "domain");
        assert_eq!(plan.static_rules[1]["kind"], "url_regex");
        assert_eq!(plan.url_rewrites[0]["action"], "reject");
        assert_eq!(plan.map_locals[0]["inlineData"], "{}");
        assert_eq!(plan.header_rewrites[0]["operation"], "header-del");
        assert_eq!(plan.mitm_hostnames, vec!["example.com", "*.example.net"]);
        assert_eq!(plan.disabled_scripts, 0);
        assert!(!plan.disabled_sections.contains(&"Body Rewrite".into()));
        assert_eq!(module_route_rules(&plan).len(), 1);
        assert_eq!(module_mitm_route_rules(&plan).len(), 2);
        assert_eq!(module_mitm_route_rules(&plan)[0]["outbound"], "module-mitm");
        assert_eq!(module_mitm_route_rules(&plan)[0]["network"][0], "tcp");
    }

    #[test]
    fn module_manifest_parser_reads_all_module_fields() {
        let path =
            std::env::temp_dir().join(format!("songsterx-modules-{}.yaml", std::process::id()));
        fs::write(&path, "schema: test\nmodules:\n  - id: demo\n    source: https://example.com/demo.sgmodule\n    local_file: modules/demo.sgmodule\n    sha256: abc\n    sections: [Rule, Script]\n").expect("write manifest fixture");
        let entries = parse_module_manifest(&path).expect("parse manifest fixture");
        let _ = fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "demo");
        assert_eq!(entries[0].local_file, "modules/demo.sgmodule");
        assert_eq!(entries[0].sections, vec!["Rule", "Script"]);
    }

    #[test]
    fn module_arguments_parse_defaults_without_matching_desc_metadata() {
        let source =
            "#!arguments=longitude:113.9,latitude:22.5,label:\"a,b\"\n#!arguments-desc=ignored\n";
        assert_eq!(
            parse_module_arguments(source),
            vec![
                ("longitude".into(), "113.9".into()),
                ("latitude".into(), "22.5".into()),
                ("label".into(), "a,b".into())
            ]
        );
    }

    #[test]
    fn imported_module_download_resolves_remote_dependencies() {
        let source = "[Script]\njs = type=http-response,script-path=https://example.com/assets/main.js,requires-body=1\n[Rule]\nRULE-SET,https://example.com/rules/list.txt,DIRECT\n[Map Local]\n^https://example.com/data data=payload.json\n";
        let references = module_asset_references(source);
        assert_eq!(references.len(), 3);
        assert_eq!(
            references[0],
            ("script".into(), "https://example.com/assets/main.js".into())
        );
        assert_eq!(
            resolve_module_reference(
                "https://example.com/modules/demo.sgmodule",
                "assets/main.js"
            ),
            Some("https://example.com/modules/assets/main.js".into())
        );
        assert_eq!(
            resolve_module_reference(
                "https://example.com/modules/demo.sgmodule",
                "/rules/list.txt"
            ),
            Some("https://example.com/rules/list.txt".into())
        );
    }

    #[test]
    fn songsterx_config_uses_surge_style_sections() {
        let config =
            render_songsterx_config(&RuntimeSettings::default(), &ProxyConfig::default(), &[]);
        assert!(config.contains("[General]"));
        assert!(config.contains("[Proxy]"));
        assert!(config.contains("[Proxy Group]"));
        assert!(config.contains("[Rule Set]"));
        assert!(config.contains("[Rule]"));
        assert!(config.contains("[Module]"));
        assert!(config.contains("listen = 127.0.0.1"));
    }

    #[test]
    fn gateway_settings_round_trip_inside_songsterx_conf() {
        let settings = RuntimeSettings {
            mode: "gateway".into(),
            gateway_policy_mode: "separate".into(),
            vfkit_path: "/opt/homebrew/bin/vfkit".into(),
            gateway_guest_kernel_path: "/tmp/Image".into(),
            gateway_guest_initrd_path: "/tmp/gateway.initrd".into(),
            gateway_guest_host_ip: "192.168.250.2".into(),
            gateway_host_ip: "192.168.250.1".into(),
            gateway_host_cidr: "192.168.250.0/24".into(),
            gateway_guest_agent_port: 38291,
            gateway_lan_interface: "en0".into(),
            gateway_ip: "192.168.88.2".into(),
            gateway_cidr: "192.168.88.0/24".into(),
            gateway_dns_ip: "198.18.0.2".into(),
            gateway_clients: "192.168.88.20,aa:bb:cc:dd:ee:ff\n192.168.88.21,11:22:33:44:55:66"
                .into(),
            dns_mode: "fakeip".into(),
            ..RuntimeSettings::default()
        };
        let rendered = render_songsterx_config(&settings, &ProxyConfig::default(), &[]);
        assert!(rendered.contains("[Gateway]"));
        assert!(rendered.contains("interface = en0"));
        assert!(rendered.contains("192.168.88.20,aa:bb:cc:dd:ee:ff"));
        assert!(!rendered.contains("gatewaykit-path"));
        assert!(!rendered.contains("gateway-backend"));
        let parsed = parse_songsterx_config(&rendered).expect("gateway conf should parse");
        assert_eq!(parsed.settings.mode, "gateway");
        assert_eq!(parsed.settings.vfkit_path, "/opt/homebrew/bin/vfkit");
        assert_eq!(parsed.settings.gateway_guest_agent_port, 38291);
        assert_eq!(parsed.settings.gateway_host_cidr, "192.168.250.0/24");
        assert_eq!(parsed.settings.gateway_lan_interface, "en0");
        assert_eq!(parsed.settings.gateway_clients, settings.gateway_clients);
        assert_eq!(parsed.settings.gateway_policy_mode, "separate");
    }

    #[test]
    fn gateway_policy_mode_defaults_to_shared_and_round_trips() {
        let settings = RuntimeSettings::default();
        assert_eq!(settings.gateway_policy_mode, "shared");
        let rendered = render_songsterx_config(&settings, &ProxyConfig::default(), &[]);
        assert!(rendered.contains("policy-mode = shared"));
        let parsed = parse_songsterx_config(&rendered).expect("shared policy mode should parse");
        assert_eq!(parsed.settings.gateway_policy_mode, "shared");
    }

    #[test]
    fn gateway_policy_mode_rejects_unknown_values() {
        let mut settings = RuntimeSettings::default();
        settings.gateway_policy_mode = "mirror".into();
        let error = validate_settings(&settings).expect_err("unknown policy mode should fail");
        assert!(error.contains("shared 或 separate"));
    }

    #[test]
    fn obsolete_gateway_profile_field_is_ignored_and_not_rendered() {
        let parsed = parse_songsterx_config(
            "[General]\nmode = mixed-direct\ngateway-profile = /old/profile.json\n[Gateway]\nenabled = false\ngateway-profile = /old/profile.json\n",
        )
        .expect("obsolete gateway profile fields should be ignored");
        let rendered = render_songsterx_config(&parsed.settings, &parsed.proxy_config, &[]);
        assert!(!rendered.contains("gateway-profile"));
    }

    #[test]
    fn songsterx_config_round_trips_user_edits_and_nested_rules() {
        let mut proxy_config = ProxyConfig::default();
        proxy_config.nodes = vec![ProxyNode {
            tag: "edge, one".into(),
            kind: "vless".into(),
            server: "example.com".into(),
            server_port: 443,
            uuid: "user=one".into(),
            password: "line1\nline2\t\\windows".into(),
            tls_enabled: false,
            tls_alpn: "h2,http/1.1".into(),
            multiplex_enabled: true,
            multiplex_max_streams: 8,
            extra_json: r#"{"packet_encoding":"xudp","custom":true}"#.into(),
            ..Default::default()
        }];
        proxy_config.groups = vec![PolicyGroup {
            name: "Auto, Select".into(),
            kind: "urltest".into(),
            members: vec!["edge, one".into(), "direct".into()],
            default: "edge, one".into(),
            url: "https://example.com/test?x=1".into(),
            interval: "10m".into(),
            tolerance: 50,
            idle_timeout: "5m".into(),
            interrupt_exist_connections: true,
        }];
        proxy_config.rule_sets = vec![RuleSetConfig {
            kind: "remote".into(),
            tag: "work-rules".into(),
            format: "binary".into(),
            url: "https://example.com/rules.srs".into(),
            update_interval: "1d".into(),
            ..Default::default()
        }];
        proxy_config.rules = vec![
            ProxyRule {
                id: "allow-work".into(),
                name: "Allow work".into(),
                enabled: true,
                action: "route".into(),
                outbound: "Auto, Select".into(),
                condition: Some(RuleCondition {
                    kind: "group".into(),
                    mode: "or".into(),
                    rules: vec![
                        RuleCondition {
                            kind: "field".into(),
                            field: "domain_suffix".into(),
                            value: "corp,internal".into(),
                            ..Default::default()
                        },
                        RuleCondition {
                            kind: "field".into(),
                            field: "process_name".into(),
                            value: "my app".into(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }),
                legacy_kind: String::new(),
                legacy_value: String::new(),
            },
            ProxyRule {
                id: "disabled-rule".into(),
                name: "Disabled".into(),
                enabled: false,
                action: "reject".into(),
                outbound: "direct".into(),
                condition: Some(RuleCondition {
                    kind: "field".into(),
                    field: "domain".into(),
                    value: "blocked.example".into(),
                    ..Default::default()
                }),
                legacy_kind: String::new(),
                legacy_value: String::new(),
            },
        ];
        let rendered = render_songsterx_config(&RuntimeSettings::default(), &proxy_config, &[]);
        let edited = rendered.replace("port = 2080", "port = 3080");
        let parsed = parse_songsterx_config(&edited).expect("parse rendered SongsterX config");
        assert_eq!(parsed.settings.port, 3080);
        assert_eq!(parsed.proxy_config.nodes[0].tag, "edge, one");
        assert_eq!(parsed.proxy_config.nodes[0].uuid, "user=one");
        assert_eq!(
            parsed.proxy_config.nodes[0].password,
            "line1\nline2\t\\windows"
        );
        assert!(!parsed.proxy_config.nodes[0].tls_enabled);
        assert_eq!(parsed.proxy_config.nodes[0].multiplex_max_streams, 8);
        assert!(parsed.proxy_config.nodes[0].extra_json.contains("custom"));
        assert_eq!(
            parsed.proxy_config.groups[0].members,
            vec!["edge, one", "direct"]
        );
        assert_eq!(parsed.proxy_config.groups[0].tolerance, 50);
        assert_eq!(
            parsed.proxy_config.rule_sets[0].url,
            "https://example.com/rules.srs"
        );
        assert_eq!(parsed.proxy_config.rules[0].name, "Allow work");
        assert!(parsed.proxy_config.rules[0].enabled);
        assert_eq!(parsed.proxy_config.rules[1].enabled, false);
        assert_eq!(
            render_rule_condition(
                parsed.proxy_config.rules[0]
                    .condition
                    .as_ref()
                    .expect("condition")
            ),
            "(domain_suffix=\"corp,internal\" || process_name=\"my app\")"
        );
    }

    #[test]
    fn songsterx_config_parses_module_preferences() {
        let config = parse_songsterx_config("[General]\nport = 2080\n[Module]\ndemo, false, modules/demo.sgmodule, Script, arguments-json=\"{\\\"token\\\":\\\"a,b\\\"}\"\n").expect("parse module config");
        assert_eq!(config.modules.len(), 1);
        assert_eq!(config.modules[0].id, "demo");
        assert!(!config.modules[0].enabled);
        assert_eq!(
            config.modules[0].argument_values.get("token"),
            Some(&"a,b".to_string())
        );
    }

    #[test]
    fn checked_in_module_assets_match_pinned_hashes() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let entries = parse_module_manifest(&root.join("config/modules.manifest.yaml"))
            .expect("parse checked-in module manifest");
        let asset_content = fs::read_to_string(root.join("config/module-assets.manifest.json"))
            .expect("read checked-in asset manifest");
        let assets: ModuleAssetManifest =
            serde_json::from_str(&asset_content).expect("parse checked-in asset manifest");
        assert_eq!(entries.len(), 9);
        assert_eq!(assets.assets.len(), 16);
        for entry in entries {
            let module_path = root.join(&entry.local_file);
            assert_eq!(
                sha256_file(&module_path).expect("hash module"),
                entry.sha256,
                "module hash: {}",
                entry.id
            );
            let source = fs::read_to_string(&module_path).expect("read module");
            let (_, _, _, _, script_sources, _, _, _) = parse_module_source(&source);
            for script_source in script_sources {
                let asset = assets
                    .assets
                    .iter()
                    .find(|asset| {
                        asset.module == entry.id
                            && asset.kind == "script"
                            && asset.source == script_source
                    })
                    .expect("script asset exists");
                assert_eq!(
                    sha256_file(&root.join(&asset.local_file)).expect("hash script"),
                    asset.sha256,
                    "asset hash: {}",
                    asset.local_file
                );
            }
        }
    }

    #[test]
    fn checked_in_modules_parse_into_safe_runtime_primitives() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let entries = parse_module_manifest(&root.join("config/modules.manifest.yaml"))
            .expect("parse checked-in module manifest");
        let asset_content = fs::read_to_string(root.join("config/module-assets.manifest.json"))
            .expect("read checked-in asset manifest");
        let assets: ModuleAssetManifest =
            serde_json::from_str(&asset_content).expect("parse checked-in asset manifest");
        let mut plan = ModuleRuntimePlan {
            version: 1,
            ..Default::default()
        };
        for entry in entries {
            let source =
                fs::read_to_string(root.join(&entry.local_file)).expect("read checked-in module");
            parse_module_runtime_source(&entry, &source, &root, &assets.assets, &mut plan);
        }
        assert_eq!(plan.mitm_hostnames.len(), 23);
        assert_eq!(plan.static_rules.len(), 18);
        assert!(plan.url_rewrites.len() >= 1);
        assert!(plan.map_locals.len() >= 10);
        assert!(plan
            .header_rewrites
            .iter()
            .any(|rule| rule["operation"] == "header-del"));
        assert_eq!(plan.disabled_scripts, 0);
        assert!(!plan.disabled_sections.contains(&"Body Rewrite".into()));
    }
}
