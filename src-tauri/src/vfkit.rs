use std::env;
use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::gateway_runtime::{
    AlwaysReadyProbe, GatewayRuntimePlan, LaunchStep, RuntimeRole, StartupProbe,
};
use crate::process_group::ManagedCommandSpec;
use crate::process_group::OwnedRuntimeArtifacts;

pub(crate) const DEFAULT_GATEWAY_HOST_IP: &str = "192.168.250.1";
pub(crate) const DEFAULT_GATEWAY_GUEST_HOST_IP: &str = "192.168.250.2";
pub(crate) const DEFAULT_GATEWAY_HOST_CIDR: &str = "192.168.250.0/24";
pub(crate) const DEFAULT_GATEWAY_GUEST_AGENT_PORT: u16 = 38291;
pub(crate) const DEFAULT_GATEWAY_GUEST_CPUS: u8 = 1;
pub(crate) const DEFAULT_GATEWAY_GUEST_MEMORY_MIB: u32 = 512;
pub(crate) const DEFAULT_GATEWAY_GUEST_LAN_SELECTOR: &str = "if:eth0";
pub(crate) const DEFAULT_GATEWAY_GUEST_HOST_SELECTOR: &str = "if:eth1";
const DARWIN_UNIX_SOCKET_PATH_LIMIT: usize = 104;
const VFKIT_LOCAL_SOCKET_MAX_BASENAME: &str = "vfkit-ffffffff-ffff.sock";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

// Used by the Gateway supervisor once the packet-path gate is enabled.
#[allow(dead_code)]
pub(crate) fn managed_command_spec(spec: &ProcessSpec, role: &str) -> ManagedCommandSpec {
    ManagedCommandSpec::new(role, spec.program.clone()).with_args(spec.args.clone())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VfkitGatewayConfig {
    pub vfkit_path: PathBuf,
    pub vmnet_helper_path: PathBuf,
    pub kernel_path: PathBuf,
    pub initrd_path: PathBuf,
    pub guest_cmdline: String,
    pub cpus: u8,
    pub memory_mib: u32,
    pub bridge_interface: String,
    pub gateway_ip: Ipv4Addr,
    pub gateway_cidr: String,
    pub upstream_gateway: Ipv4Addr,
    pub dns_server: String,
    pub guest_lan_selector: String,
    pub guest_host_selector: String,
    pub host_ip: Ipv4Addr,
    pub guest_host_ip: Ipv4Addr,
    pub host_network_cidr: String,
    pub guest_agent_port: u16,
    pub lan_socket_path: PathBuf,
    pub host_socket_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VfkitGatewayPlan {
    pub lan_vmnet: ProcessSpec,
    pub host_vmnet: ProcessSpec,
    pub vfkit: ProcessSpec,
}

pub(crate) fn build_plan(config: &VfkitGatewayConfig) -> Result<VfkitGatewayPlan, String> {
    validate(config)?;

    let cmdline = guest_cmdline(config)?;
    let console_log_path = config
        .lan_socket_path
        .parent()
        .map(|parent| parent.join("vfkit-console.log"))
        .unwrap_or_else(|| PathBuf::from("vfkit-console.log"));
    let lan_vmnet = ProcessSpec {
        program: config.vmnet_helper_path.clone(),
        args: vec![
            OsString::from("--socket"),
            config.lan_socket_path.as_os_str().to_owned(),
            OsString::from("--operation-mode"),
            OsString::from("bridged"),
            OsString::from("--shared-interface"),
            OsString::from(&config.bridge_interface),
            OsString::from("--enable-tso"),
        ],
    };

    let (start_address, end_address, subnet_mask) =
        host_network_options(&config.host_network_cidr, config.host_ip)?;
    let host_vmnet = ProcessSpec {
        program: config.vmnet_helper_path.clone(),
        args: vec![
            OsString::from("--socket"),
            config.host_socket_path.as_os_str().to_owned(),
            OsString::from("--operation-mode"),
            OsString::from("host"),
            OsString::from("--start-address"),
            OsString::from(start_address),
            OsString::from("--end-address"),
            OsString::from(end_address),
            OsString::from("--subnet-mask"),
            OsString::from(subnet_mask),
            OsString::from("--enable-isolation"),
        ],
    };

    let vfkit = ProcessSpec {
        program: config.vfkit_path.clone(),
        args: vec![
            OsString::from("--cpus"),
            OsString::from(config.cpus.to_string()),
            OsString::from("--memory"),
            OsString::from(config.memory_mib.to_string()),
            OsString::from("--kernel"),
            config.kernel_path.as_os_str().to_owned(),
            OsString::from("--initrd"),
            config.initrd_path.as_os_str().to_owned(),
            OsString::from("--kernel-cmdline"),
            OsString::from(cmdline),
            OsString::from("--device"),
            OsString::from(format!(
                "virtio-serial,logFilePath={}",
                console_log_path.display()
            )),
            OsString::from("--device"),
            OsString::from(format!(
                "virtio-net,unixSocketPath={}",
                config.lan_socket_path.display()
            )),
            OsString::from("--device"),
            OsString::from(format!(
                "virtio-net,unixSocketPath={}",
                config.host_socket_path.display()
            )),
        ],
    };

    Ok(VfkitGatewayPlan {
        lan_vmnet,
        host_vmnet,
        vfkit,
    })
}

// The plan is prepared for the future release-gated Gateway start path.
#[allow(dead_code)]
pub(crate) fn build_runtime_plan(
    plan: VfkitGatewayPlan,
    runtime_dir: PathBuf,
    bridged_socket: PathBuf,
    host_only_socket: PathBuf,
    bridged_probe: Box<dyn StartupProbe>,
    host_only_probe: Box<dyn StartupProbe>,
    guest_agent_probe: Box<dyn StartupProbe>,
) -> Result<GatewayRuntimePlan, String> {
    let mut artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone())
        .map_err(|error| format!("创建 vfkit Gateway runtime 目录失败：{error}"))?;
    let bridged_pid = runtime_dir.join("vmnet-bridged.pid");
    let host_only_pid = runtime_dir.join("vmnet-host-only.pid");
    let vfkit_pid = runtime_dir.join("vfkit.pid");
    let bridged_stdout = runtime_dir.join("vmnet-bridged.stdout.log");
    let bridged_stderr = runtime_dir.join("vmnet-bridged.stderr.log");
    let host_only_stdout = runtime_dir.join("vmnet-host-only.stdout.log");
    let host_only_stderr = runtime_dir.join("vmnet-host-only.stderr.log");
    let bridged_plist = runtime_dir.join("vmnet-bridged.launchd.plist");
    let host_only_plist = runtime_dir.join("vmnet-host-only.launchd.plist");
    let console_log = runtime_dir.join("vfkit-console.log");

    for path in [
        bridged_socket,
        host_only_socket,
        bridged_pid,
        host_only_pid,
        vfkit_pid,
        bridged_stdout.clone(),
        bridged_stderr.clone(),
        host_only_stdout.clone(),
        host_only_stderr.clone(),
        bridged_plist,
        host_only_plist,
        console_log,
    ] {
        artifacts
            .register_file(path)
            .map_err(|error| format!("注册 vfkit Gateway runtime 文件失败：{error}"))?;
    }

    // Direct ownership avoids creating two transient per-user launchd jobs on
    // every Gateway start/stop. vmnet-helper is already an independently
    // signed executable, and ManagedChild gives it an isolated process group
    // plus deterministic cleanup. Keep launchd as an explicit compatibility
    // mode for older helper/macOS combinations that require it.
    let use_launchd = env::var("SONGSTERX_VMNET_LAUNCH_MODE")
        .map(|value| value.eq_ignore_ascii_case("launchd"))
        .unwrap_or(false);
    let host_only_command = managed_command_spec(&plan.host_vmnet, "vmnet-host-only");
    let host_only_command = if use_launchd {
        host_only_command.with_launchd_logs(host_only_stdout, host_only_stderr)
    } else {
        host_only_command
    };
    let bridged_command = managed_command_spec(&plan.lan_vmnet, "vmnet-bridged");
    let bridged_command = if use_launchd {
        bridged_command.with_launchd_logs(bridged_stdout, bridged_stderr)
    } else {
        bridged_command
    };

    Ok(GatewayRuntimePlan::new(
        artifacts,
        vec![
            LaunchStep {
                role: RuntimeRole::VmnetHostOnly,
                command: Some(host_only_command),
                probe: host_only_probe,
                timeout: Duration::from_secs(5),
                pid_file: Some(runtime_dir.join("vmnet-host-only.pid")),
            },
            LaunchStep {
                role: RuntimeRole::VmnetBridged,
                command: Some(bridged_command),
                probe: bridged_probe,
                timeout: Duration::from_secs(5),
                pid_file: Some(runtime_dir.join("vmnet-bridged.pid")),
            },
            LaunchStep {
                role: RuntimeRole::Vfkit,
                command: Some(managed_command_spec(&plan.vfkit, "vfkit")),
                // vfkit has no trusted readiness endpoint here; the supervisor
                // separately requires its leader to remain alive during startup.
                probe: Box::new(AlwaysReadyProbe),
                timeout: Duration::from_secs(2),
                pid_file: Some(runtime_dir.join("vfkit.pid")),
            },
            LaunchStep {
                role: RuntimeRole::GuestAgent,
                command: None,
                probe: guest_agent_probe,
                timeout: Duration::from_secs(20),
                pid_file: None,
            },
        ],
    ))
}

pub(crate) fn validate(config: &VfkitGatewayConfig) -> Result<(), String> {
    for (label, path, allow_path_lookup) in [
        ("vfkit", &config.vfkit_path, true),
        ("vmnet-helper", &config.vmnet_helper_path, true),
        ("Linux kernel", &config.kernel_path, false),
        ("Linux initrd", &config.initrd_path, false),
    ] {
        if !path.is_file() && !(allow_path_lookup && path.components().count() == 1) {
            return Err(format!("{label} 不存在或不是文件：{}", path.display()));
        }
    }
    if config.cpus == 0 || config.cpus > 8 {
        return Err("vfkit guest CPU 数必须在 1-8 之间".into());
    }
    if !(256..=16_384).contains(&config.memory_mib) {
        return Err("vfkit guest 内存必须在 256-16384 MiB 之间".into());
    }
    if config.bridge_interface.trim().is_empty() {
        return Err("vfkit LAN bridge 必须填写物理网卡名称".into());
    }
    if config.guest_agent_port == 0 {
        return Err("vfkit guest agent 端口无效".into());
    }
    validate_dns_server(&config.dns_server)?;
    validate_network_addresses(config)?;
    for (label, path) in [
        ("LAN", &config.lan_socket_path),
        ("host-only", &config.host_socket_path),
    ] {
        validate_unixgram_socket_path(path, label)?;
    }
    let guest_lan_selector = effective_selector(
        &config.guest_lan_selector,
        DEFAULT_GATEWAY_GUEST_LAN_SELECTOR,
    );
    let guest_host_selector = effective_selector(
        &config.guest_host_selector,
        DEFAULT_GATEWAY_GUEST_HOST_SELECTOR,
    );
    parse_selector(guest_lan_selector, "LAN")?;
    parse_selector(guest_host_selector, "host-only")?;
    if guest_lan_selector == guest_host_selector {
        return Err("LAN 与 host-only selector 不能相同".into());
    }
    if config.host_ip == config.guest_host_ip {
        return Err("vfkit host-only 网卡的 host IP 与 guest IP 不能相同".into());
    }
    let (network, prefix) = parse_cidr(&config.host_network_cidr)?;
    let mask = prefix_mask(prefix);
    for (label, address) in [("host", config.host_ip), ("guest", config.guest_host_ip)] {
        if u32::from(address) & mask != u32::from(network) {
            return Err(format!(
                "vfkit host-only {label} IP 不在 {} 内",
                config.host_network_cidr
            ));
        }
    }
    if config.lan_socket_path == config.host_socket_path {
        return Err("vfkit 的 LAN 与 host-only socket 不能相同".into());
    }
    if config.guest_cmdline.contains('\n') || config.guest_cmdline.contains('\r') {
        return Err("vfkit guest kernel cmdline 不能包含换行".into());
    }
    Ok(())
}

fn validate_unixgram_socket_path(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;

    let length = path.as_os_str().as_bytes().len();
    if length >= DARWIN_UNIX_SOCKET_PATH_LIMIT {
        return Err(format!(
            "vfkit {label} Unix socket 路径过长（{length} 字节，Darwin 限制为 {}）：{}",
            DARWIN_UNIX_SOCKET_PATH_LIMIT - 1,
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("vfkit {label} Unix socket 缺少父目录：{}", path.display()))?;
    let client_path = parent.join(VFKIT_LOCAL_SOCKET_MAX_BASENAME);
    let client_length = client_path.as_os_str().as_bytes().len();
    if client_length >= DARWIN_UNIX_SOCKET_PATH_LIMIT {
        return Err(format!(
            "vfkit {label} Unix socket 所在目录过长（隐式 client endpoint 为 {client_length} 字节）：{}",
            client_path.display()
        ));
    }
    Ok(())
}

fn guest_cmdline(config: &VfkitGatewayConfig) -> Result<String, String> {
    let mut cmdline = config.guest_cmdline.trim().to_string();
    for token in cmdline.split_ascii_whitespace() {
        if token.starts_with("songsterx.") {
            return Err(format!("guest cmdline 不允许覆盖保留参数：{token}"));
        }
    }
    // vfkit 0.6.x does not expose a virtio-net MAC option. Keep Alpine's
    // predictable names disabled so the two devices remain eth0/eth1 across
    // boots and match the default Gateway selectors.
    if !cmdline
        .split_ascii_whitespace()
        .any(|token| token.starts_with("net.ifnames="))
    {
        if !cmdline.is_empty() {
            cmdline.push(' ');
        }
        cmdline.push_str("net.ifnames=0");
    }
    let lan_selector = selector_cmdline(
        &config.guest_lan_selector,
        "lan",
        DEFAULT_GATEWAY_GUEST_LAN_SELECTOR,
    )?;
    let host_selector = selector_cmdline(
        &config.guest_host_selector,
        "host",
        DEFAULT_GATEWAY_GUEST_HOST_SELECTOR,
    )?;
    for value in [
        format!("songsterx.lan_ip={}", config.gateway_ip),
        format!("songsterx.lan_cidr={}", config.gateway_cidr),
        format!("songsterx.upstream_gateway={}", config.upstream_gateway),
        format!("songsterx.dns_server={}", config.dns_server.trim()),
        format!("songsterx.{lan_selector}"),
        format!("songsterx.host_ip={}", config.guest_host_ip),
        format!("songsterx.host_cidr={}", config.host_network_cidr),
        format!("songsterx.{host_selector}"),
        format!("songsterx.mitm_host={}", config.host_ip),
        format!("songsterx.agent_port={}", config.guest_agent_port),
    ] {
        if !cmdline.is_empty() {
            cmdline.push(' ');
        }
        cmdline.push_str(&value);
    }
    Ok(cmdline)
}

fn validate_dns_server(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("vfkit guest DNS 服务器不能为空".into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
    {
        return Err("vfkit guest DNS 服务器包含非法字符".into());
    }
    Ok(())
}

fn validate_network_addresses(config: &VfkitGatewayConfig) -> Result<(), String> {
    let (lan_network, lan_prefix) = parse_cidr(&config.gateway_cidr)?;
    let (host_network, host_prefix) = parse_cidr(&config.host_network_cidr)?;
    let lan_mask = prefix_mask(lan_prefix);
    let host_mask = prefix_mask(host_prefix);
    let lan_network = u32::from(lan_network);
    let host_network = u32::from(host_network);
    let lan_gateway = u32::from(config.gateway_ip);
    let upstream_gateway = u32::from(config.upstream_gateway);
    let host_ip = u32::from(config.host_ip);
    let guest_host_ip = u32::from(config.guest_host_ip);
    if lan_gateway & lan_mask != lan_network {
        return Err(format!(
            "vfkit LAN gateway IP 不在 {} 内",
            config.gateway_cidr
        ));
    }
    let lan_broadcast = lan_network | !lan_mask;
    if lan_gateway == lan_network || lan_gateway == lan_broadcast {
        return Err("vfkit LAN gateway IP 不能是网络地址或广播地址".into());
    }
    if upstream_gateway & lan_mask != lan_network {
        return Err(format!(
            "vfkit upstream gateway 不在 {} 内",
            config.gateway_cidr
        ));
    }
    if upstream_gateway == lan_network || upstream_gateway == lan_broadcast {
        return Err("vfkit upstream gateway 不能是网络地址或广播地址".into());
    }
    if lan_gateway == upstream_gateway {
        return Err("vfkit LAN gateway IP 与 upstream gateway 不能相同".into());
    }
    if host_ip & host_mask != host_network {
        return Err(format!(
            "vfkit host-only host IP 不在 {} 内",
            config.host_network_cidr
        ));
    }
    if guest_host_ip & host_mask != host_network {
        return Err(format!(
            "vfkit host-only guest IP 不在 {} 内",
            config.host_network_cidr
        ));
    }
    let host_broadcast = host_network | !host_mask;
    if host_ip == host_network
        || host_ip == host_broadcast
        || guest_host_ip == host_network
        || guest_host_ip == host_broadcast
    {
        return Err("vfkit host-only IP 不能是网络地址或广播地址".into());
    }
    if cidr_overlaps(lan_network, lan_prefix, host_network, host_prefix) {
        return Err("vfkit LAN CIDR 与 host-only CIDR 不能重叠".into());
    }
    Ok(())
}

fn cidr_overlaps(
    first_network: u32,
    first_prefix: u8,
    second_network: u32,
    second_prefix: u8,
) -> bool {
    let first_mask = prefix_mask(first_prefix);
    let second_mask = prefix_mask(second_prefix);
    first_network & second_mask == second_network || second_network & first_mask == first_network
}

fn parse_selector(value: &str, label: &str) -> Result<(), String> {
    let (kind, selector) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("{label} selector 必须使用 if:NAME 或 mac:XX:XX:XX:XX:XX:XX"))?;
    match kind {
        "if" => validate_interface_name(selector, label),
        "mac" => validate_mac(selector, label),
        _ => Err(format!("{label} selector 类型只能是 if 或 mac")),
    }
}

fn selector_cmdline(value: &str, role: &str, default: &str) -> Result<String, String> {
    let value = effective_selector(value, default);
    let (kind, selector) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("{role} selector 无效"))?;
    parse_selector(value, role)?;
    Ok(format!("{role}_{kind}={selector}"))
}

fn effective_selector<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value.trim()
    }
}

fn validate_interface_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 15
        || value == "lo"
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err(format!("{label} selector 网卡名称无效：{value}"));
    }
    Ok(())
}

fn validate_mac(value: &str, label: &str) -> Result<(), String> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(format!("{label} selector MAC 无效：{value}"));
    }
    Ok(())
}

fn parse_cidr(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address, prefix) = value
        .trim()
        .split_once('/')
        .ok_or_else(|| format!("host-only 网段必须使用 IPv4/prefix 格式：{value}"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("host-only 网段地址无效：{address}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("host-only 网段 prefix 无效：{prefix}"))?;
    if prefix > 30 {
        return Err("host-only 网段 prefix 必须在 0-30 之间".into());
    }
    let mask = prefix_mask(prefix);
    Ok((Ipv4Addr::from(u32::from(address) & mask), prefix))
}

fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn host_network_options(cidr: &str, host_ip: Ipv4Addr) -> Result<(String, String, String), String> {
    let (network, prefix) = parse_cidr(cidr)?;
    let mask = prefix_mask(prefix);
    let first = u32::from(host_ip);
    let last = (u32::from(network) | !mask).saturating_sub(1);
    if first >= last {
        return Err(format!("host-only 网段可用地址不足：{cidr}"));
    }
    Ok((
        Ipv4Addr::from(first).to_string(),
        Ipv4Addr::from(last).to_string(),
        Ipv4Addr::from(mask).to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn config(root: &std::path::Path) -> VfkitGatewayConfig {
        VfkitGatewayConfig {
            vfkit_path: root.join("vfkit"),
            vmnet_helper_path: root.join("vmnet-helper"),
            kernel_path: root.join("vmlinuz"),
            initrd_path: root.join("initrd"),
            guest_cmdline: "console=hvc0".into(),
            cpus: 1,
            memory_mib: 512,
            bridge_interface: "en0".into(),
            gateway_ip: "192.168.1.2".parse().unwrap(),
            gateway_cidr: "192.168.1.0/24".into(),
            upstream_gateway: "192.168.1.1".parse().unwrap(),
            dns_server: "223.5.5.5".into(),
            guest_lan_selector: "mac:02:00:00:00:00:11".into(),
            guest_host_selector: "mac:02:00:00:00:00:22".into(),
            host_ip: "192.168.250.1".parse().unwrap(),
            guest_host_ip: "192.168.250.2".parse().unwrap(),
            host_network_cidr: "192.168.250.0/24".into(),
            guest_agent_port: 38291,
            lan_socket_path: root.join("lan.sock"),
            host_socket_path: root.join("host.sock"),
        }
    }

    fn materialize_files(root: &std::path::Path) {
        fs::create_dir_all(root).unwrap();
        for name in ["vfkit", "vmnet-helper", "vmlinuz", "initrd"] {
            fs::write(root.join(name), b"test").unwrap();
        }
    }

    fn args(spec: &ProcessSpec) -> Vec<String> {
        spec.args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn plan_has_two_virtio_networks_and_isolation_for_host_only_network() {
        let root =
            std::env::temp_dir().join(format!("songsterx-vfkit-test-{}", std::process::id()));
        materialize_files(&root);
        let plan = build_plan(&config(&root)).unwrap();
        let vfkit_args = args(&plan.vfkit);
        assert_eq!(
            vfkit_args
                .iter()
                .filter(|value| *value == "--device")
                .count(),
            3
        );
        assert!(vfkit_args
            .iter()
            .any(|value| value.starts_with("virtio-serial,logFilePath=")));
        assert!(vfkit_args.iter().any(|value| value.contains("lan.sock")));
        assert!(vfkit_args.iter().any(|value| value.contains("host.sock")));
        assert!(vfkit_args
            .windows(2)
            .any(|pair| pair == ["--memory", "512"]));
        assert!(vfkit_args.iter().any(|value| value == "--kernel-cmdline"));
        assert!(!vfkit_args.iter().any(|value| value == "--cmdline"));
        assert!(args(&plan.host_vmnet).contains(&"--enable-isolation".into()));
        assert!(args(&plan.host_vmnet)
            .windows(2)
            .any(|pair| pair == ["--start-address", "192.168.250.1"]));
        assert!(args(&plan.host_vmnet)
            .windows(2)
            .any(|pair| pair == ["--end-address", "192.168.250.254"]));
        assert!(args(&plan.host_vmnet)
            .windows(2)
            .any(|pair| pair == ["--subnet-mask", "255.255.255.0"]));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn guest_cmdline_carries_addresses_for_agent_bootstrap() {
        let root =
            std::env::temp_dir().join(format!("songsterx-vfkit-cmdline-{}", std::process::id()));
        materialize_files(&root);
        let plan = build_plan(&config(&root)).unwrap();
        let args = args(&plan.vfkit);
        let cmdline = args
            .iter()
            .position(|value| value == "--kernel-cmdline")
            .and_then(|index| args.get(index + 1))
            .unwrap();
        assert!(cmdline.contains("songsterx.lan_ip=192.168.1.2"));
        assert!(cmdline.contains("songsterx.lan_cidr=192.168.1.0/24"));
        assert!(cmdline.contains("songsterx.upstream_gateway=192.168.1.1"));
        assert!(cmdline.contains("songsterx.dns_server=223.5.5.5"));
        assert!(cmdline.contains("songsterx.lan_mac=02:00:00:00:00:11"));
        assert!(cmdline.contains("songsterx.host_ip=192.168.250.2"));
        assert!(cmdline.contains("songsterx.host_cidr=192.168.250.0/24"));
        assert!(cmdline.contains("songsterx.host_mac=02:00:00:00:00:22"));
        assert!(cmdline.contains("songsterx.mitm_host=192.168.250.1"));
        assert!(cmdline.contains("songsterx.agent_port=38291"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn empty_guest_selectors_use_stable_interface_defaults() {
        let root = PathBuf::from("/tmp").join(format!(
            "songsterx-vfkit-default-selectors-{}",
            std::process::id()
        ));
        materialize_files(&root);
        let mut value = config(&root);
        value.guest_lan_selector.clear();
        value.guest_host_selector.clear();
        let plan = build_plan(&value).unwrap();
        let args = args(&plan.vfkit);
        let cmdline = args
            .iter()
            .position(|value| value == "--kernel-cmdline")
            .and_then(|index| args.get(index + 1))
            .unwrap();
        assert!(cmdline.contains("songsterx.lan_if=eth0"));
        assert!(cmdline.contains("songsterx.host_if=eth1"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_guest_dns_server_is_rejected() {
        let root = std::env::temp_dir().join(format!("songsterx-vfkit-dns-{}", std::process::id()));
        materialize_files(&root);
        let mut value = config(&root);
        value.dns_server = "1.1.1.1 nameserver".into();
        assert!(build_plan(&value).unwrap_err().contains("非法字符"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_host_only_address_is_rejected() {
        let root =
            std::env::temp_dir().join(format!("songsterx-vfkit-invalid-{}", std::process::id()));
        materialize_files(&root);
        let mut value = config(&root);
        value.guest_host_ip = "192.168.251.2".parse().unwrap();
        assert!(build_plan(&value).unwrap_err().contains("不在"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unix_socket_paths_are_rejected_before_vfkit_start() {
        let root = PathBuf::from("/tmp/songsterx-").join("a".repeat(110));
        materialize_files(&root);
        let error = build_plan(&config(&root)).unwrap_err();
        assert!(error.contains("Unix socket 路径过长"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reserved_cmdline_and_invalid_selectors_are_rejected() {
        let root =
            PathBuf::from("/tmp").join(format!("songsterx-vfkit-selector-{}", std::process::id()));
        materialize_files(&root);
        let mut value = config(&root);
        value.guest_cmdline = "console=hvc0 songsterx.lan_ip=10.0.0.1".into();
        assert!(build_plan(&value).unwrap_err().contains("保留参数"));
        value.guest_cmdline = "console=hvc0".into();
        value.guest_lan_selector = "eth0".into();
        assert!(build_plan(&value).unwrap_err().contains("selector"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_plan_orders_host_processes_before_guest_barrier() {
        let root = PathBuf::from("/tmp").join(format!(
            "songsterx-vfkit-runtime-plan-{}",
            std::process::id()
        ));
        materialize_files(&root);
        let runtime_dir = root.join("runtime");
        let mut value = config(&root);
        value.lan_socket_path = runtime_dir.join("lan.sock");
        value.host_socket_path = runtime_dir.join("host.sock");
        let plan = build_plan(&value).unwrap();
        let runtime = build_runtime_plan(
            plan,
            runtime_dir.clone(),
            value.lan_socket_path,
            value.host_socket_path,
            Box::new(AlwaysReadyProbe),
            Box::new(AlwaysReadyProbe),
            Box::new(AlwaysReadyProbe),
        )
        .unwrap();

        assert_eq!(runtime.steps.len(), 4);
        assert_eq!(runtime.steps[0].role, RuntimeRole::VmnetHostOnly);
        assert_eq!(runtime.steps[1].role, RuntimeRole::VmnetBridged);
        assert_eq!(runtime.steps[2].role, RuntimeRole::Vfkit);
        assert_eq!(runtime.steps[3].role, RuntimeRole::GuestAgent);
        assert!(runtime.steps[3].command.is_none());
        drop(runtime);
        assert!(!runtime_dir.exists());
        let _ = fs::remove_dir_all(root);
    }
}
