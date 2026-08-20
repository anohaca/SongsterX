use std::{collections::BTreeMap, fs, net::Ipv4Addr, path::Path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InterfaceSelector {
    pub(crate) name: Option<String>,
    pub(crate) mac: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ipv4Cidr {
    pub(crate) network: Ipv4Addr,
    pub(crate) prefix: u8,
}

impl Ipv4Cidr {
    fn parse(value: &str, label: &str) -> Result<Self, String> {
        let (address, prefix) = value
            .trim()
            .split_once('/')
            .ok_or_else(|| format!("{label} 必须使用 IPv4/prefix"))?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("{label} IPv4 无效：{address}"))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("{label} prefix 无效：{prefix}"))?;
        if !(1..=30).contains(&prefix) {
            return Err(format!("{label} prefix 必须在 1-30"));
        }
        let mask = prefix_mask(prefix);
        Ok(Self {
            network: Ipv4Addr::from(u32::from(address) & mask),
            prefix,
        })
    }

    fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & prefix_mask(self.prefix) == u32::from(self.network)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuestBootConfig {
    pub(crate) lan_ip: Ipv4Addr,
    pub(crate) lan_cidr: Ipv4Cidr,
    pub(crate) host_ip: Ipv4Addr,
    pub(crate) host_cidr: Ipv4Cidr,
    pub(crate) upstream_gateway: Ipv4Addr,
    pub(crate) agent_port: u16,
    pub(crate) lan_selector: InterfaceSelector,
    pub(crate) host_selector: InterfaceSelector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InterfaceIdentity {
    pub(crate) name: String,
    pub(crate) mac: String,
    pub(crate) virtio: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedGuestNetwork {
    pub(crate) lan_interface: String,
    pub(crate) host_interface: String,
    pub(crate) lan_ip: Ipv4Addr,
    pub(crate) host_ip: Ipv4Addr,
    pub(crate) upstream_gateway: Ipv4Addr,
    pub(crate) agent_port: u16,
}

pub(crate) fn parse_cmdline(value: &str) -> Result<GuestBootConfig, String> {
    let mut values = BTreeMap::<String, String>::new();
    for token in value.split_ascii_whitespace() {
        let Some((key, raw_value)) = token.split_once('=') else {
            continue;
        };
        if !key.starts_with("songsterx.") {
            continue;
        }
        if values
            .insert(key.to_string(), raw_value.to_string())
            .is_some()
        {
            return Err(format!("kernel cmdline 参数重复：{key}"));
        }
    }

    let lan_ip = required_ipv4(&values, "songsterx.lan_ip")?;
    let lan_cidr = Ipv4Cidr::parse(required(&values, "songsterx.lan_cidr")?, "LAN CIDR")?;
    let host_ip = required_ipv4(&values, "songsterx.host_ip")?;
    let host_cidr = Ipv4Cidr::parse(required(&values, "songsterx.host_cidr")?, "host-only CIDR")?;
    let upstream_gateway = required_ipv4(&values, "songsterx.upstream_gateway")?;
    let agent_port = required(&values, "songsterx.agent_port")?
        .parse::<u16>()
        .map_err(|_| "songsterx.agent_port 无效".to_string())?;
    if agent_port == 0 {
        return Err("songsterx.agent_port 不能为 0".into());
    }
    if !lan_cidr.contains(lan_ip) {
        return Err(format!("LAN IP {lan_ip} 不在 LAN CIDR 内"));
    }
    if !lan_cidr.contains(upstream_gateway) {
        return Err(format!("上游网关 {upstream_gateway} 不在 LAN CIDR 内"));
    }
    if lan_ip == upstream_gateway {
        return Err("LAN IP 与上游网关不能相同".into());
    }
    if !host_cidr.contains(host_ip) {
        return Err(format!("host-only IP {host_ip} 不在 host-only CIDR 内"));
    }
    if lan_cidr.overlaps(&host_cidr) {
        return Err("LAN CIDR 与 host-only CIDR 不能重叠".into());
    }

    Ok(GuestBootConfig {
        lan_ip,
        lan_cidr,
        host_ip,
        host_cidr,
        upstream_gateway,
        agent_port,
        lan_selector: selector(&values, "lan")?,
        host_selector: selector(&values, "host")?,
    })
}

pub(crate) fn read_interface_inventory(
    sys_class_net: &Path,
) -> Result<Vec<InterfaceIdentity>, String> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir(sys_class_net)
        .map_err(|error| format!("无法读取 {}：{error}", sys_class_net.display()))?
    {
        let entry = entry.map_err(|error| format!("读取 guest 网卡目录失败：{error}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        validate_ifname(&name)?;
        let path = entry.path();
        let mac = normalize_mac(
            fs::read_to_string(path.join("address"))
                .map_err(|error| format!("读取 guest 网卡 {name} MAC 失败：{error}"))?
                .trim(),
        )?;
        let modalias = fs::read_to_string(path.join("device/modalias")).unwrap_or_default();
        let uevent = fs::read_to_string(path.join("device/uevent")).unwrap_or_default();
        interfaces.push(InterfaceIdentity {
            name,
            mac,
            virtio: modalias.trim().starts_with("virtio:")
                || uevent
                    .lines()
                    .any(|line| line.trim() == "DRIVER=virtio_net"),
        });
    }
    Ok(interfaces)
}

pub(crate) fn resolve_interfaces(
    config: &GuestBootConfig,
    interfaces: &[InterfaceIdentity],
) -> Result<ResolvedGuestNetwork, String> {
    let lan_interface = resolve_selector("LAN", &config.lan_selector, interfaces)?;
    let host_interface = resolve_selector("host-only", &config.host_selector, interfaces)?;
    if lan_interface == host_interface {
        return Err("LAN 与 host-only selector 解析到了同一张网卡".into());
    }
    Ok(ResolvedGuestNetwork {
        lan_interface,
        host_interface,
        lan_ip: config.lan_ip,
        host_ip: config.host_ip,
        upstream_gateway: config.upstream_gateway,
        agent_port: config.agent_port,
    })
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("kernel cmdline 缺少 {key}"))
}

fn required_ipv4(values: &BTreeMap<String, String>, key: &str) -> Result<Ipv4Addr, String> {
    let value = required(values, key)?;
    value
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("{key} IPv4 无效：{value}"))
}

fn selector(values: &BTreeMap<String, String>, role: &str) -> Result<InterfaceSelector, String> {
    let name = values
        .get(&format!("songsterx.{role}_if"))
        .filter(|value| !value.is_empty())
        .cloned();
    let mac = values
        .get(&format!("songsterx.{role}_mac"))
        .filter(|value| !value.is_empty())
        .map(|value| normalize_mac(value))
        .transpose()?;
    if name.is_none() && mac.is_none() {
        return Err(format!("{role} 接口 selector 缺失"));
    }
    if let Some(name) = name.as_deref() {
        validate_ifname(name)?;
    }
    Ok(InterfaceSelector { name, mac })
}

fn resolve_selector(
    label: &str,
    selector: &InterfaceSelector,
    interfaces: &[InterfaceIdentity],
) -> Result<String, String> {
    let matches = interfaces
        .iter()
        .filter(|interface| interface.virtio)
        .filter(|interface| {
            selector
                .name
                .as_ref()
                .map(|name| name == &interface.name)
                .unwrap_or(true)
        })
        .filter(|interface| {
            selector
                .mac
                .as_ref()
                .map(|mac| mac == &interface.mac)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [interface] => Ok(interface.name.clone()),
        [] => Err(format!("{label} selector 没有匹配到 virtio-net 网卡")),
        _ => Err(format!("{label} selector 匹配到多张 virtio-net 网卡")),
    }
}

fn validate_ifname(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 15
        || value == "lo"
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err(format!("guest 网卡名称无效：{value}"));
    }
    Ok(())
}

fn normalize_mac(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(format!("MAC 地址无效：{value}"));
    }
    Ok(value)
}

fn prefix_mask(prefix: u8) -> u32 {
    u32::MAX << (32 - prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_cmdline() -> String {
        [
            "console=hvc0",
            "songsterx.lan_ip=192.168.1.2",
            "songsterx.lan_cidr=192.168.1.0/24",
            "songsterx.host_ip=192.168.250.2",
            "songsterx.host_cidr=192.168.250.0/24",
            "songsterx.upstream_gateway=192.168.1.1",
            "songsterx.agent_port=38291",
            "songsterx.lan_mac=02:00:00:00:00:11",
            "songsterx.host_if=mgmt0",
        ]
        .join(" ")
    }

    #[test]
    fn parses_gateway_kernel_cmdline() {
        let parsed = parse_cmdline(&valid_cmdline()).unwrap();
        assert_eq!(parsed.lan_ip, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(parsed.host_ip, "192.168.250.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            parsed.upstream_gateway,
            "192.168.1.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(parsed.agent_port, 38291);
        assert_eq!(
            parsed.lan_selector.mac.as_deref(),
            Some("02:00:00:00:00:11")
        );
        assert_eq!(parsed.host_selector.name.as_deref(), Some("mgmt0"));
    }

    #[test]
    fn rejects_missing_or_duplicate_bindings() {
        let missing = valid_cmdline().replace(" songsterx.host_if=mgmt0", "");
        assert!(parse_cmdline(&missing)
            .unwrap_err()
            .contains("host 接口 selector 缺失"));
        let duplicate = format!("{} songsterx.lan_ip=192.168.1.9", valid_cmdline());
        assert!(parse_cmdline(&duplicate).unwrap_err().contains("参数重复"));
    }

    #[test]
    fn rejects_non_virtio_and_same_interface() {
        let config = parse_cmdline(&valid_cmdline()).unwrap();
        let same = vec![InterfaceIdentity {
            name: "mgmt0".into(),
            mac: "02:00:00:00:00:11".into(),
            virtio: true,
        }];
        assert!(resolve_interfaces(&config, &same)
            .unwrap_err()
            .contains("同一张网卡"));
        let non_virtio = vec![
            InterfaceIdentity {
                name: "lan0".into(),
                mac: "02:00:00:00:00:11".into(),
                virtio: false,
            },
            InterfaceIdentity {
                name: "mgmt0".into(),
                mac: "02:00:00:00:00:22".into(),
                virtio: true,
            },
        ];
        assert!(resolve_interfaces(&config, &non_virtio)
            .unwrap_err()
            .contains("LAN selector"));
    }
}
