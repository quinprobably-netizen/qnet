//! `NetBackend` over the system D-Bus: NetworkManager and systemd-resolved.
//! Plain method calls (no cached proxies), everything as the calling user.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use zbus::blocking::Connection;
use zbus::zvariant::{OwnedValue, Value};

use crate::net::*;

const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const RESOLVED: &str = "org.freedesktop.resolve1";
const RESOLVED_PATH: &str = "/org/freedesktop/resolve1";
const PROPS: &str = "org.freedesktop.DBus.Properties";

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

type Dict = HashMap<String, OwnedValue>;
/// `ResolveHostname` reply: (ifindex, family, address) records, canonical name, flags.
type ResolveReply = (Vec<(i32, i32, Vec<u8>)>, String, u64);
pub type Settings = HashMap<String, Dict>;

pub struct DbusBackend {
    conn: Connection,
    /// Set by SIGTERM in a one-shot verb: waiting loops give up.
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl DbusBackend {
    pub fn connect() -> NetResult<Self> {
        let conn = zbus::blocking::connection::Builder::system()
            .map_err(map_err)?
            .method_timeout(Duration::from_secs(15))
            .build()
            .map_err(map_err)?;
        Ok(Self { conn, cancel: None })
    }

    /// Let `flag` cut the waits short (activation polling).
    pub fn with_cancel(mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.cancel = Some(flag);
        self
    }

    fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn call<B>(&self, dest: &str, path: &str, iface: &str, method: &str, body: &B) -> NetResult<zbus::Message>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.conn
            .call_method(Some(dest), path, Some(iface), method, body)
            .map_err(map_err)
    }

    fn get_all(&self, dest: &str, path: &str, iface: &str) -> NetResult<Dict> {
        let m = self.call(dest, path, PROPS, "GetAll", &(iface,))?;
        m.body().deserialize::<Dict>().map_err(|e| NetError::Bus(e.to_string()))
    }

    fn get_prop(&self, dest: &str, path: &str, iface: &str, name: &str) -> NetResult<OwnedValue> {
        let m = self.call(dest, path, PROPS, "Get", &(iface, name))?;
        m.body()
            .deserialize::<OwnedValue>()
            .map_err(|e| NetError::Bus(e.to_string()))
    }

    fn path_reply(&self, m: &zbus::Message) -> NetResult<String> {
        m.body()
            .deserialize::<zbus::zvariant::OwnedObjectPath>()
            .map(|p| p.to_string())
            .map_err(|e| NetError::Bus(e.to_string()))
    }

    fn device_by_iface(&self, iface: &str) -> NetResult<String> {
        let m = self
            .call(NM, NM_PATH, "org.freedesktop.NetworkManager", "GetDeviceByIpIface", &(iface,))
            .map_err(|e| match e {
                NetError::Bus(_) | NetError::NotFound(_) => NetError::NotFound(format!("no device {iface}")),
                other => other,
            })?;
        self.path_reply(&m)
    }

    fn connection_by_uuid(&self, uuid: &str) -> NetResult<String> {
        let m = self
            .call(
                NM,
                NM_SETTINGS_PATH,
                "org.freedesktop.NetworkManager.Settings",
                "GetConnectionByUuid",
                &(uuid,),
            )
            .map_err(|e| match e {
                NetError::Bus(_) | NetError::NotFound(_) => NetError::NotFound("no such saved connection".into()),
                other => other,
            })?;
        self.path_reply(&m)
    }

    fn get_settings(&self, conn_path: &str) -> NetResult<Settings> {
        let m = self.call(
            NM,
            conn_path,
            "org.freedesktop.NetworkManager.Settings.Connection",
            "GetSettings",
            &(),
        )?;
        m.body()
            .deserialize::<Settings>()
            .map_err(|e| NetError::Bus(e.to_string()))
    }

    /// System-owned secrets of the sections that carry them.
    fn get_secrets(&self, conn_path: &str, settings: &Settings) -> Settings {
        let mut out = Settings::new();
        for section in ["802-11-wireless-security", "802-1x"] {
            if !settings.contains_key(section) {
                continue;
            }
            let Ok(m) = self.call(
                NM,
                conn_path,
                "org.freedesktop.NetworkManager.Settings.Connection",
                "GetSecrets",
                &(section,),
            ) else {
                continue;
            };
            if let Ok(s) = m.body().deserialize::<Settings>() {
                for (k, v) in s {
                    out.entry(k).or_default().extend(v);
                }
            }
        }
        out
    }

    /// Replace a profile's settings, carrying its secrets along so the update
    /// can never drop a stored passphrase. Verifies that they survived.
    fn update_profile(&self, conn_path: &str, mut settings: Settings, secrets: Settings) -> NetResult<()> {
        for (section, entries) in &secrets {
            let dst = settings.entry(section.clone()).or_default();
            for (k, v) in entries {
                if let Ok(c) = v.try_clone() {
                    dst.insert(k.clone(), c);
                }
            }
        }
        let call_update = |s: &Settings| -> NetResult<()> {
            self.call(
                NM,
                conn_path,
                "org.freedesktop.NetworkManager.Settings.Connection",
                "Update",
                &(s,),
            )
            .map(|_| ())
        };
        call_update(&settings)?;

        // Verify the secrets are still stored; if not, put them back once.
        let expected: usize = secrets.values().map(|e| e.len()).sum();
        if expected > 0 {
            let after_settings = self.get_settings(conn_path)?;
            let after = self.get_secrets(conn_path, &after_settings);
            let have: usize = after.values().map(|e| e.len()).sum();
            if have < expected {
                call_update(&settings)?;
                let after = self.get_secrets(conn_path, &self.get_settings(conn_path)?);
                let have: usize = after.values().map(|e| e.len()).sum();
                if have < expected {
                    return Err(NetError::Bus(
                        "the profile's stored secrets could not be preserved".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn wait_activation(&self, active_path: &str, device_path: &str, timeout: Duration) -> NetResult<()> {
        let start = Instant::now();
        loop {
            let state = self
                .get_prop(NM, active_path, "org.freedesktop.NetworkManager.Connection.Active", "State")
                .ok()
                .and_then(|v| u32::try_from(&v).ok());
            match state {
                Some(2) => return Ok(()),
                Some(0) | Some(1) | Some(3) => {}
                // Deactivated, or the object is already gone.
                Some(_) | None => {
                    let reason = self
                        .get_prop(NM, device_path, "org.freedesktop.NetworkManager.Device", "StateReason")
                        .ok()
                        .and_then(|v| reason_code(&v));
                    return Err(activation_error(reason));
                }
            }
            if self.cancelled() {
                return Err(NetError::Interrupted("stopped while waiting for the connection".into()));
            }
            if start.elapsed() >= timeout {
                return Err(NetError::Timeout("the connection did not come up".into()));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// NM_DEVICE_STATE_REASON codes that mean the secrets were rejected.
fn activation_error(reason: Option<u32>) -> NetError {
    match reason {
        // NO_SECRETS, SUPPLICANT_DISCONNECT, SUPPLICANT_CONFIG_FAILED,
        // SUPPLICANT_FAILED, SUPPLICANT_TIMEOUT
        Some(7) | Some(8) | Some(9) | Some(10) | Some(11) => NetError::Activation {
            auth: true,
            detail: "authentication failed; check the passphrase".into(),
        },
        Some(r) => NetError::Activation {
            auth: false,
            detail: format!("activation failed (NetworkManager reason {r})"),
        },
        None => NetError::Activation {
            auth: false,
            detail: "activation failed".into(),
        },
    }
}

fn reason_code(v: &OwnedValue) -> Option<u32> {
    match &**v {
        Value::Structure(s) => s.fields().get(1).and_then(|f| as_u32(f)),
        _ => None,
    }
}

fn map_err(e: zbus::Error) -> NetError {
    match e {
        zbus::Error::MethodError(name, desc, _) => {
            let n = name.as_str();
            let d = desc.unwrap_or_default();
            if n.ends_with("PermissionDenied") || n.ends_with("NotAuthorized") || n.ends_with("AccessDenied") {
                NetError::Denied(if d.is_empty() { n.to_string() } else { d })
            } else if n.ends_with("UnknownObject")
                || n.ends_with("UnknownMethod")
                || n.ends_with("UnknownDevice")
                || n.ends_with("UnknownConnection")
                || n.ends_with("InvalidConnection")
                || n.ends_with("NoSuchLink")
            {
                NetError::NotFound(if d.is_empty() { n.to_string() } else { d })
            } else if n.ends_with("InvalidArguments") {
                NetError::Invalid(d)
            } else {
                NetError::Bus(format!("{n}: {d}"))
            }
        }
        zbus::Error::InputOutput(io) if io.kind() == std::io::ErrorKind::TimedOut => {
            NetError::Timeout("D-Bus call timed out".into())
        }
        other => NetError::Bus(other.to_string()),
    }
}

// ---- Value helpers --------------------------------------------------------

fn unwrap_variant<'a, 'b>(v: &'a Value<'b>) -> &'a Value<'b> {
    match v {
        Value::Value(inner) => unwrap_variant(inner),
        other => other,
    }
}

fn as_u32(v: &Value<'_>) -> Option<u32> {
    match unwrap_variant(v) {
        Value::U32(x) => Some(*x),
        Value::U16(x) => Some(*x as u32),
        Value::U8(x) => Some(*x as u32),
        _ => None,
    }
}
fn as_i32(v: &Value<'_>) -> Option<i32> {
    match unwrap_variant(v) {
        Value::I32(x) => Some(*x),
        _ => None,
    }
}
fn as_bool(v: &Value<'_>) -> Option<bool> {
    match unwrap_variant(v) {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}
fn as_string(v: &Value<'_>) -> Option<String> {
    match unwrap_variant(v) {
        Value::Str(s) => Some(s.to_string()),
        Value::ObjectPath(p) => Some(p.to_string()),
        _ => None,
    }
}
fn as_bytes(v: &Value<'_>) -> Option<Vec<u8>> {
    match unwrap_variant(v) {
        Value::Array(a) => a
            .inner()
            .iter()
            .map(|e| match e {
                Value::U8(b) => Some(*b),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

fn d_u32(d: &Dict, k: &str) -> Option<u32> {
    d.get(k).and_then(|v| as_u32(v))
}
fn d_bool(d: &Dict, k: &str) -> Option<bool> {
    d.get(k).and_then(|v| as_bool(v))
}
fn d_string(d: &Dict, k: &str) -> Option<String> {
    d.get(k).and_then(|v| as_string(v))
}
fn d_bytes(d: &Dict, k: &str) -> Option<Vec<u8>> {
    d.get(k).and_then(|v| as_bytes(v))
}
fn d_i64(d: &Dict, k: &str) -> Option<i64> {
    match d.get(k).map(|v| unwrap_variant(v)) {
        Some(Value::I64(x)) => Some(*x),
        Some(Value::U64(x)) => Some(*x as i64),
        Some(Value::I32(x)) => Some(*x as i64),
        Some(Value::U32(x)) => Some(*x as i64),
        _ => None,
    }
}
fn d_path(d: &Dict, k: &str) -> Option<String> {
    d_string(d, k).filter(|p| p != "/" && !p.is_empty())
}

fn ip_from(family: i32, bytes: &[u8]) -> Option<IpAddr> {
    match (family, bytes.len()) {
        (AF_INET, 4) => Some(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))),
        (AF_INET6, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// `a(iiayqs)`: (ifindex, family, address, port, server name).
fn parse_dns_ex(v: &Value<'_>) -> Vec<(i32, IpAddr)> {
    let Value::Array(arr) = unwrap_variant(v) else { return vec![] };
    arr.inner()
        .iter()
        .filter_map(|e| {
            let Value::Structure(s) = unwrap_variant(e) else { return None };
            let f = s.fields();
            let ifindex = as_i32(f.first()?)?;
            let family = as_i32(f.get(1)?)?;
            let addr = as_bytes(f.get(2)?)?;
            Some((ifindex, ip_from(family, &addr)?))
        })
        .collect()
}

/// `(iayqs)`: the link's current server (family, address, port, name).
fn parse_current_ex(v: &Value<'_>) -> Option<IpAddr> {
    let Value::Structure(s) = unwrap_variant(v) else { return None };
    let f = s.fields();
    let family = as_i32(f.first()?)?;
    let addr = as_bytes(f.get(1)?)?;
    ip_from(family, &addr)
}

/// The Manager's `CurrentDNSServerEx`: `(iiayqs)` = ifindex, family, address,
/// port, name. Only an entry without a link (ifindex 0) is a global server.
fn parse_global_current(v: &Value<'_>) -> Option<IpAddr> {
    let Value::Structure(s) = unwrap_variant(v) else { return None };
    let f = s.fields();
    if as_i32(f.first()?)? != 0 {
        return None;
    }
    let family = as_i32(f.get(1)?)?;
    let addr = as_bytes(f.get(2)?)?;
    ip_from(family, &addr)
}

/// `a(sb)` domains: true when one is the root routing domain.
fn has_root_route(v: &Value<'_>) -> bool {
    let Value::Array(arr) = unwrap_variant(v) else { return false };
    arr.inner().iter().any(|e| {
        let Value::Structure(s) = unwrap_variant(e) else { return false };
        let f = s.fields();
        matches!(
            (f.first().and_then(|d| as_string(d)), f.get(1).and_then(|r| as_bool(r))),
            (Some(d), Some(true)) if d == "." || d == "~."
        )
    })
}

fn ov<'a, T: Into<Value<'a>>>(v: T) -> OwnedValue {
    OwnedValue::try_from(v.into()).expect("plain values convert to OwnedValue")
}

fn section_dict<'a>(s: &'a Settings, name: &str) -> Option<&'a Dict> {
    s.get(name)
}

fn parse_v4_dns(d: &Dict) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    if let Some(Value::Array(a)) = d.get("dns").map(|v| unwrap_variant(v)) {
        for e in a.inner() {
            if let Some(n) = as_u32(e) {
                // NM stores IPv4 addresses in network byte order.
                out.push(Ipv4Addr::from(n.to_ne_bytes()));
            }
        }
    }
    if out.is_empty() {
        if let Some(Value::Array(a)) = d.get("dns-data").map(|v| unwrap_variant(v)) {
            for e in a.inner() {
                if let Some(s) = as_string(e) {
                    if let Ok(ip) = s.split('#').next().unwrap_or("").parse::<Ipv4Addr>() {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

fn parse_v6_dns(d: &Dict) -> Vec<Ipv6Addr> {
    let mut out = Vec::new();
    if let Some(Value::Array(a)) = d.get("dns").map(|v| unwrap_variant(v)) {
        for e in a.inner() {
            if let Some(b) = as_bytes(e) {
                if let Some(IpAddr::V6(ip)) = ip_from(AF_INET6, &b) {
                    out.push(ip);
                }
            }
        }
    }
    if out.is_empty() {
        if let Some(Value::Array(a)) = d.get("dns-data").map(|v| unwrap_variant(v)) {
            for e in a.inner() {
                if let Some(s) = as_string(e) {
                    if let Ok(ip) = s.split('#').next().unwrap_or("").parse::<Ipv6Addr>() {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

pub fn parse_dns_settings(s: &Settings) -> DnsSettings {
    let empty = Dict::new();
    let v4 = section_dict(s, "ipv4").unwrap_or(&empty);
    let v6 = section_dict(s, "ipv6").unwrap_or(&empty);
    DnsSettings {
        v4_method: d_string(v4, "method").unwrap_or_else(|| "auto".into()),
        v4_dns: parse_v4_dns(v4),
        v4_ignore_auto: d_bool(v4, "ignore-auto-dns").unwrap_or(false),
        v6_method: d_string(v6, "method").unwrap_or_else(|| "auto".into()),
        v6_dns: parse_v6_dns(v6),
        v6_ignore_auto: d_bool(v6, "ignore-auto-dns").unwrap_or(false),
    }
}

/// Write `dns` into the ipv4/ipv6 sections of a settings dictionary.
pub fn apply_dns_settings(s: &mut Settings, dns: &DnsSettings) {
    {
        let v4 = s.entry("ipv4".into()).or_default();
        let raw: Vec<u32> = dns.v4_dns.iter().map(|a| u32::from_ne_bytes(a.octets())).collect();
        v4.insert("dns".into(), ov(raw));
        v4.remove("dns-data");
        v4.insert("ignore-auto-dns".into(), ov(dns.v4_ignore_auto));
    }
    {
        let v6 = s.entry("ipv6".into()).or_default();
        let raw: Vec<Vec<u8>> = dns.v6_dns.iter().map(|a| a.octets().to_vec()).collect();
        v6.insert("dns".into(), ov(raw));
        v6.remove("dns-data");
        v6.insert("ignore-auto-dns".into(), ov(dns.v6_ignore_auto));
    }
}

pub fn parse_profile(path: &str, s: &Settings) -> Option<Profile> {
    let c = section_dict(s, "connection")?;
    let uuid = d_string(c, "uuid")?;
    let id = d_string(c, "id").unwrap_or_default();
    let kind = match d_string(c, "type").as_deref() {
        Some("802-11-wireless") => ProfileKind::Wifi,
        Some("802-3-ethernet") => ProfileKind::Ethernet,
        _ => ProfileKind::Other,
    };
    let ssid = section_dict(s, "802-11-wireless").and_then(|w| d_bytes(w, "ssid"));
    Some(Profile {
        path: path.to_string(),
        uuid,
        id,
        kind,
        ssid,
        autoconnect: d_bool(c, "autoconnect").unwrap_or(true),
        timestamp: d_i64(c, "timestamp").unwrap_or(0).max(0) as u64,
        dns: parse_dns_settings(s),
    })
}

fn uptime_ms() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = t.split_whitespace().next()?.parse().ok()?;
    Some((secs * 1000.0) as u64)
}

fn ifindex_of(iface: &str) -> Option<u32> {
    if iface.is_empty() || iface.contains('/') || iface.contains("..") {
        return None;
    }
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn ifname_of(ifindex: u32) -> Option<String> {
    let rd = std::fs::read_dir("/sys/class/net").ok()?;
    for e in rd.flatten() {
        if let Ok(t) = std::fs::read_to_string(e.path().join("ifindex")) {
            if t.trim().parse::<u32>().ok() == Some(ifindex) {
                return e.file_name().into_string().ok();
            }
        }
    }
    None
}

impl DbusBackend {
    fn read_ap(&self, path: &str) -> Option<Ap> {
        let d = self
            .get_all(NM, path, "org.freedesktop.NetworkManager.AccessPoint")
            .ok()?;
        Some(Ap {
            path: path.to_string(),
            ssid: d_bytes(&d, "Ssid").unwrap_or_default(),
            strength: d_u32(&d, "Strength").unwrap_or(0).min(100) as u8,
            freq: d_u32(&d, "Frequency").unwrap_or(0),
            flags: d_u32(&d, "Flags").unwrap_or(0),
            wpa: d_u32(&d, "WpaFlags").unwrap_or(0),
            rsn: d_u32(&d, "RsnFlags").unwrap_or(0),
        })
    }

    fn read_device(&self, path: &str, with_aps: bool) -> Option<Device> {
        let d = self.get_all(NM, path, "org.freedesktop.NetworkManager.Device").ok()?;
        let kind = match d_u32(&d, "DeviceType")? {
            1 => DeviceKind::Ethernet,
            2 => DeviceKind::Wifi,
            _ => return None,
        };
        let iface = d_string(&d, "Interface")?;
        let state = d_u32(&d, "State").unwrap_or(0);
        let ifindex = d_u32(&d, "Ifindex")
            .filter(|i| *i > 0)
            .or_else(|| ifindex_of(&iface))
            .unwrap_or(0);

        let active = d_path(&d, "ActiveConnection").and_then(|ap| {
            let a = self
                .get_all(NM, &ap, "org.freedesktop.NetworkManager.Connection.Active")
                .ok()?;
            Some(ActiveConn {
                path: ap.clone(),
                uuid: d_string(&a, "Uuid")?,
                id: d_string(&a, "Id").unwrap_or_default(),
                state: d_u32(&a, "State").unwrap_or(0),
            })
        });

        let (mut ip4, mut gateway) = (None, None);
        if let Some(cfg) = d_path(&d, "Ip4Config") {
            if let Ok(c) = self.get_all(NM, &cfg, "org.freedesktop.NetworkManager.IP4Config") {
                gateway = d_string(&c, "Gateway").and_then(|g| g.parse().ok());
                if let Some(Value::Array(a)) = c.get("AddressData").map(|v| unwrap_variant(v)) {
                    ip4 = a.inner().iter().find_map(|e| match unwrap_variant(e) {
                        Value::Dict(dict) => dict
                            .get::<_, Value>(&Value::new("address"))
                            .ok()
                            .flatten()
                            .and_then(|v| as_string(&v))
                            .and_then(|s| s.parse().ok()),
                        _ => None,
                    });
                }
            }
        }

        let mut speed_mbps = 0;
        if kind == DeviceKind::Ethernet && state == NM_DEVICE_STATE_ACTIVATED {
            speed_mbps = self
                .get_prop(NM, path, "org.freedesktop.NetworkManager.Device.Wired", "Speed")
                .ok()
                .and_then(|v| as_u32(&v))
                .unwrap_or(0);
        }

        let wifi = if kind == DeviceKind::Wifi {
            self.get_all(NM, path, "org.freedesktop.NetworkManager.Device.Wireless")
                .ok()
                .map(|w| {
                    let active_ap = d_path(&w, "ActiveAccessPoint");
                    let last_scan = d_i64(&w, "LastScan").filter(|t| *t >= 0);
                    let last_scan_age_ms = match (last_scan, uptime_ms()) {
                        (Some(t), Some(now)) => Some(now.saturating_sub(t as u64)),
                        _ => None,
                    };
                    let ap_paths: Vec<String> = if with_aps {
                        self.call(
                            NM,
                            path,
                            "org.freedesktop.NetworkManager.Device.Wireless",
                            "GetAllAccessPoints",
                            &(),
                        )
                        .ok()
                        .and_then(|m| m.body().deserialize::<Vec<zbus::zvariant::OwnedObjectPath>>().ok())
                        .map(|v| v.into_iter().map(|p| p.to_string()).collect())
                        .unwrap_or_default()
                    } else {
                        active_ap.iter().cloned().collect()
                    };
                    WifiDev {
                        bitrate_kbps: d_u32(&w, "Bitrate").unwrap_or(0),
                        last_scan_age_ms,
                        aps: ap_paths.iter().filter_map(|p| self.read_ap(p)).collect(),
                        active_ap,
                    }
                })
        } else {
            None
        };

        Some(Device {
            path: path.to_string(),
            iface,
            ifindex,
            kind,
            state,
            active,
            ip4,
            gateway,
            speed_mbps,
            wifi,
        })
    }
}

impl NetBackend for DbusBackend {
    fn snapshot(&self, with_aps: bool) -> NetResult<NetSnapshot> {
        let nm = self.get_all(NM, NM_PATH, "org.freedesktop.NetworkManager")?;
        let device_paths: Vec<String> = match nm.get("Devices").map(|v| unwrap_variant(v)) {
            Some(Value::Array(a)) => a.inner().iter().filter_map(|e| as_string(e)).collect(),
            _ => vec![],
        };
        let devices = device_paths
            .iter()
            .filter_map(|p| self.read_device(p, with_aps))
            .collect();
        Ok(NetSnapshot {
            wifi_enabled: d_bool(&nm, "WirelessEnabled").unwrap_or(false),
            hw_enabled: d_bool(&nm, "WirelessHardwareEnabled").unwrap_or(true),
            connectivity: Connectivity::from_nm(d_u32(&nm, "Connectivity").unwrap_or(0)),
            check_uri: d_string(&nm, "ConnectivityCheckUri").unwrap_or_default(),
            primary_conn: d_path(&nm, "PrimaryConnection"),
            devices,
        })
    }

    fn profiles(&self) -> NetResult<Vec<Profile>> {
        let m = self.call(
            NM,
            NM_SETTINGS_PATH,
            "org.freedesktop.NetworkManager.Settings",
            "ListConnections",
            &(),
        )?;
        let paths = m
            .body()
            .deserialize::<Vec<zbus::zvariant::OwnedObjectPath>>()
            .map_err(|e| NetError::Bus(e.to_string()))?;
        let mut out = Vec::new();
        for p in paths {
            let p = p.to_string();
            // A profile deleted between the list and the read is skipped.
            if let Ok(s) = self.get_settings(&p) {
                if let Some(profile) = parse_profile(&p, &s) {
                    out.push(profile);
                }
            }
        }
        Ok(out)
    }

    fn resolver(&self, wanted: &[(u32, String)]) -> NetResult<ResolverSnapshot> {
        let mgr = self.get_all(RESOLVED, RESOLVED_PATH, "org.freedesktop.resolve1.Manager")?;
        let all = mgr.get("DNSEx").map(|v| parse_dns_ex(v)).unwrap_or_default();
        let fallback: Vec<IpAddr> = mgr
            .get("FallbackDNSEx")
            .map(|v| parse_dns_ex(v))
            .unwrap_or_default()
            .into_iter()
            .map(|(_, a)| a)
            .collect();
        let global: Vec<IpAddr> = all.iter().filter(|(i, _)| *i == 0).map(|(_, a)| *a).collect();

        let mut ifindexes: Vec<u32> = wanted.iter().map(|(i, _)| *i).collect();
        for (i, _) in &all {
            if *i > 0 && !ifindexes.contains(&(*i as u32)) {
                ifindexes.push(*i as u32);
            }
        }
        let mut links = Vec::new();
        for ifx in ifindexes {
            let Ok(m) = self.call(
                RESOLVED,
                RESOLVED_PATH,
                "org.freedesktop.resolve1.Manager",
                "GetLink",
                &(ifx as i32,),
            ) else {
                continue;
            };
            let Ok(path) = self.path_reply(&m) else { continue };
            let Ok(l) = self.get_all(RESOLVED, &path, "org.freedesktop.resolve1.Link") else {
                continue;
            };
            let servers: Vec<IpAddr> = l.get("DNSEx").map(|v| parse_dns_ex_link(v)).unwrap_or_default();
            let current = l.get("CurrentDNSServerEx").and_then(|v| parse_current_ex(v));
            let default_route = d_bool(&l, "DefaultRoute").unwrap_or(false)
                || l.get("Domains").is_some_and(|v| has_root_route(v));
            let name = wanted
                .iter()
                .find(|(i, _)| *i == ifx)
                .map(|(_, n)| n.clone())
                .or_else(|| ifname_of(ifx))
                .unwrap_or_else(|| format!("if{ifx}"));
            links.push(LinkDns {
                ifindex: ifx,
                name,
                servers,
                current,
                default_route,
            });
        }
        let global_current = mgr.get("CurrentDNSServerEx").and_then(|v| parse_global_current(v));
        Ok(ResolverSnapshot {
            links,
            global,
            fallback,
            global_current,
        })
    }

    fn applied_dns(&self, iface: &str) -> NetResult<DnsSettings> {
        let dev = self.device_by_iface(iface)?;
        let m = self.call(
            NM,
            &dev,
            "org.freedesktop.NetworkManager.Device",
            "GetAppliedConnection",
            &(0u32,),
        )?;
        let (settings, _version): (Settings, u64) =
            m.body().deserialize().map_err(|e| NetError::Bus(e.to_string()))?;
        Ok(parse_dns_settings(&settings))
    }

    fn set_profile_dns(&self, uuid: &str, dns: &DnsSettings) -> NetResult<()> {
        let path = self.connection_by_uuid(uuid)?;
        let mut settings = self.get_settings(&path)?;
        let secrets = self.get_secrets(&path, &settings);
        apply_dns_settings(&mut settings, dns);
        self.update_profile(&path, settings, secrets)
    }

    fn reapply_saved(&self, iface: &str) -> NetResult<()> {
        let dev = self.device_by_iface(iface)?;
        let empty = Settings::new();
        self.call(
            NM,
            &dev,
            "org.freedesktop.NetworkManager.Device",
            "Reapply",
            &(&empty, 0u64, 0u32),
        )
        .map(|_| ())
    }

    fn reapply_runtime_dns(&self, iface: &str, servers: &[Ipv4Addr]) -> NetResult<()> {
        let dev = self.device_by_iface(iface)?;
        let m = self.call(
            NM,
            &dev,
            "org.freedesktop.NetworkManager.Device",
            "GetAppliedConnection",
            &(0u32,),
        )?;
        let (mut settings, version): (Settings, u64) =
            m.body().deserialize().map_err(|e| NetError::Bus(e.to_string()))?;
        let mut dns = parse_dns_settings(&settings);
        dns.v4_dns = servers.to_vec();
        dns.v4_ignore_auto = true;
        dns.v6_ignore_auto = true;
        dns.v6_dns.clear();
        apply_dns_settings(&mut settings, &dns);
        self.call(
            NM,
            &dev,
            "org.freedesktop.NetworkManager.Device",
            "Reapply",
            &(&settings, version, 0u32),
        )
        .map(|_| ())
    }

    fn request_scan(&self, iface: &str) -> NetResult<()> {
        let dev = self.device_by_iface(iface)?;
        let opts: HashMap<String, OwnedValue> = HashMap::new();
        self.call(
            NM,
            &dev,
            "org.freedesktop.NetworkManager.Device.Wireless",
            "RequestScan",
            &(&opts,),
        )
        .map(|_| ())
    }

    fn set_wifi_enabled(&self, on: bool) -> NetResult<()> {
        self.call(
            NM,
            NM_PATH,
            PROPS,
            "Set",
            &("org.freedesktop.NetworkManager", "WirelessEnabled", Value::from(on)),
        )
        .map(|_| ())
    }

    fn disconnect(&self, iface: &str) -> NetResult<()> {
        let dev = self.device_by_iface(iface)?;
        self.call(NM, &dev, "org.freedesktop.NetworkManager.Device", "Disconnect", &())
            .map(|_| ())
    }

    fn forget(&self, uuid: &str) -> NetResult<()> {
        let path = self.connection_by_uuid(uuid)?;
        self.call(
            NM,
            &path,
            "org.freedesktop.NetworkManager.Settings.Connection",
            "Delete",
            &(),
        )
        .map(|_| ())
    }

    fn activate_known(
        &self,
        uuid: &str,
        iface: &str,
        ap_path: &str,
        new_passphrase: Option<&str>,
    ) -> NetResult<()> {
        let conn = self.connection_by_uuid(uuid)?;
        let dev = self.device_by_iface(iface)?;
        if let Some(pass) = new_passphrase {
            let mut settings = self.get_settings(&conn)?;
            let secrets = self.get_secrets(&conn, &settings);
            let sec = settings.entry("802-11-wireless-security".into()).or_default();
            sec.entry("key-mgmt".into()).or_insert_with(|| ov("wpa-psk"));
            sec.insert("psk".into(), ov(pass));
            // The new psk replaces the old one; drop the old secret copy.
            let mut secrets = secrets;
            if let Some(s) = secrets.get_mut("802-11-wireless-security") {
                s.remove("psk");
            }
            self.update_profile(&conn, settings, secrets)?;
        }
        let m = self.call(
            NM,
            NM_PATH,
            "org.freedesktop.NetworkManager",
            "ActivateConnection",
            &(
                zbus::zvariant::ObjectPath::try_from(conn.as_str()).map_err(|e| NetError::Invalid(e.to_string()))?,
                zbus::zvariant::ObjectPath::try_from(dev.as_str()).map_err(|e| NetError::Invalid(e.to_string()))?,
                zbus::zvariant::ObjectPath::try_from(ap_path).map_err(|e| NetError::Invalid(e.to_string()))?,
            ),
        )?;
        let active = self.path_reply(&m)?;
        self.wait_activation(&active, &dev, Duration::from_secs(30))
    }

    fn connect_new(
        &self,
        iface: &str,
        ap: &Ap,
        security: &Security,
        passphrase: Option<&str>,
    ) -> NetResult<()> {
        let dev = self.device_by_iface(iface)?;
        let (shown, hidden) = display_ssid(&ap.ssid);
        if hidden {
            return Err(NetError::Invalid("hidden networks cannot be joined from the list".into()));
        }
        let mut s = Settings::new();
        s.insert(
            "connection".into(),
            Dict::from([
                ("id".to_string(), ov(shown.as_str())),
                ("type".to_string(), ov("802-11-wireless")),
                ("autoconnect".to_string(), ov(true)),
            ]),
        );
        s.insert(
            "802-11-wireless".into(),
            Dict::from([
                ("ssid".to_string(), ov(ap.ssid.clone())),
                ("mode".to_string(), ov("infrastructure")),
            ]),
        );
        match security {
            Security::Open => {}
            Security::Psk | Security::Sae => {
                let pass = passphrase.ok_or_else(|| NetError::Invalid("a passphrase is required".into()))?;
                let key_mgmt = if *security == Security::Sae { "sae" } else { "wpa-psk" };
                s.insert(
                    "802-11-wireless-security".into(),
                    Dict::from([
                        ("key-mgmt".to_string(), ov(key_mgmt)),
                        ("psk".to_string(), ov(pass)),
                    ]),
                );
            }
            Security::Owe => {
                s.insert(
                    "802-11-wireless-security".into(),
                    Dict::from([("key-mgmt".to_string(), ov("owe"))]),
                );
            }
            Security::Wep => {
                return Err(NetError::Invalid("WEP networks are not supported".into()));
            }
            Security::Enterprise => {
                return Err(NetError::Invalid("802.1X networks are not supported".into()));
            }
        }
        s.insert("ipv4".into(), Dict::from([("method".to_string(), ov("auto"))]));
        s.insert("ipv6".into(), Dict::from([("method".to_string(), ov("auto"))]));

        let m = self.call(
            NM,
            NM_PATH,
            "org.freedesktop.NetworkManager",
            "AddAndActivateConnection",
            &(
                &s,
                zbus::zvariant::ObjectPath::try_from(dev.as_str()).map_err(|e| NetError::Invalid(e.to_string()))?,
                zbus::zvariant::ObjectPath::try_from(ap.path.as_str()).map_err(|e| NetError::Invalid(e.to_string()))?,
            ),
        )?;
        let (conn_path, active_path): (zbus::zvariant::OwnedObjectPath, zbus::zvariant::OwnedObjectPath) =
            m.body().deserialize().map_err(|e| NetError::Bus(e.to_string()))?;
        match self.wait_activation(active_path.as_str(), &dev, Duration::from_secs(30)) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Do not leave a half-made profile with a wrong key behind.
                let _ = self.call(
                    NM,
                    conn_path.as_str(),
                    "org.freedesktop.NetworkManager.Settings.Connection",
                    "Delete",
                    &(),
                );
                Err(e)
            }
        }
    }

    fn resolve_hostname(&self, name: &str) -> NetResult<Vec<IpAddr>> {
        let m = self.call(
            RESOLVED,
            RESOLVED_PATH,
            "org.freedesktop.resolve1.Manager",
            "ResolveHostname",
            &(0i32, name, AF_INET, 0u64),
        )?;
        let (addrs, _canonical, _flags): ResolveReply =
            m.body().deserialize().map_err(|e| NetError::Bus(e.to_string()))?;
        Ok(addrs
            .into_iter()
            .filter_map(|(_, family, bytes)| ip_from(family, &bytes))
            .collect())
    }
}

/// Link `DNSEx` entries are `(family, address, port, name)` without ifindex.
fn parse_dns_ex_link(v: &Value<'_>) -> Vec<IpAddr> {
    let Value::Array(arr) = unwrap_variant(v) else { return vec![] };
    arr.inner()
        .iter()
        .filter_map(|e| {
            let Value::Structure(s) = unwrap_variant(e) else { return None };
            let f = s.fields();
            let family = as_i32(f.first()?)?;
            let addr = as_bytes(f.get(1)?)?;
            ip_from(family, &addr)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(entries: Vec<(&str, OwnedValue)>) -> Dict {
        entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    fn sample_settings() -> Settings {
        let mut s = Settings::new();
        s.insert(
            "connection".into(),
            dict(vec![
                ("id", ov("Redwood")),
                ("uuid", ov("21307067-f47b-43ea-8c9c-2c746454b2bb")),
                ("type", ov("802-11-wireless")),
                ("autoconnect", ov(true)),
                ("timestamp", ov(1_700_000_000u64)),
            ]),
        );
        s.insert(
            "802-11-wireless".into(),
            dict(vec![("ssid", ov(b"Redwood".to_vec()))]),
        );
        s.insert(
            "ipv4".into(),
            dict(vec![
                ("method", ov("auto")),
                ("dns", ov(vec![u32::from_ne_bytes([192, 168, 1, 153])])),
                ("ignore-auto-dns", ov(true)),
            ]),
        );
        s.insert(
            "ipv6".into(),
            dict(vec![("method", ov("auto")), ("ignore-auto-dns", ov(true))]),
        );
        s
    }

    #[test]
    fn parses_profile_and_dns() {
        let p = parse_profile("/p/1", &sample_settings()).unwrap();
        assert_eq!(p.id, "Redwood");
        assert_eq!(p.kind, ProfileKind::Wifi);
        assert_eq!(p.ssid.as_deref(), Some(&b"Redwood"[..]));
        assert_eq!(p.dns.v4_dns, vec![Ipv4Addr::new(192, 168, 1, 153)]);
        assert!(p.dns.v4_ignore_auto && p.dns.v6_ignore_auto);
        assert!(p.dns.v6_dns.is_empty());
        assert_eq!(p.timestamp, 1_700_000_000);
    }

    #[test]
    fn profile_without_uuid_is_skipped() {
        let mut s = sample_settings();
        s.get_mut("connection").unwrap().remove("uuid");
        assert!(parse_profile("/p/1", &s).is_none());
    }

    #[test]
    fn ethernet_with_missing_sections_defaults_to_auto() {
        let mut s = Settings::new();
        s.insert(
            "connection".into(),
            dict(vec![
                ("id", ov("Wired connection 1")),
                ("uuid", ov("f5520df2-a482-3ff6-a770-64b74a740967")),
                ("type", ov("802-3-ethernet")),
            ]),
        );
        let p = parse_profile("/p/2", &s).unwrap();
        assert_eq!(p.kind, ProfileKind::Ethernet);
        assert!(p.dns.is_automatic());
        assert_eq!(p.dns.v4_method, "auto");
    }

    #[test]
    fn dns_data_is_read_when_dns_is_empty() {
        let mut s = sample_settings();
        let v4 = s.get_mut("ipv4").unwrap();
        v4.remove("dns");
        v4.insert("dns-data".into(), ov(vec!["9.9.9.9#dns.quad9.net".to_string(), "1.1.1.1".to_string()]));
        let d = parse_dns_settings(&s);
        assert_eq!(d.v4_dns, vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)]);
    }

    #[test]
    fn apply_dns_roundtrips_and_drops_dns_data() {
        let mut s = sample_settings();
        s.get_mut("ipv4")
            .unwrap()
            .insert("dns-data".into(), ov(vec!["192.168.1.153".to_string()]));
        let pi: IpAddr = "192.168.1.153".parse().unwrap();
        let auto = parse_dns_settings(&s).automatic();
        apply_dns_settings(&mut s, &auto);
        assert!(!s["ipv4"].contains_key("dns-data"));
        let back = parse_dns_settings(&s);
        assert!(back.is_automatic());
        assert_eq!(back.v4_method, "auto");

        let pinned = back.pinned_to(pi);
        apply_dns_settings(&mut s, &pinned);
        assert_eq!(parse_dns_settings(&s), pinned);
        // Other sections are untouched.
        assert!(s.contains_key("802-11-wireless"));
        assert!(s["connection"].contains_key("uuid"));
    }

    #[test]
    fn ipv6_dns_roundtrip() {
        let mut s = sample_settings();
        let mut d = parse_dns_settings(&s);
        d.v6_dns = vec!["2001:4860:4860::8888".parse().unwrap()];
        apply_dns_settings(&mut s, &d);
        assert_eq!(parse_dns_settings(&s).v6_dns, d.v6_dns);
    }

    #[test]
    fn dns_ex_parsing() {
        use zbus::zvariant::StructureBuilder;
        let s1 = StructureBuilder::new()
            .add_field(4i32)
            .add_field(2i32)
            .add_field(vec![192u8, 168, 1, 153])
            .add_field(0u16)
            .add_field("")
            .build()
            .unwrap();
        let v6 = StructureBuilder::new()
            .add_field(0i32)
            .add_field(10i32)
            .add_field(vec![0x26u8, 0x20, 0, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09])
            .add_field(0u16)
            .add_field("dns.quad9.net")
            .build()
            .unwrap();
        let arr = Value::from(vec![Value::Structure(s1), Value::Structure(v6)]);
        let got = parse_dns_ex(&arr);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], (4, "192.168.1.153".parse().unwrap()));
        assert_eq!(got[1].0, 0);
        assert!(got[1].1.is_ipv6());
    }

    #[test]
    fn global_current_server_needs_ifindex_zero() {
        use zbus::zvariant::StructureBuilder;
        let mk = |ifx: i32| {
            Value::Structure(
                StructureBuilder::new()
                    .add_field(ifx)
                    .add_field(2i32)
                    .add_field(vec![9u8, 9, 9, 9])
                    .add_field(0u16)
                    .add_field("dns.quad9.net".to_string())
                    .build()
                    .unwrap(),
            )
        };
        assert_eq!(parse_global_current(&mk(0)), Some("9.9.9.9".parse().unwrap()));
        assert_eq!(parse_global_current(&mk(4)), None, "a link's server is not a global one");
        assert_eq!(parse_global_current(&Value::from(3u32)), None);
    }

    #[test]
    fn activation_reason_mapping() {
        assert!(matches!(activation_error(Some(7)), NetError::Activation { auth: true, .. }));
        assert!(matches!(activation_error(Some(11)), NetError::Activation { auth: true, .. }));
        assert!(matches!(activation_error(Some(5)), NetError::Activation { auth: false, .. }));
        assert!(matches!(activation_error(None), NetError::Activation { auth: false, .. }));
    }

    #[test]
    fn root_route_detection() {
        use zbus::zvariant::StructureBuilder;
        fn dom(d: &str, r: bool) -> Value<'static> {
            Value::Structure(
                StructureBuilder::new()
                    .add_field(d.to_string())
                    .add_field(r)
                    .build()
                    .unwrap(),
            )
        }
        assert!(has_root_route(&Value::from(vec![dom("~.", true)])));
        assert!(has_root_route(&Value::from(vec![dom(".", true)])));
        assert!(!has_root_route(&Value::from(vec![dom("lan", false)])));
    }
}
