//! `~/.config/qnet/config.toml` and the Pi-hole app password in the keyring.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::util;

pub const DEFAULT_CANARY: &str = "doubleclick.net";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    Router,
    Quad9,
    Cloudflare,
}

impl Fallback {
    pub fn as_str(self) -> &'static str {
        match self {
            Fallback::Router => "router",
            Fallback::Quad9 => "quad9",
            Fallback::Cloudflare => "cloudflare",
        }
    }

    /// IPv4 servers to run while failed over. `router` needs the gateway.
    pub fn servers(self, gateway: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
        match self {
            Fallback::Router => gateway.into_iter().collect(),
            Fallback::Quad9 => vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
            Fallback::Cloudflare => vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiholeCfg {
    pub address: IpAddr,
    pub tls_sha256: [u8; 32],
    pub canary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverCfg {
    pub enabled: bool,
    pub fallback: Fallback,
}

impl Default for FailoverCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            fallback: Fallback::Router,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub pihole: Option<PiholeCfg>,
    pub failover: FailoverCfg,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawConfig {
    pihole: Option<RawPihole>,
    failover: Option<RawFailover>,
}

#[derive(Deserialize)]
struct RawPihole {
    address: String,
    tls_sha256: String,
    canary: Option<String>,
}

#[derive(Deserialize)]
struct RawFailover {
    enabled: Option<bool>,
    fallback: Option<String>,
}

pub fn parse(text: &str) -> Result<Config, String> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| format!("config.toml: {}", e.message()))?;
    let pihole = match raw.pihole {
        None => None,
        Some(p) => {
            let address: IpAddr = p
                .address
                .trim()
                .parse()
                .map_err(|_| "config.toml: pihole.address must be an IP address".to_string())?;
            let tls_sha256 = util::parse_fingerprint(&p.tls_sha256)
                .ok_or_else(|| "config.toml: pihole.tls_sha256 must be a SHA-256 fingerprint".to_string())?;
            let canary = p.canary.unwrap_or_else(|| DEFAULT_CANARY.to_string());
            if !util::valid_dns_name(&canary) {
                return Err("config.toml: pihole.canary is not a valid host name".into());
            }
            Some(PiholeCfg {
                address,
                tls_sha256,
                canary,
            })
        }
    };
    let mut failover = FailoverCfg::default();
    if let Some(f) = raw.failover {
        if let Some(e) = f.enabled {
            failover.enabled = e;
        }
        if let Some(fb) = f.fallback {
            failover.fallback = match fb.as_str() {
                "router" => Fallback::Router,
                "quad9" => Fallback::Quad9,
                "cloudflare" => Fallback::Cloudflare,
                _ => return Err("config.toml: failover.fallback must be router, quad9 or cloudflare".into()),
            };
        }
    }
    Ok(Config { pihole, failover })
}

/// Load the config. A missing file is the empty config, not an error.
pub fn load(path: &Path) -> Result<Config, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => parse(&t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(format!("config.toml: {e}")),
    }
}

/// Write the `[pihole]` table, keeping everything else in the file. A fresh
/// file also gets the default `[failover]` table.
pub fn save_pihole(
    path: &Path,
    address: IpAddr,
    tls_sha256: &[u8; 32],
    canary: Option<&str>,
) -> Result<(), String> {
    let mut doc: toml::Table = match std::fs::read_to_string(path) {
        Ok(t) => t.parse().map_err(|e: toml::de::Error| format!("config.toml: {}", e.message()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("config.toml: {e}")),
    };
    let mut pi = match doc.remove("pihole") {
        Some(toml::Value::Table(t)) => t,
        _ => toml::Table::new(),
    };
    pi.insert("address".into(), toml::Value::String(address.to_string()));
    pi.insert(
        "tls_sha256".into(),
        toml::Value::String(util::format_fingerprint(tls_sha256)),
    );
    if !pi.contains_key("canary") {
        pi.insert(
            "canary".into(),
            toml::Value::String(canary.unwrap_or(DEFAULT_CANARY).to_string()),
        );
    }
    doc.insert("pihole".into(), toml::Value::Table(pi));
    if !doc.contains_key("failover") {
        let mut f = toml::Table::new();
        f.insert("enabled".into(), toml::Value::Boolean(true));
        f.insert("fallback".into(), toml::Value::String("router".into()));
        doc.insert("failover".into(), toml::Value::Table(f));
    }
    let text = toml::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    util::atomic_write(path, text.as_bytes(), 0o600).map_err(|e| format!("config.toml: {e}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// Nothing stored (or the keyring is locked / unavailable).
    Missing(String),
    Failed(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::Missing(s) | SecretError::Failed(s) => write!(f, "{s}"),
        }
    }
}

const SECRET_TIMEOUT: Duration = Duration::from_secs(10);

/// Dev-only: read the web password from the file named by
/// `QNET_DEV_PIHOLE_PASSWORD_FILE`. Compiled into debug builds only, so the
/// installed (release) binary cannot be pointed at a plaintext password.
#[cfg(debug_assertions)]
fn dev_password() -> Option<String> {
    let p = std::env::var_os("QNET_DEV_PIHOLE_PASSWORD_FILE")?;
    let t = std::fs::read_to_string(p).ok()?;
    Some(t.trim_end_matches(['\n', '\r']).to_string())
}

#[cfg(not(debug_assertions))]
fn dev_password() -> Option<String> {
    None
}

/// The Pi-hole app password from the Secret Service. The secret comes back
/// on stdout; it is never passed on a command line.
pub fn lookup_password(address: IpAddr) -> Result<Zeroizing<String>, SecretError> {
    if let Some(p) = dev_password() {
        return Ok(Zeroizing::new(p));
    }
    let addr = address.to_string();
    let out = crate::proc::run(
        "secret-tool",
        &["lookup", "service", "qnet", "pihole", &addr],
        None,
        SECRET_TIMEOUT,
        4096,
    )
    .map_err(|e| SecretError::Failed(format!("secret-tool: {e}")))?;
    if out.timed_out {
        return Err(SecretError::Failed("keyring did not answer".into()));
    }
    if !out.success() || out.stdout.is_empty() {
        return Err(SecretError::Missing("no app password in the keyring".into()));
    }
    let s = std::str::from_utf8(&out.stdout).map_err(|_| SecretError::Failed("secret is not UTF-8".into()))?;
    Ok(Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_string()))
}

/// Store the app password; the secret is written to `secret-tool` on stdin.
pub fn store_password(address: IpAddr, secret: &str) -> Result<(), SecretError> {
    let addr = address.to_string();
    let label = format!("qnet Pi-hole {addr}");
    let out = crate::proc::run(
        "secret-tool",
        &["store", "--label", &label, "service", "qnet", "pihole", &addr],
        Some(secret.as_bytes()),
        SECRET_TIMEOUT,
        4096,
    )
    .map_err(|e| SecretError::Failed(format!("secret-tool: {e}")))?;
    if out.success() {
        Ok(())
    } else {
        Err(SecretError::Failed("could not store the secret in the keyring".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "71:C7:1F:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:01:23:45:67:89:AB:CD:EF:10:32:54:76:F4";

    #[test]
    fn spec_example_parses() {
        let t = format!(
            "[pihole]\naddress = \"192.168.1.153\"\ntls_sha256 = \"{FP}\"\ncanary = \"doubleclick.net\"\n[failover]\nenabled = true\nfallback = \"router\"\n"
        );
        let c = parse(&t).unwrap();
        let p = c.pihole.unwrap();
        assert_eq!(p.address, "192.168.1.153".parse::<IpAddr>().unwrap());
        assert_eq!(p.canary, "doubleclick.net");
        assert_eq!(util::format_fingerprint(&p.tls_sha256), FP);
        assert_eq!(c.failover, FailoverCfg { enabled: true, fallback: Fallback::Router });
    }

    #[test]
    fn defaults_and_missing_sections() {
        assert_eq!(parse("").unwrap(), Config::default());
        let t = format!("[pihole]\naddress = \"10.0.0.2\"\ntls_sha256 = \"{FP}\"\n");
        let c = parse(&t).unwrap();
        assert_eq!(c.pihole.unwrap().canary, DEFAULT_CANARY);
        assert!(c.failover.enabled);
        let t = "[failover]\nenabled = false\nfallback = \"quad9\"\n";
        let c = parse(t).unwrap();
        assert!(!c.failover.enabled);
        assert_eq!(c.failover.fallback, Fallback::Quad9);
    }

    #[test]
    fn rejects_bad_values() {
        let bad_addr = format!("[pihole]\naddress = \"pi.hole\"\ntls_sha256 = \"{FP}\"\n");
        assert!(parse(&bad_addr).unwrap_err().contains("IP address"));
        let bad_fp = "[pihole]\naddress = \"10.0.0.2\"\ntls_sha256 = \"abc\"\n";
        assert!(parse(bad_fp).unwrap_err().contains("SHA-256"));
        let bad_canary = format!("[pihole]\naddress = \"10.0.0.2\"\ntls_sha256 = \"{FP}\"\ncanary = \"a b\"\n");
        assert!(parse(&bad_canary).unwrap_err().contains("canary"));
        assert!(parse("[failover]\nfallback = \"evil\"\n").is_err());
        assert!(parse("this is not toml").is_err());
    }

    #[test]
    fn fallback_servers() {
        let gw = Some(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Fallback::Router.servers(gw), vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert!(Fallback::Router.servers(None).is_empty());
        assert_eq!(Fallback::Quad9.servers(None)[0], Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(Fallback::Cloudflare.servers(None)[0], Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn save_roundtrip_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("config.toml");
        let fp = util::parse_fingerprint(FP).unwrap();
        save_pihole(&p, "192.168.1.153".parse().unwrap(), &fp, None).unwrap();
        let c = load(&p).unwrap();
        assert_eq!(c.pihole.as_ref().unwrap().canary, DEFAULT_CANARY);
        assert!(c.failover.enabled);

        // Hand-edit: custom canary + failover choice, then re-run setup.
        let mut text = std::fs::read_to_string(&p).unwrap();
        text = text.replace("doubleclick.net", "ads.example.com").replace("router", "quad9");
        std::fs::write(&p, text).unwrap();
        let fp2 = [7u8; 32];
        save_pihole(&p, "192.168.1.200".parse().unwrap(), &fp2, None).unwrap();
        let c = load(&p).unwrap();
        let pi = c.pihole.unwrap();
        assert_eq!(pi.address, "192.168.1.200".parse::<IpAddr>().unwrap());
        assert_eq!(pi.tls_sha256, fp2);
        assert_eq!(pi.canary, "ads.example.com");
        assert_eq!(c.failover.fallback, Fallback::Quad9);
    }

    #[test]
    fn missing_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&dir.path().join("nope.toml")).unwrap(), Config::default());
    }
}
