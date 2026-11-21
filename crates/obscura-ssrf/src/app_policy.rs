//! Optional, expiring exact-origin grants issued by the workspace gateway.
//! This never enables general private-network access. Internal names are pinned
//! to policy addresses without DNS, and every request rechecks the live policy.
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    sync::{Mutex, OnceLock},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;

#[derive(Deserialize)]
struct Policy {
    version: u32,
    installation: u64,
    expires: String,
    targets: Vec<Target>,
}
#[derive(Deserialize)]
struct Target {
    id: u64,
    origin: String,
    addresses: Vec<IpAddr>,
}

fn addresses(data: &[u8], host: &str, now: OffsetDateTime) -> Result<Vec<SocketAddr>, String> {
    let policy: Policy = serde_json::from_slice(data).map_err(|_| "invalid app policy")?;
    let expires = OffsetDateTime::parse(&policy.expires, &Rfc3339)
        .map_err(|_| "invalid app policy expiry")?;
    if policy.version != 1
        || policy.installation == 0
        || expires <= now
        || expires > now + time::Duration::seconds(90)
    {
        return Err("invalid or expired app policy".into());
    }
    let origin = format!("https://{host}");
    let target = policy
        .targets
        .iter()
        .find(|t| t.origin == origin && t.id > 0)
        .ok_or("app origin not granted")?;
    if target.addresses.is_empty() || target.addresses.len() > 16 {
        return Err("invalid app gateway addresses".into());
    }
    // Only gateway addresses explicitly supplied by the trusted mount qualify.
    // Loopback, metadata/link-local, unspecified and multicast remain forbidden.
    if target.addresses.iter().any(|ip| match ip {
        IpAddr::V4(ip) => !ip.is_private(),
        IpAddr::V6(ip) => !ip.is_unique_local(),
    }) {
        return Err("invalid app gateway address".into());
    }
    Ok(target
        .addresses
        .iter()
        .map(|ip| SocketAddr::new(*ip, 0))
        .collect())
}

/// None means ordinary public DNS rules apply. A valid exact-origin grant
/// pins gateway addresses without consulting DNS; expired matched grants fail.
/// Missing/malformed policy never grants a private-network exception.
pub fn resolve_app(host: &str) -> Option<Result<Vec<SocketAddr>, String>> {
    // Remember granted names for this browser process so a removed/corrupt
    // policy cannot fall back to a pooled connection opened under an old grant.
    static KNOWN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let mut known = KNOWN
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let loaded = (|| {
        let path = std::env::var("TARVIS_APP_NETWORK_POLICY").ok()?;
        let mut data = Vec::new();
        File::open(path)
            .ok()?
            .take(1_048_577)
            .read_to_end(&mut data)
            .ok()?;
        if data.len() > 1_048_576 {
            return None;
        }
        let policy: Policy = serde_json::from_slice(&data).ok()?;
        let origin = format!("https://{host}");
        if !policy.targets.iter().any(|target| target.origin == origin) {
            return None;
        }
        Some(data)
    })();
    if let Some(data) = loaded {
        known.insert(host.to_string());
        return Some(addresses(&data, host, OffsetDateTime::now_utc()));
    }
    known
        .contains(host)
        .then(|| Err("app grant unavailable".into()))
}

fn validate_granted_url(url: &Url) -> Result<(), String> {
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("app access requires a granted HTTPS origin".into());
    }
    Ok(())
}

/// Rechecked before requests and redirects, including pooled connections.
/// Unlisted URLs retain the transport's ordinary DNS and SSRF enforcement.
pub fn validate_app_url(url: &Url) -> Result<(), String> {
    let Some(host) = url.host_str() else {
        return Ok(());
    };
    let Some(grant) = resolve_app(host) else {
        return Ok(());
    };
    validate_granted_url(url)?;
    grant.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(expires: OffsetDateTime, origin: &str, ip: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"version":1,"installation":7,"expires":expires.format(&Rfc3339).unwrap(),"targets":[{"id":8,"origin":origin,"addresses":[ip]}]})).unwrap()
    }
    #[test]
    fn exact_origin_and_gateway_only() {
        let now = OffsetDateTime::now_utc();
        let data = policy(
            now + time::Duration::seconds(45),
            "https://treg.ray.example.com",
            "10.89.0.1",
        );
        assert_eq!(
            addresses(&data, "treg.ray.example.com", now).unwrap(),
            vec!["10.89.0.1:0".parse::<SocketAddr>().unwrap()]
        );
        for host in [
            "other.ray.example.com",
            "treg.ray.example.com.",
            "treg.ray.example.com.evil",
            "10.89.0.1",
        ] {
            assert!(addresses(&data, host, now).is_err());
        }
    }
    #[test]
    fn stale_missing_malformed_or_unsafe_fail_closed() {
        let now = OffsetDateTime::now_utc();
        for delta in [-1, 0, 91] {
            assert!(addresses(
                &policy(
                    now + time::Duration::seconds(delta),
                    "https://treg.ray.example.com",
                    "10.89.0.1"
                ),
                "treg.ray.example.com",
                now
            )
            .is_err());
        }
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "::ffff:10.89.0.1",
            "8.8.8.8",
        ] {
            assert!(addresses(
                &policy(
                    now + time::Duration::seconds(45),
                    "https://treg.ray.example.com",
                    ip
                ),
                "treg.ray.example.com",
                now
            )
            .is_err());
        }
        assert!(addresses(b"{}", "treg.ray.example.com", now).is_err());
        assert!(resolve_app("example.com").is_none());
    }
    #[test]
    fn revoked_policy_cannot_reuse_a_granted_connection() {
        let path =
            std::env::temp_dir().join(format!("obscura-policy-test-{}.json", std::process::id()));
        let host = "revocation.workspace.example";
        std::fs::write(
            &path,
            policy(
                OffsetDateTime::now_utc() + time::Duration::seconds(45),
                &format!("https://{host}"),
                "10.89.0.1",
            ),
        )
        .unwrap();
        std::env::set_var("TARVIS_APP_NETWORK_POLICY", &path);
        assert!(resolve_app(host).unwrap().is_ok());
        std::fs::write(&path, b"{}").unwrap();
        assert!(resolve_app(host).unwrap().is_err());
        assert!(validate_app_url(&Url::parse(&format!("https://{host}")).unwrap()).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(resolve_app(host).unwrap().is_err());
        std::env::remove_var("TARVIS_APP_NETWORK_POLICY");
    }
    #[test]
    fn internal_non_https_and_non_default_ports_are_rejected() {
        for raw in [
            "http://treg.ray.example.com",
            "https://treg.ray.example.com:8443",
            "https://user@treg.ray.example.com",
        ] {
            assert!(validate_granted_url(&Url::parse(raw).unwrap()).is_err());
        }
    }
}
