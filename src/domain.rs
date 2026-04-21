// ────────────────────────── src/domain.rs ──────────────────────────
//
// Domain / subdomain support for portwave (v0.14.0+).
//
// Responsibilities:
//   1. Classify an input line (one of CIDR, IP range, IPv4/IPv6 literal,
//      domain, or invalid) — lets a single `--input-file` hold mixed
//      content and route each line correctly.
//   2. Resolve a batch of domains to their A/AAAA records in parallel,
//      with a bounded-concurrency async pool.
//   3. Flag domains whose resolved IPs land on a known CDN edge range,
//      so the main scanner can skip them by default (no point probing
//      Cloudflare's edge when the user asked about origin.example.com).
//
// DNS resolver: `hickory-resolver` with direct UDP queries to Cloudflare
// (1.1.1.1) + Google (8.8.8.8). Faster and more predictable than the
// system resolver for bulk lookups; avoids surprises from misconfigured
// /etc/resolv.conf on scanning VPSes.
//
// Private-IP filter: A/AAAA records that point at RFC1918 / loopback /
// link-local / ULA space are dropped. These often appear in wildcard
// DNS sinkholes (e.g., `*.dev.internal → 10.0.0.1`) or misconfigured
// zones, and scanning them would either hit the scanner's own host or
// traverse the wrong network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use ipnetwork::IpNetwork;

/// One parsed entry from user input (CLI positional, `--input-file`, or
/// `--domain`). Each kind gets routed differently by `main()` — IP-ish
/// kinds go straight into the existing target-expansion path, Domain
/// kinds get resolved first.
#[derive(Debug, Clone)]
pub enum InputKind {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Cidr(IpNetwork),
    Ipv4Range(Ipv4Addr, Ipv4Addr),
    Domain(String),
    Invalid { raw: String, reason: &'static str },
}

/// Best-effort classification of one trimmed input line. Does not touch
/// the network. Order of checks matters — CIDR first (has `/`), then
/// range (`A-B` with both sides parseable), then bare IP, then domain.
pub fn classify_input_line(raw: &str) -> InputKind {
    let tok = raw.trim();
    if tok.is_empty() {
        return InputKind::Invalid {
            raw: raw.to_string(),
            reason: "empty line",
        };
    }

    // CIDR — contains `/` and parses as IpNetwork
    if tok.contains('/') {
        if let Ok(n) = tok.parse::<IpNetwork>() {
            return InputKind::Cidr(n);
        }
        // Something like `example.com/path` — treat as invalid so we
        // don't mis-classify it as a domain and send a DNS query for
        // a URL.
        return InputKind::Invalid {
            raw: tok.to_string(),
            reason: "contains '/' but isn't a valid CIDR",
        };
    }

    // IPv4 range — `A-B` where both sides parse as IPv4
    if let Some((a, b)) = tok.split_once('-') {
        let a = a.trim();
        let b = b.trim();
        // Guard: only treat as a range if BOTH halves parse — otherwise
        // `sub-domain.example.com` would incorrectly match the range arm.
        if let (Ok(IpAddr::V4(a4)), Ok(IpAddr::V4(b4))) =
            (a.parse::<IpAddr>(), b.parse::<IpAddr>())
        {
            if u32::from(a4) <= u32::from(b4) {
                return InputKind::Ipv4Range(a4, b4);
            }
            return InputKind::Invalid {
                raw: tok.to_string(),
                reason: "IPv4 range A-B has A > B",
            };
        }
    }

    // Bare IP
    if let Ok(ip) = tok.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v) => InputKind::Ipv4(v),
            IpAddr::V6(v) => InputKind::Ipv6(v),
        };
    }

    // Domain — looks plausible: contains a dot, non-empty labels, no spaces.
    // We don't try to validate against RFC 1035 beyond the minimum that
    // keeps obvious garbage out. hickory will reject truly-malformed names.
    if looks_like_domain(tok) {
        return InputKind::Domain(tok.to_ascii_lowercase());
    }

    InputKind::Invalid {
        raw: tok.to_string(),
        reason: "not a valid CIDR, IP, range, or domain",
    }
}

/// Cheap syntactic check — saves a DNS round-trip on obvious garbage.
/// We allow IDN / Unicode letters (hickory + libidn handle Punycode).
fn looks_like_domain(s: &str) -> bool {
    if s.len() < 3 || s.len() > 253 {
        return false;
    }
    if !s.contains('.') {
        return false;
    }
    if s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    if s.contains(' ') || s.contains('\t') {
        return false;
    }
    // No ".." (empty label)
    if s.contains("..") {
        return false;
    }
    // At least one label must contain an alphabetic character — rules
    // out stuff like "192.0.2.999" that failed the IP parse but is
    // still numeric.
    s.split('.').any(|label| label.chars().any(|c| c.is_alphabetic()))
}

/// One domain's resolution outcome. Returned in the same order as
/// input so callers can zip / lookup without tracking IDs.
#[derive(Debug, Clone)]
pub struct DomainResult {
    pub domain: String,
    /// A + AAAA records merged; private / reserved / sinkhole IPs
    /// already filtered out.
    pub ips: Vec<IpAddr>,
    /// First CDN provider name that matched any of `ips`. `None` if
    /// every resolved IP is a real origin (or if `ips` is empty).
    pub cdn: Option<&'static str>,
    /// Human-readable error for NXDOMAIN / timeout / other resolver
    /// failures. Empty if resolution succeeded (even with zero records —
    /// `ips.is_empty() && error.is_none()` means "domain exists but
    /// returned no usable A/AAAA").
    pub error: Option<String>,
}

/// Build a hickory resolver pointing at Cloudflare + Google upstreams
/// with the caller's timeout budget. Fresh resolver per call so state
/// (cache / in-flight) is scoped to the scan.
fn build_resolver(timeout: Duration) -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 1; // one try per A/AAAA; caller can retry at a higher level
    opts.num_concurrent_reqs = 2; // A and AAAA in parallel per domain
    opts.cache_size = 0; // scan-scoped; no reason to persist across domains

    // Cloudflare 1.1.1.1 / 1.0.0.1 + Google 8.8.8.8 / 8.8.4.4 as fallback.
    // Hickory rotates through these if the primary fails.
    let nameservers = NameServerConfigGroup::from_ips_clear(
        &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        ],
        53,
        true, // trust_negative_responses — NXDOMAIN is fatal per query
    );
    let cfg = ResolverConfig::from_parts(None, vec![], nameservers);
    TokioAsyncResolver::tokio(cfg, opts)
}

/// Drop private / loopback / link-local / ULA / sinkhole addresses from
/// a resolution result. Rejecting these prevents the scanner from
/// wasting probes on the operator's own LAN (wildcard `*.dev.internal`
/// DNS sinkholes are common in corp DNS setups).
fn keep_scannable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_documentation())
        }
        IpAddr::V6(v) => {
            let seg = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                // fc00::/7 — ULA
                || (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 — link-local
                || (seg[0] & 0xffc0) == 0xfe80
                // 2001:db8::/32 — documentation prefix
                || (seg[0] == 0x2001 && seg[1] == 0x0db8))
        }
    }
}

/// Resolve one domain — queries A and AAAA in parallel, merges results,
/// applies the private-IP filter. Returns an empty Vec (not an error)
/// if the domain exists but has no usable records.
async fn resolve_one(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> Result<Vec<IpAddr>, String> {
    let (a_res, aaaa_res) = tokio::join!(
        resolver.ipv4_lookup(domain),
        resolver.ipv6_lookup(domain),
    );

    let mut ips: Vec<IpAddr> = Vec::new();
    match a_res {
        Ok(lookup) => ips.extend(lookup.iter().map(|r| IpAddr::V4(r.0))),
        Err(e) => {
            // AAAA might still succeed, so we don't bail yet — but we do
            // record the A-side error for reporting if both sides fail.
            let aaaa_err_hint = matches!(
                e.kind(),
                hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. }
            );
            if aaaa_err_hint {
                // NoRecordsFound is benign for A; IPv6-only hosts hit this.
            } else if aaaa_res.is_err() {
                return Err(format!("{}", e));
            }
        }
    }
    if let Ok(lookup) = aaaa_res {
        ips.extend(lookup.iter().map(|r| IpAddr::V6(r.0)));
    }

    ips.retain(keep_scannable);
    ips.sort();
    ips.dedup();
    Ok(ips)
}

/// Resolve many domains in parallel with bounded concurrency, tagging
/// each result with a CDN provider name if any resolved IP lands in
/// `cdn_table`. Order of returned results matches input order.
pub async fn resolve_many(
    domains: &[String],
    concurrency: usize,
    timeout: Duration,
    cdn_table: &[(IpNetwork, &'static str)],
) -> Vec<DomainResult> {
    if domains.is_empty() {
        return Vec::new();
    }
    let resolver = build_resolver(timeout);
    let concurrency = concurrency.max(1);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

    // Spawn one task per domain, permit-gated by `sem` so at most
    // `concurrency` are in flight simultaneously. Each returns
    // `JoinHandle<(usize, DomainResult)>` — one concrete type, so
    // `FuturesUnordered` is happy.
    let mut set: FuturesUnordered<tokio::task::JoinHandle<(usize, DomainResult)>> =
        FuturesUnordered::new();

    for (idx, d) in domains.iter().enumerate() {
        let d = d.clone();
        let r = resolver.clone();
        let sem = sem.clone();
        let cdn_table: Vec<(IpNetwork, &'static str)> = cdn_table.to_vec();
        set.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let outcome = resolve_one(&r, &d).await;
            let (ips, error) = match outcome {
                Ok(v) => (v, None),
                Err(e) => (Vec::new(), Some(e)),
            };
            let cdn = ips.iter().find_map(|ip| cdn_tag_first(*ip, &cdn_table));
            (
                idx,
                DomainResult {
                    domain: d,
                    ips,
                    cdn,
                    error,
                },
            )
        }));
    }

    let mut results: Vec<Option<DomainResult>> = (0..domains.len()).map(|_| None).collect();
    while let Some(join) = set.next().await {
        if let Ok((idx, r)) = join {
            results[idx] = Some(r);
        }
    }
    results.into_iter().map(|o| o.unwrap()).collect()
}

/// Linear scan against the CDN CIDR table. Same behavior as the
/// `cdn_tag_for()` helper in main.rs — duplicated here so this module
/// has no back-reference into main. Returns the first provider match.
fn cdn_tag_first(ip: IpAddr, table: &[(IpNetwork, &'static str)]) -> Option<&'static str> {
    for (net, tag) in table {
        if net.contains(ip) {
            return Some(*tag);
        }
    }
    None
}

/// Collapse many `DomainResult`s into a compact "by CDN provider"
/// histogram, for the pre-scan summary.
pub fn cdn_breakdown(results: &[DomainResult]) -> Vec<(&'static str, usize)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<&'static str, usize> = BTreeMap::new();
    for r in results {
        if let Some(tag) = r.cdn {
            *map.entry(tag).or_insert(0) += 1;
        }
    }
    map.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ipv4() {
        assert!(matches!(
            classify_input_line("1.2.3.4"),
            InputKind::Ipv4(_)
        ));
    }

    #[test]
    fn classify_cidr() {
        assert!(matches!(
            classify_input_line("10.0.0.0/24"),
            InputKind::Cidr(_)
        ));
    }

    #[test]
    fn classify_range() {
        assert!(matches!(
            classify_input_line("1.2.3.4-1.2.3.10"),
            InputKind::Ipv4Range(_, _)
        ));
    }

    #[test]
    fn classify_domain() {
        assert!(matches!(
            classify_input_line("example.com"),
            InputKind::Domain(_)
        ));
        assert!(matches!(
            classify_input_line("sub.Example.COM"),
            InputKind::Domain(d) if d == "sub.example.com"
        ));
    }

    #[test]
    fn classify_invalid() {
        assert!(matches!(
            classify_input_line("not a target"),
            InputKind::Invalid { .. }
        ));
        assert!(matches!(
            classify_input_line("example.com/admin"),
            InputKind::Invalid { .. }
        ));
    }

    #[test]
    fn private_ip_filtered() {
        assert!(!keep_scannable(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!keep_scannable(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(keep_scannable(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
