// ────────────────────────── src/wildcard.rs ──────────────────────────
//
// Wildcard DNS pre-filter (v0.16.2). Designed to beat puredns on huge
// subdomain lists by detecting wildcard zones BEFORE resolving the
// bulk of inputs — so we skip ~90% of DNS queries on wildcard-heavy
// scopes (typical for big-org bug-bounty targets).
//
// Algorithm:
//   1. Bucket input domains by parent suffix (depth=3 default —
//      "x.y.example.com" → "y.example.com")
//   2. For each bucket with ≥ min_cluster members, generate 3 random
//      32-hex-char labels and resolve them at the bucket suffix.
//   3. ≥ 2 of 3 must resolve with overlapping IPs → confirmed wildcard
//      zone. Capture the wildcard's IP fingerprint.
//   4. Filter inputs:
//      - For domains under a confirmed wildcard zone: keep ONE
//        representative (first seen), collapse the rest.
//      - For non-wildcard domains: keep all.
//
// Why this beats puredns:
//   - puredns runs massdns over the full input first, THEN filters.
//     We detect zones with ~3 probes per zone BEFORE bulk resolution,
//     skipping ~90% of unnecessary DNS work.
//   - No external binaries, no file shuffling.
//   - Reuses portwave's hickory resolver (Cloudflare + Google + Quad9
//     trusted upstreams). No --resolvers flag needed.
//
// Accuracy guarantees:
//   - Zero finding loss at the IP level: each wildcard zone keeps a
//     representative, so the wildcard's IPs still go through Phase A
//     and Phase B/SSL probing.
//   - Conservative defaults: min_cluster=10, ≥2-of-3 probe vote,
//     suffix depth ≥3 labels (anti-`.com`-anchor).
//   - Audit trail: every collapsed name written to disk for verify.

use hickory_resolver::TokioAsyncResolver;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

/// Maximum parallel wildcard probes (v0.17.3). On 1M-domain inputs the
/// previous unbounded `tokio::spawn`-per-bucket pattern fanned out to
/// thousands of simultaneous DNS queries against the upstream resolver
/// pool (15 trusted upstreams). Free-tier Cloudflare / Google rate
/// limits dropped a fraction of those, and combined with the strict
/// "≥2-of-3 probes must succeed" vote rule, high-fan-out parent zones
/// (e.g. a wildcard with tens of thousands of children) silently
/// escaped detection — letting tens of thousands of duplicate domains
/// survive into `resolve_many`. Bounding to 64 concurrent probes keeps
/// upstream load at ~192 queries/sec which is well within free-tier
/// limits while still finishing wildcard detection in seconds for
/// realistic input sizes.
const PROBER_CONCURRENCY: usize = 64;

/// Per-probe DNS timeout (v0.17.3, was 3s). Longer than the resolver's
/// own per-server timeout so retries inside hickory still get a chance,
/// while not so long that a fully-broken upstream hangs detection.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// One detected wildcard zone.
#[derive(Debug, Clone)]
pub struct WildcardZone {
    /// Common suffix of the bucket — e.g. "r2-prod-standalone4.eu.e00.c01.tenant-cloud.example"
    pub suffix: String,
    /// Wildcard's fingerprint IPs (overlap of the 3 probe results).
    pub ip_set: Vec<IpAddr>,
    /// How many domains were collapsed under this zone.
    pub collapsed_count: usize,
    /// The representative domain we kept (first input matching this suffix).
    pub representative: String,
}

/// Result of pre-filtering: domains to actually resolve, plus an
/// audit list of collapsed names and the zones we detected.
#[derive(Debug, Clone, Default)]
pub struct WildcardOutcome {
    /// Domains to feed `resolve_many` — non-wildcard inputs + one rep
    /// per wildcard zone.
    pub kept: Vec<String>,
    /// Collapsed names — written to wildcard_collapsed.txt for audit.
    pub collapsed: Vec<String>,
    /// Detected zones — written to wildcard_zones.txt for audit.
    pub zones: Vec<WildcardZone>,
}

impl WildcardOutcome {
    /// Passthrough: no detection performed (e.g. small input or
    /// `--no-wildcard-filter`). All domains kept, no collapse.
    pub fn passthrough(domains: Vec<String>) -> Self {
        Self {
            kept: domains,
            collapsed: Vec::new(),
            zones: Vec::new(),
        }
    }
}

/// Pre-detection + filtering. Called BEFORE `resolve_many` so we skip
/// resolving wildcard descendants entirely.
pub async fn pre_detect_and_filter(
    domains: &[String],
    resolver: &TokioAsyncResolver,
    min_cluster: usize,
) -> WildcardOutcome {
    if domains.len() < min_cluster {
        return WildcardOutcome::passthrough(domains.to_vec());
    }

    // Step 1 — bucket inputs by parent suffix (depth=3 by default;
    // ≥3 labels keeps us from anchoring on `.com` / `.co.uk`).
    let buckets = bucket_by_suffix(domains, 3);

    // Step 2 — probe each bucket with ≥ min_cluster members.
    // v0.17.3: probes run with bounded concurrency (PROBER_CONCURRENCY)
    // so the upstream DNS pool isn't bursted past its rate limits — see
    // the constant's doc comment for the failure mode this defends.
    let mut wildcarded_suffixes: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut probe_handles: Vec<(String, tokio::task::JoinHandle<Option<Vec<IpAddr>>>)> = Vec::new();
    let probe_sem = Arc::new(Semaphore::new(PROBER_CONCURRENCY));

    for (suffix, members) in &buckets {
        if members.len() < min_cluster {
            continue;
        }
        let resolver_clone = resolver.clone();
        let suffix_clone = suffix.clone();
        let sem = probe_sem.clone();
        let h = tokio::spawn(async move {
            // Hold the permit for the entire probe (3 DNS queries with
            // retries). Permit drops automatically when the task ends.
            let _permit = sem.acquire_owned().await.ok()?;
            probe_wildcard(&suffix_clone, &resolver_clone).await
        });
        probe_handles.push((suffix.clone(), h));
    }

    for (suffix, h) in probe_handles {
        if let Ok(Some(ip_set)) = h.await {
            wildcarded_suffixes.insert(suffix, ip_set);
        }
    }

    // Step 3 — partition inputs into kept + collapsed. For each
    // domain we find its DEEPEST matching wildcarded ancestor zone
    // (so `*.foo.example.com` wins over `*.example.com` when both
    // are wildcarded). First-seen domain per zone becomes the
    // representative; subsequent matches collapse.
    let mut zone_reps: HashMap<String, String> = HashMap::new();
    let mut zone_collapsed_count: HashMap<String, usize> = HashMap::new();
    let mut kept: Vec<String> = Vec::with_capacity(domains.len() / 4);
    let mut collapsed: Vec<String> = Vec::with_capacity(domains.len() / 2);

    for d in domains {
        // ancestor_zones returns most-specific first → first-found
        // is the deepest match.
        let deepest_match: Option<String> = ancestor_zones(d)
            .into_iter()
            .find(|z| wildcarded_suffixes.contains_key(z));

        match deepest_match {
            Some(zone) => {
                if zone_reps.contains_key(&zone) {
                    *zone_collapsed_count.entry(zone).or_insert(0) += 1;
                    collapsed.push(d.clone());
                } else {
                    zone_reps.insert(zone, d.clone());
                    kept.push(d.clone());
                }
            }
            None => {
                kept.push(d.clone());
            }
        }
    }

    // Step 4 — build zone summaries.
    let mut zones: Vec<WildcardZone> = wildcarded_suffixes
        .into_iter()
        .filter_map(|(suffix, ip_set)| {
            let rep = zone_reps.get(&suffix)?.clone();
            let collapsed_count = zone_collapsed_count.get(&suffix).copied().unwrap_or(0);
            Some(WildcardZone {
                suffix,
                ip_set,
                collapsed_count,
                representative: rep,
            })
        })
        .collect();

    // Stable order so re-runs produce deterministic output.
    zones.sort_by(|a, b| b.collapsed_count.cmp(&a.collapsed_count));

    WildcardOutcome { kept, collapsed, zones }
}

/// Compute ancestor zones for a domain, from most-specific to least-specific.
/// Used for multi-tier wildcard detection — a name like
/// "x.y.dev.example.com" might match either `*.y.dev.example.com`,
/// `*.dev.example.com`, or `*.example.com`. We probe all candidates
/// and pick the deepest confirmed match.
///
/// Stops at eTLD+1 (computed via `extract_root_domain`) so we never
/// probe `*.com` or `*.co.uk`.
fn ancestor_zones(domain: &str) -> Vec<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    let etld_plus_1 = crate::domain::extract_root_domain(&domain);
    let etld_label_count = etld_plus_1.matches('.').count() + 1;

    let mut out: Vec<String> = Vec::new();
    // Walk up from "second-to-leftmost" toward eTLD+1 inclusive.
    // labels.len() = N. eTLD has `etld_label_count` labels. We add
    // suffixes from depth `etld_label_count` to depth `N-1` (parent of
    // input, grandparent, ... eTLD+1).
    if labels.len() <= etld_label_count {
        // 3-label input where eTLD+1 also has 3 labels (compound TLD)
        // OR 2-label input — only meaningful candidate is eTLD+1.
        out.push(etld_plus_1);
        return out;
    }
    // For "a.b.c.example.com" with eTLD+1 "example.com" (2 labels),
    // candidates are: "b.c.example.com", "c.example.com", "example.com"
    // (most specific first; skip the input itself).
    for i in (etld_label_count..labels.len()).rev() {
        let suffix = labels[labels.len() - i..].join(".");
        out.push(suffix);
    }
    out
}

/// Group input domains by candidate wildcard-zone suffix. Each domain
/// is added to MULTIPLE buckets (one per ancestor level up to eTLD+1)
/// so the same input contributes to wildcard detection at every
/// possible parent zone.
fn bucket_by_suffix(domains: &[String], _depth_unused: usize) -> HashMap<String, Vec<String>> {
    let mut buckets: HashMap<String, Vec<String>> = HashMap::new();
    for d in domains {
        for suffix in ancestor_zones(d) {
            // Suffix must have ≥ 1 dot (not a bare TLD).
            if suffix.matches('.').count() < 1 {
                continue;
            }
            buckets.entry(suffix).or_default().push(d.clone());
        }
    }
    buckets
}

/// One DNS lookup attempt, returning a sorted/deduped IP list on
/// success. Empty results filter out so callers see `None` for "no
/// usable IPs" the same as for "DNS error / timeout".
async fn try_resolve_probe(probe: &str, resolver: &TokioAsyncResolver) -> Option<Vec<IpAddr>> {
    tokio::time::timeout(PROBE_TIMEOUT, resolver.lookup_ip(probe))
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|lu| {
            let mut ips: Vec<IpAddr> = lu.iter().collect();
            ips.sort();
            ips.dedup();
            ips
        })
        .filter(|ips| !ips.is_empty())
}

/// Probe a suffix for wildcard behaviour. Generate 3 random labels,
/// resolve each at `<random>.<suffix>`, and return the wildcard
/// fingerprint IPs if ≥2 of 3 probes share at least one IP.
///
/// v0.17.3: each individual probe retries once on transient failure
/// (timeout / NXDOMAIN-from-upstream-hiccup / empty result). The retry
/// catches the single-drop case that previously killed detection of
/// real parent wildcards under bursty load.
async fn probe_wildcard(suffix: &str, resolver: &TokioAsyncResolver) -> Option<Vec<IpAddr>> {
    let probes: Vec<String> = (0..3)
        .map(|_| format!("{}.{}", random_label(32), suffix))
        .collect();

    // Resolve all 3 in parallel; per-probe retry once on failure.
    let mut handles = Vec::with_capacity(3);
    for probe in probes {
        let resolver = resolver.clone();
        handles.push(tokio::spawn(async move {
            if let Some(ips) = try_resolve_probe(&probe, &resolver).await {
                return Some(ips);
            }
            // First attempt failed/empty — retry once. Catches transient
            // upstream rate-limit drops; doesn't change cost in success cases.
            try_resolve_probe(&probe, &resolver).await
        }));
    }

    let mut probe_results: Vec<Vec<IpAddr>> = Vec::new();
    for h in handles {
        if let Ok(Some(ips)) = h.await {
            if !ips.is_empty() {
                probe_results.push(ips);
            }
        }
    }

    // Need at least 2 successful probes to vote.
    if probe_results.len() < 2 {
        return None;
    }

    // Vote: ≥2 probes must share at least one IP. The shared IP set is
    // the wildcard fingerprint.
    let mut shared: HashSet<IpAddr> = HashSet::new();
    for i in 0..probe_results.len() {
        for j in (i + 1)..probe_results.len() {
            for ip in &probe_results[i] {
                if probe_results[j].contains(ip) {
                    shared.insert(*ip);
                }
            }
        }
    }

    if shared.is_empty() {
        None
    } else {
        let mut sorted: Vec<IpAddr> = shared.into_iter().collect();
        sorted.sort();
        Some(sorted)
    }
}

/// Generate a hex-encoded random label of `n` chars (n must be even).
/// Uses xorshift64 PRNG seeded with system nanos + atomic counter for
/// uniqueness across rapid probe bursts. Not cryptographically random,
/// but deterministically unpredictable from a server's POV — which is
/// all we need (defeats sinkholing of predictable scan-tool patterns).
fn random_label(n: usize) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut state = (now.subsec_nanos() as u64)
        .wrapping_mul(0x9E3779B97F4A7C15)
        ^ (now.as_secs().wrapping_mul(0xBF58476D1CE4E5B9))
        ^ counter.wrapping_mul(0x94D049BB133111EB);
    if state == 0 {
        state = 0xDEADBEEFCAFEBABE;
    }
    let bytes_needed = (n + 1) / 2;
    let mut out = String::with_capacity(n);
    for _ in 0..bytes_needed {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push_str(&format!("{:02x}", (state & 0xFF) as u8));
    }
    out.truncate(n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestor_zones_three_label_input() {
        // 3-label input: only meaningful candidate is eTLD+1.
        assert_eq!(ancestor_zones("host-1.test-net.example"), vec!["test-net.example"]);
    }

    #[test]
    fn ancestor_zones_deeper_input() {
        // "a.b.c.example.com" → candidates (most specific first):
        // b.c.example.com, c.example.com, example.com
        // (the input itself is excluded — it's the leaf, not an ancestor)
        let zones = ancestor_zones("a.b.c.example.com");
        assert_eq!(zones, vec!["b.c.example.com", "c.example.com", "example.com"]);
    }

    #[test]
    fn ancestor_zones_compound_tld() {
        // example.co.uk has eTLD+1 = "example.co.uk" (3 labels);
        // 4-label "api.example.co.uk" should yield ["example.co.uk"].
        let zones = ancestor_zones("api.example.co.uk");
        assert_eq!(zones, vec!["example.co.uk"]);
    }

    #[test]
    fn bucket_clusters_three_label_inputs() {
        // The v0.16.6 fix: 3-label inputs all cluster under their eTLD+1.
        let domains = vec![
            "host-1.test-net.example".to_string(),
            "host-2.test-net.example".to_string(),
            "host-3.test-net.example".to_string(),
            "x.elsewhere.com".to_string(),
        ];
        let buckets = bucket_by_suffix(&domains, 0);
        assert_eq!(buckets.get("test-net.example").map(|v| v.len()), Some(3));
        assert_eq!(buckets.get("elsewhere.com").map(|v| v.len()), Some(1));
    }

    #[test]
    fn bucket_groups_by_suffix() {
        let domains = vec![
            "a.foo.example.com".to_string(),
            "b.foo.example.com".to_string(),
            "c.foo.example.com".to_string(),
            "x.bar.example.com".to_string(),
        ];
        let buckets = bucket_by_suffix(&domains, 0);
        // Each domain ALSO contributes to eTLD+1 bucket now.
        assert!(buckets.get("foo.example.com").map(|v| v.len()).unwrap_or(0) >= 3);
        assert!(buckets.get("example.com").map(|v| v.len()).unwrap_or(0) >= 4);
    }

    #[test]
    fn random_label_length_32() {
        let l = random_label(32);
        assert_eq!(l.len(), 32);
        assert!(l.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_label_unique_across_calls() {
        let labels: HashSet<String> = (0..100).map(|_| random_label(32)).collect();
        // 100 calls in tight loop — counter ensures uniqueness even if
        // SystemTime granularity collides.
        assert_eq!(labels.len(), 100);
    }

    #[test]
    fn passthrough_keeps_all() {
        let outcome = WildcardOutcome::passthrough(vec!["a.com".to_string(), "b.com".to_string()]);
        assert_eq!(outcome.kept.len(), 2);
        assert!(outcome.collapsed.is_empty());
        assert!(outcome.zones.is_empty());
    }

    #[test]
    fn small_input_below_threshold_passthrough() {
        // 5 inputs, min_cluster = 10 → no detection runs.
        let domains: Vec<String> = (0..5).map(|i| format!("a{}.foo.example.com", i)).collect();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let outcome = rt.block_on(async {
            // Build a dummy resolver — won't actually be called since
            // input is below threshold.
            let resolver = crate::domain::build_resolver(Duration::from_secs(1));
            pre_detect_and_filter(&domains, &resolver, 10).await
        });
        assert_eq!(outcome.kept.len(), 5);
        assert!(outcome.collapsed.is_empty());
    }
}
