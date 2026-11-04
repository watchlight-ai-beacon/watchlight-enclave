//! Address-level defence, applied *after* DNS and *before* the socket.
//!
//! An allowlist names hostnames, but a hostname is not a destination — DNS is.
//! Two attacks follow from that, and both are standard against forward
//! proxies:
//!
//! * **DNS rebinding / TOCTOU.** The guard resolves `api.example.com`,
//!   validates the answer, and then connects *by name again*. A resolver
//!   controlled or poisoned by the agent returns a public address for the
//!   check and a private one for the connection. The defence is structural:
//!   resolve once, validate the resulting addresses, and dial **the validated
//!   `SocketAddr`** — never the name a second time. This module exists so that
//!   ordering cannot be got wrong by accident.
//!
//! * **Cloud metadata and internal-range access.** `169.254.169.254` is the
//!   single most valuable target for an agent that has escaped its remit: it
//!   hands out instance credentials with no authentication. Loopback, RFC 1918
//!   and carrier-grade NAT ranges reach the host and its neighbours. None of
//!   them are ever a legitimate destination for a sandboxed agent, so they are
//!   refused regardless of what the allowlist says.
//!
//! The allowlist and this guard compose as AND, not OR: a destination must be
//! named *and* routable to somewhere outside the infrastructure.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an address was refused. Recorded verbatim in the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Loopback,
    Private,
    LinkLocal,
    CloudMetadata,
    Multicast,
    Unspecified,
    Reserved,
}

impl Refusal {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Loopback => "address is loopback",
            Self::Private => "address is in a private range",
            Self::LinkLocal => "address is link-local",
            Self::CloudMetadata => "address is the cloud metadata endpoint",
            Self::Multicast => "address is multicast",
            Self::Unspecified => "address is unspecified",
            Self::Reserved => "address is in a reserved range",
        }
    }
}

/// The cloud instance-metadata address, called out separately from the
/// link-local range it belongs to because it is worth naming in evidence.
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Decide whether one resolved address may be dialled.
pub fn check(addr: IpAddr) -> Result<(), Refusal> {
    match addr {
        IpAddr::V4(v4) => check_v4(v4),
        IpAddr::V6(v6) => check_v6(v6),
    }
}

fn check_v4(ip: Ipv4Addr) -> Result<(), Refusal> {
    if ip == METADATA_V4 {
        return Err(Refusal::CloudMetadata);
    }
    if ip.is_loopback() {
        return Err(Refusal::Loopback);
    }
    if ip.is_unspecified() {
        return Err(Refusal::Unspecified);
    }
    if ip.is_link_local() {
        return Err(Refusal::LinkLocal);
    }
    if ip.is_private() {
        return Err(Refusal::Private);
    }
    if ip.is_multicast() || ip.is_broadcast() {
        return Err(Refusal::Multicast);
    }
    let [a, b, ..] = ip.octets();
    // 100.64.0.0/10 carrier-grade NAT, 192.0.0.0/24 protocol assignments,
    // 198.18.0.0/15 benchmarking, 240.0.0.0/4 reserved. Each is reachable
    // infrastructure on some networks and is never an agent's destination.
    let reserved = (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0)
        || (a == 198 && (18..20).contains(&b))
        || a >= 240;
    if reserved {
        return Err(Refusal::Reserved);
    }
    Ok(())
}

fn check_v6(ip: Ipv6Addr) -> Result<(), Refusal> {
    // An IPv4-mapped address must be judged by its IPv4 rules, or ::ffff:127.0.0.1
    // walks straight past every check below.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return check_v4(v4);
    }
    if ip.is_loopback() {
        return Err(Refusal::Loopback);
    }
    if ip.is_unspecified() {
        return Err(Refusal::Unspecified);
    }
    if ip.is_multicast() {
        return Err(Refusal::Multicast);
    }
    let segments = ip.segments();
    if segments[0] & 0xffc0 == 0xfe80 {
        return Err(Refusal::LinkLocal);
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Err(Refusal::Private); // fc00::/7 unique local
    }
    // Deprecated 6to4/Teredo and the documentation range are all ways to
    // express an inner address this check would otherwise not see.
    if segments[0] == 0x2002 || (segments[0] == 0x2001 && segments[1] == 0x0000) {
        return Err(Refusal::Reserved);
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Err(Refusal::Reserved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(s: &str) -> Refusal {
        check(s.parse().unwrap()).expect_err(&format!("{s} was allowed"))
    }

    #[test]
    fn the_metadata_endpoint_is_named_specifically() {
        assert_eq!(refused("169.254.169.254"), Refusal::CloudMetadata);
    }

    #[test]
    fn loopback_is_refused() {
        assert_eq!(refused("127.0.0.1"), Refusal::Loopback);
    }

    #[test]
    fn private_ranges_are_refused() {
        for ip in ["10.0.0.1", "172.16.5.4", "192.168.1.1"] {
            assert_eq!(refused(ip), Refusal::Private, "{ip}");
        }
    }

    #[test]
    fn carrier_grade_nat_is_refused() {
        assert_eq!(refused("100.64.0.1"), Refusal::Reserved);
        // ...but 100.63 and 100.128 are ordinary public space.
        assert!(check("100.63.0.1".parse().unwrap()).is_ok());
        assert!(check("100.128.0.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_smuggle_loopback() {
        // ::ffff:127.0.0.1 is the classic way past a v4-only check.
        assert_eq!(refused("::ffff:127.0.0.1"), Refusal::Loopback);
        assert_eq!(refused("::ffff:169.254.169.254"), Refusal::CloudMetadata);
    }

    #[test]
    fn ipv6_loopback_and_unique_local_are_refused() {
        assert_eq!(refused("::1"), Refusal::Loopback);
        assert_eq!(refused("fd00::1"), Refusal::Private);
        assert_eq!(refused("fe80::1"), Refusal::LinkLocal);
    }

    #[test]
    fn six_to_four_and_teredo_are_refused() {
        assert_eq!(refused("2002::1"), Refusal::Reserved);
        assert_eq!(refused("2001::1"), Refusal::Reserved);
    }

    #[test]
    fn ordinary_public_addresses_are_allowed() {
        for ip in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(check(ip.parse().unwrap()).is_ok(), "{ip}");
        }
    }
}
