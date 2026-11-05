//! Address-level defence, applied *after* DNS and *before* the socket.
//!
//! An allowlist names hostnames, but a hostname is not a destination — DNS is.
//! Two attacks follow from that, and both are standard against forward
//! proxies:
//!
//! * **DNS rebinding / TOCTOU.** The mistake to avoid is resolving
//!   `api.example.com`, validating the answer, and then connecting *by name a
//!   second time*: a resolver the agent controls or has poisoned can return a
//!   public address for the check and a private one for the connection. The
//!   defence is structural rather than careful — resolve once, validate the
//!   resulting addresses, and dial **the validated `SocketAddr`**. This module
//!   exists so that ordering cannot be got wrong by accident.
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
    // 0.0.0.0/8 is "this host on this network" (RFC 1122) and resolves to a
    // local interface on some stacks, so only 0.0.0.0 itself being refused
    // left 0.0.0.1-0.255.255.255 as a loopback route. The embedded-IPv4
    // branches in check_v6 made that reachable as ::2, ::0.0.0.2, 64:ff9b::2
    // and ::ffff:0.0.0.2 as well.
    let reserved = a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0)
        || (a == 198 && (18..20).contains(&b))
        || a >= 240;
    if reserved {
        return Err(Refusal::Reserved);
    }
    Ok(())
}

fn check_v6(ip: Ipv6Addr) -> Result<(), Refusal> {
    let segments = ip.segments();
    // An IPv4-mapped address must be judged by its IPv4 rules, or ::ffff:127.0.0.1
    // walks straight past every check below.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return check_v4(v4);
    }
    // Decided before the embedded-IPv4 branches below, because `::1` is also
    // six zero segments and must be judged as loopback rather than as the
    // IPv4-compatible address `::0.0.0.1`.
    if ip.is_loopback() {
        return Err(Refusal::Loopback);
    }
    if ip.is_unspecified() {
        return Err(Refusal::Unspecified);
    }
    if ip.is_multicast() {
        return Err(Refusal::Multicast);
    }

    // Two more ways to carry an IPv4 address inside an IPv6 one, both of which
    // reach the v4 world through a translator and neither of which
    // `to_ipv4_mapped` recognises:
    //
    //   * NAT64 `64:ff9b::/96` — the well-known prefix. `64:ff9b::7f00:1`
    //     is 127.0.0.1 on the other side of any NAT64 gateway.
    //   * IPv4-compatible `::/96`, deprecated but still routed by some stacks.
    //     `::127.0.0.1` is not caught by `is_loopback`, which is only `::1`.
    //
    // Judged by the v4 rules, because that is where the packet ends up.
    let v4_compatible = segments[0..6] == [0, 0, 0, 0, 0, 0] && !ip.is_unspecified();
    let nat64 = segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0];
    if v4_compatible || nat64 {
        let embedded = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return check_v4(embedded);
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Err(Refusal::LinkLocal);
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Err(Refusal::Private); // fc00::/7 unique local
    }
    // Deprecated 6to4 is a way to express an inner address this check would
    // otherwise not see.
    if segments[0] == 0x2002 {
        return Err(Refusal::Reserved);
    }
    // 2001::/23, IETF Protocol Assignments: Teredo (2001:0::/32), the PCP and
    // NAT64-discovery anycast addresses (2001:1::1, 2001:1::2), benchmarking
    // (2001:2::/48) and the documentation range (2001:db8::/32). All sit
    // inside 2000::/3, so the global-unicast default-deny below never reaches
    // them, and each names infrastructure rather than a destination.
    if segments[0] == 0x2001 && (segments[1] < 0x0200 || segments[1] == 0x0db8) {
        return Err(Refusal::Reserved);
    }
    if segments[0] & 0xffc0 == 0xfec0 {
        return Err(Refusal::Private); // fec0::/10, deprecated site-local
    }
    // Default-deny anything outside global unicast. An agent's destination is
    // a public host; every other prefix is either infrastructure or a way of
    // naming one, and new ones get assigned faster than this file is revisited.
    if segments[0] & 0xe000 != 0x2000 {
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
    fn an_ipv4_address_tunnelled_inside_ipv6_is_judged_by_its_v4_rules() {
        // Each of these reaches the v4 world through a translator, so the
        // address that matters is the embedded one.
        assert_eq!(refused("64:ff9b::7f00:1"), Refusal::Loopback); // NAT64 127.0.0.1
        assert_eq!(refused("64:ff9b::a9fe:a9fe"), Refusal::CloudMetadata); // 169.254.169.254
        assert_eq!(refused("64:ff9b::c0a8:1"), Refusal::Private); // 192.168.0.1
        assert_eq!(refused("::127.0.0.1"), Refusal::Loopback); // IPv4-compatible
        assert_eq!(refused("::169.254.169.254"), Refusal::CloudMetadata);
    }

    #[test]
    fn loopback_wins_over_the_embedded_ipv4_reading() {
        // ::1 is also six zero segments, so it would otherwise be read as the
        // IPv4-compatible address ::0.0.0.1 and allowed.
        assert_eq!(refused("::1"), Refusal::Loopback);
        assert_eq!(refused("::"), Refusal::Unspecified);
    }

    #[test]
    fn anything_outside_global_unicast_is_refused_by_default() {
        // New non-global prefixes get assigned faster than this file is
        // revisited, so the default is deny rather than allow.
        assert_eq!(refused("fec0::1"), Refusal::Private); // deprecated site-local
        assert_eq!(refused("100::1"), Refusal::Reserved); // discard-only
                                                          // Note 3ffe::/16 (the former 6bone) is NOT caught here: it sits inside
                                                          // 2000::/3, so a default-deny on non-global-unicast does not reach it.
                                                          // Left alone rather than special-cased — the prefix is unassigned, not
                                                          // infrastructure, so it is not a path to anything.
                                                          // ...and a genuine public address still passes.
        assert!(check("2606:4700:4700::1111".parse().unwrap()).is_ok());
    }

    #[test]
    fn the_zero_network_is_refused_in_every_spelling() {
        // 0.0.0.0/8 is "this host on this network" and reaches a local
        // interface on some stacks. Only 0.0.0.0 itself used to be refused,
        // and the embedded-IPv4 branches made the rest reachable over v6.
        for ip in [
            "0.0.0.2",
            "0.1.2.3",
            "::2",
            "::0.0.0.2",
            "64:ff9b::2",
            "64:ff9b::0.0.0.2",
            "::ffff:0.0.0.2",
        ] {
            assert!(check(ip.parse().unwrap()).is_err(), "{ip} must be refused");
        }
    }

    #[test]
    fn ietf_protocol_assignments_are_refused() {
        // 2001::/23 sits inside 2000::/3, so the global-unicast default-deny
        // does not reach it. Each of these names infrastructure.
        assert_eq!(refused("2001:1::1"), Refusal::Reserved); // PCP anycast
        assert_eq!(refused("2001:1::2"), Refusal::Reserved); // NAT64 discovery
        assert_eq!(refused("2001:2::1"), Refusal::Reserved); // benchmarking
        assert_eq!(refused("2001:db8::1"), Refusal::Reserved); // documentation
        assert_eq!(refused("2001::1"), Refusal::Reserved); // Teredo
                                                           // 2001:200::/23 onward is ordinary allocated space.
        assert!(check("2001:200::1".parse().unwrap()).is_ok());
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
