//! The failover state machine. Pure: it sees one observation per Pi-hole
//! probe and says what to do; the caller performs the DNS change. Time comes
//! in as a millisecond counter so tests can drive it with a fake clock.
//!
//! Engage only when all of these hold:
//!   * failover is eligible (enabled, Pi-hole configured, the active profile
//!     is in Pi-hole mode),
//!   * the link has been up with the same connection for LINK_STABLE_MS,
//!   * FAILS_TO_ENGAGE consecutive probes failed,
//!   * the gateway answered a DNS probe at the same time (so a dead Wi-Fi
//!     card or an unplugged cable is never mistaken for a Pi-hole outage).
//!
//! Recover after GOODS_TO_RECOVER consecutive good probes sent straight to
//! the Pi-hole. A link change while failed over clears the state without
//! touching DNS: a new activation already loads the saved profile.

pub const FAILS_TO_ENGAGE: u32 = 3;
pub const GOODS_TO_RECOVER: u32 = 3;
pub const LINK_STABLE_MS: u64 = 10_000;
pub const RETRY_COOLDOWN_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkKey {
    pub iface: String,
    pub uuid: String,
}

#[derive(Debug, Clone)]
pub struct Obs {
    pub now_ms: u64,
    /// The activated primary link, or None when there is none.
    pub link: Option<LinkKey>,
    pub eligible: bool,
    pub pihole_ok: bool,
    /// Gateway probe result; only meaningful when `pihole_ok` is false.
    pub gateway_ok: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Idle,
    Engage,
    Recover,
    /// Failover state dropped without touching DNS (reason for the log).
    Cleared(&'static str),
}

#[derive(Debug, Default)]
pub struct Failover {
    fails: u32,
    goods: u32,
    active: bool,
    since: u64,
    reason: String,
    link: Option<LinkKey>,
    link_since_ms: u64,
    seen_any: bool,
    retry_after_ms: u64,
}

impl Failover {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active(&self) -> bool {
        self.active
    }
    pub fn since(&self) -> u64 {
        if self.active {
            self.since
        } else {
            0
        }
    }
    pub fn reason(&self) -> &str {
        if self.active {
            &self.reason
        } else {
            ""
        }
    }
    #[cfg(test)]
    pub fn fails(&self) -> u32 {
        self.fails
    }

    fn clear(&mut self) {
        self.active = false;
        self.since = 0;
        self.reason.clear();
        self.fails = 0;
        self.goods = 0;
    }

    pub fn observe(&mut self, o: &Obs) -> Decision {
        // Link bookkeeping: any change of iface/connection restarts the
        // stability window.
        if !self.seen_any || o.link != self.link {
            self.seen_any = true;
            let had_link = self.link.is_some();
            self.link = o.link.clone();
            self.link_since_ms = o.now_ms;
            self.fails = 0;
            self.goods = 0;
            if self.active && (had_link || o.link.is_none()) {
                self.clear();
                return Decision::Cleared("link changed");
            }
        }
        if !o.eligible {
            if self.active {
                self.clear();
                return Decision::Cleared("no longer eligible");
            }
            self.fails = 0;
            return Decision::Idle;
        }
        let stable = o.link.is_some() && o.now_ms.saturating_sub(self.link_since_ms) >= LINK_STABLE_MS;
        if !stable {
            self.fails = 0;
            self.goods = 0;
            return Decision::Idle;
        }

        if self.active {
            if o.pihole_ok {
                self.goods += 1;
                if self.goods >= GOODS_TO_RECOVER && o.now_ms >= self.retry_after_ms {
                    return Decision::Recover;
                }
            } else {
                self.goods = 0;
            }
            return Decision::Idle;
        }

        if o.pihole_ok {
            self.fails = 0;
            return Decision::Idle;
        }
        self.fails += 1;
        if self.fails >= FAILS_TO_ENGAGE
            && o.gateway_ok == Some(true)
            && o.now_ms >= self.retry_after_ms
        {
            return Decision::Engage;
        }
        Decision::Idle
    }

    /// The caller applied the fallback DNS.
    pub fn engaged(&mut self, unix_now: u64, reason: &str) {
        self.active = true;
        self.since = unix_now;
        self.reason = reason.to_string();
        self.fails = 0;
        self.goods = 0;
    }

    /// The caller could not apply it; back off before trying again.
    pub fn engage_failed(&mut self, now_ms: u64) {
        self.retry_after_ms = now_ms + RETRY_COOLDOWN_MS;
    }

    /// The caller restored the saved profile.
    pub fn recovered(&mut self) {
        self.clear();
    }

    pub fn recover_failed(&mut self, now_ms: u64) {
        self.retry_after_ms = now_ms + RETRY_COOLDOWN_MS;
    }

    /// Start in the failed-over state because the device is found running
    /// different DNS than its saved Pi-hole profile (a crashed qnet).
    pub fn adopt(&mut self, unix_now: u64, reason: &str) {
        self.active = true;
        self.since = unix_now;
        self.reason = reason.to_string();
        self.goods = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Option<LinkKey> {
        Some(LinkKey {
            iface: "wlp7s0".into(),
            uuid: "u1".into(),
        })
    }

    struct Rig {
        f: Failover,
        t: u64,
        link: Option<LinkKey>,
        eligible: bool,
    }

    impl Rig {
        fn new() -> Self {
            let mut r = Rig {
                f: Failover::new(),
                t: 1_000,
                link: key(),
                eligible: true,
            };
            // First sighting of the link, then let it settle.
            r.probe(true, None);
            r.t += LINK_STABLE_MS;
            r
        }
        fn probe(&mut self, ok: bool, gw: Option<bool>) -> Decision {
            let d = self.f.observe(&Obs {
                now_ms: self.t,
                link: self.link.clone(),
                eligible: self.eligible,
                pihole_ok: ok,
                gateway_ok: gw,
            });
            self.t += 15_000;
            d
        }
        fn fail(&mut self) -> Decision {
            self.probe(false, Some(true))
        }
        fn good(&mut self) -> Decision {
            self.probe(true, None)
        }
    }

    #[test]
    fn engages_on_third_consecutive_failure_with_gateway_up() {
        let mut r = Rig::new();
        assert_eq!(r.fail(), Decision::Idle);
        assert_eq!(r.fail(), Decision::Idle);
        assert_eq!(r.fail(), Decision::Engage);
        r.f.engaged(1_700_000_000, "Pi-hole not answering");
        assert!(r.f.active());
        assert_eq!(r.f.since(), 1_700_000_000);
        assert_eq!(r.f.reason(), "Pi-hole not answering");
        // While active, failures do nothing more.
        assert_eq!(r.fail(), Decision::Idle);
    }

    #[test]
    fn a_good_probe_resets_the_count() {
        let mut r = Rig::new();
        r.fail();
        r.fail();
        assert_eq!(r.good(), Decision::Idle);
        assert_eq!(r.fail(), Decision::Idle);
        assert_eq!(r.fail(), Decision::Idle);
        assert_eq!(r.fail(), Decision::Engage);
    }

    #[test]
    fn gateway_gate_blocks_and_then_releases() {
        let mut r = Rig::new();
        for _ in 0..10 {
            assert_eq!(r.probe(false, Some(false)), Decision::Idle, "gateway also dead");
        }
        assert_eq!(r.probe(false, None), Decision::Idle, "no gateway known");
        assert!(r.f.fails() >= 3);
        // The gateway comes back while the Pi-hole is still dead.
        assert_eq!(r.probe(false, Some(true)), Decision::Engage);
    }

    #[test]
    fn link_down_never_engages_and_resets_counts() {
        let mut r = Rig::new();
        r.fail();
        r.fail();
        r.link = None; // Wi-Fi card died: probes fail, gateway fails
        for _ in 0..6 {
            assert_eq!(r.probe(false, Some(false)), Decision::Idle);
        }
        assert_eq!(r.f.fails(), 0);
        // Even a lying gateway answer cannot engage without a link.
        for _ in 0..6 {
            assert_eq!(r.probe(false, Some(true)), Decision::Idle);
        }
    }

    #[test]
    fn flapping_link_never_engages() {
        let mut r = Rig::new();
        let other = Some(LinkKey { iface: "wlp7s0".into(), uuid: "u2".into() });
        // Link identity or state changes between every probe (5 s apart).
        for i in 0..12 {
            r.link = if i % 2 == 0 { key() } else { other.clone() };
            assert_eq!(r.fail(), Decision::Idle, "step {i}");
        }
    }

    #[test]
    fn link_must_be_stable_after_coming_back() {
        let mut r = Rig::new();
        r.link = None;
        r.fail();
        r.link = key();
        // Back up: the stability window restarts, so three fast failures
        // right after reconnect still do not engage.
        let t0 = r.t;
        let mut decisions = vec![];
        for i in 0..3 {
            decisions.push(r.f.observe(&Obs {
                now_ms: t0 + i * 2_000,
                link: key(),
                eligible: true,
                pihole_ok: false,
                gateway_ok: Some(true),
            }));
        }
        assert!(decisions.iter().all(|d| *d == Decision::Idle), "{decisions:?}");
        // After the window, failures count again.
        let t1 = t0 + 20_000;
        let mut got = Decision::Idle;
        for i in 0..3 {
            got = r.f.observe(&Obs {
                now_ms: t1 + i * 5_000,
                link: key(),
                eligible: true,
                pihole_ok: false,
                gateway_ok: Some(true),
            });
        }
        assert_eq!(got, Decision::Engage);
    }

    #[test]
    fn recovers_after_three_good_probes_and_a_bad_one_resets() {
        let mut r = Rig::new();
        r.fail();
        r.fail();
        assert_eq!(r.fail(), Decision::Engage);
        r.f.engaged(100, "x");
        assert_eq!(r.good(), Decision::Idle);
        assert_eq!(r.good(), Decision::Idle);
        assert_eq!(r.probe(false, Some(true)), Decision::Idle, "bad probe resets");
        assert_eq!(r.good(), Decision::Idle);
        assert_eq!(r.good(), Decision::Idle);
        assert_eq!(r.good(), Decision::Recover);
        r.f.recovered();
        assert!(!r.f.active());
        assert_eq!(r.f.since(), 0);
        assert_eq!(r.f.reason(), "");
    }

    #[test]
    fn recovery_does_not_need_the_gateway() {
        let mut r = Rig::new();
        r.f.adopt(5, "adopted");
        for _ in 0..2 {
            assert_eq!(r.probe(true, Some(false)), Decision::Idle);
        }
        assert_eq!(r.probe(true, Some(false)), Decision::Recover);
    }

    #[test]
    fn link_change_while_failed_over_clears_without_dns_action() {
        let mut r = Rig::new();
        r.fail();
        r.fail();
        r.fail();
        r.f.engaged(1, "x");
        r.link = None;
        assert_eq!(r.fail(), Decision::Cleared("link changed"));
        assert!(!r.f.active());
        // Reconnecting to the same profile later does not resurrect it.
        r.link = key();
        assert_eq!(r.good(), Decision::Idle);
        assert!(!r.f.active());
    }

    #[test]
    fn different_connection_while_failed_over_clears() {
        let mut r = Rig::new();
        r.f.adopt(1, "x");
        r.link = Some(LinkKey { iface: "wlp7s0".into(), uuid: "other".into() });
        assert_eq!(r.good(), Decision::Cleared("link changed"));
    }

    #[test]
    fn not_eligible_never_engages_and_clears_active() {
        let mut r = Rig::new();
        r.eligible = false;
        for _ in 0..6 {
            assert_eq!(r.fail(), Decision::Idle);
        }
        r.eligible = true;
        r.fail();
        r.fail();
        r.fail();
        r.f.engaged(1, "x");
        r.eligible = false;
        assert_eq!(r.good(), Decision::Cleared("no longer eligible"));
        assert!(!r.f.active());
    }

    #[test]
    fn failed_engage_backs_off() {
        let mut r = Rig::new();
        r.fail();
        r.fail();
        assert_eq!(r.fail(), Decision::Engage);
        r.f.engage_failed(r.t - 15_000);
        // Next probes are within the cooldown: no immediate retry storm.
        assert_eq!(r.fail(), Decision::Idle);
        // After the cooldown the retry comes.
        assert_eq!(r.fail(), Decision::Engage);
    }

    #[test]
    fn first_observation_alone_never_engages() {
        let mut f = Failover::new();
        for i in 0..5u64 {
            let d = f.observe(&Obs {
                now_ms: i * 1_000,
                link: key(),
                eligible: true,
                pihole_ok: false,
                gateway_ok: Some(true),
            });
            assert_eq!(d, Decision::Idle, "first 5 s after start");
        }
    }
}
