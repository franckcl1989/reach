use std::time::Duration;

pub const MAX_ACTIVE_TARGETS: usize = 4;
pub const MAX_ACTIVE_RESOLVERS: usize = 4;
pub const TCP_CONNECT_BUDGET: Duration = Duration::from_secs(5);
pub const TARGET_ICMP_BUDGET: Duration = Duration::from_secs(2);
pub const NEXT_HOP_ICMP_BUDGET: Duration = Duration::from_secs(1);
pub const NEIGHBOR_CONVERGENCE_BUDGET: Duration = Duration::from_secs(2);
pub const NEIGHBOR_POLL_INTERVAL: Duration = Duration::from_millis(200);
pub const PATH_ATTEMPT_BUDGET: Duration = Duration::from_secs(1);
pub const MAX_PATH_HOP_LIMIT: u8 = 30;
pub const DNS_UDP_BUDGET: Duration = Duration::from_secs(2);
pub const DNS_TCP_BUDGET: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_product_policy_matches_version_contract() {
        assert_eq!(MAX_ACTIVE_TARGETS, 4);
        assert_eq!(MAX_ACTIVE_RESOLVERS, 4);
        assert_eq!(TCP_CONNECT_BUDGET, Duration::from_secs(5));
        assert_eq!(TARGET_ICMP_BUDGET, Duration::from_secs(2));
        assert_eq!(NEXT_HOP_ICMP_BUDGET, Duration::from_secs(1));
        assert_eq!(NEIGHBOR_CONVERGENCE_BUDGET, Duration::from_secs(2));
        assert_eq!(NEIGHBOR_POLL_INTERVAL, Duration::from_millis(200));
        assert_eq!(PATH_ATTEMPT_BUDGET, Duration::from_secs(1));
        assert_eq!(MAX_PATH_HOP_LIMIT, 30);
        assert_eq!(DNS_UDP_BUDGET, Duration::from_secs(2));
        assert_eq!(DNS_TCP_BUDGET, Duration::from_secs(5));
    }
}
