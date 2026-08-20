use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ComponentReadiness {
    Unknown,
    Starting,
    Ready,
    NotReady(String),
    Failed(String),
    Stopped,
}

impl ComponentReadiness {
    pub(crate) fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    pub(crate) fn not_ready(reason: impl Into<String>) -> Self {
        Self::NotReady(reason.into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuestAgentReadiness {
    Unknown,
    ReachableOnly,
    Status { healthy: bool, ready: bool },
    Failed(String),
    Stopped,
}

impl GuestAgentReadiness {
    pub(crate) fn is_ready(&self) -> bool {
        matches!(
            self,
            Self::Status {
                healthy: true,
                ready: true
            }
        )
    }

    pub(crate) fn ready() -> Self {
        Self::Status {
            healthy: true,
            ready: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MitmReadiness {
    Disabled,
    Starting,
    Ready,
    Failed(String),
    Stopped,
}

impl MitmReadiness {
    pub(crate) fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GatewayReadiness {
    pub vmnet_bridged: ComponentReadiness,
    pub vmnet_host_only: ComponentReadiness,
    pub vfkit_leader: ComponentReadiness,
    pub guest_agent: GuestAgentReadiness,
    pub guest_packet_path: ComponentReadiness,
    pub mitm: MitmReadiness,
}

impl Default for GatewayReadiness {
    fn default() -> Self {
        Self {
            vmnet_bridged: ComponentReadiness::Unknown,
            vmnet_host_only: ComponentReadiness::Unknown,
            vfkit_leader: ComponentReadiness::Unknown,
            guest_agent: GuestAgentReadiness::Unknown,
            guest_packet_path: ComponentReadiness::not_ready(
                "guest packet path has not been verified",
            ),
            mitm: MitmReadiness::Disabled,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForwardingBlocker {
    ReleaseGateClosed,
    BridgedVmnetHelperNotReady,
    HostOnlyVmnetHelperNotReady,
    VfkitLeaderNotReady,
    GuestAgentNotReady,
    GuestPacketPathNotReady,
}

impl fmt::Display for ForwardingBlocker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::ReleaseGateClosed => "guest packet path release gate 未打开",
            Self::BridgedVmnetHelperNotReady => "LAN bridged vmnet-helper 未就绪",
            Self::HostOnlyVmnetHelperNotReady => "host-only vmnet-helper 未就绪",
            Self::VfkitLeaderNotReady => "vfkit leader 未就绪",
            Self::GuestAgentNotReady => "guest-agent 未达到 healthy && ready",
            Self::GuestPacketPathNotReady => "guest packet path 未完成端到端验收",
        };
        formatter.write_str(value)
    }
}

impl GatewayReadiness {
    pub(crate) fn runtime_blockers(&self, release_gate_open: bool) -> Vec<ForwardingBlocker> {
        let mut blockers = Vec::new();
        if !release_gate_open {
            blockers.push(ForwardingBlocker::ReleaseGateClosed);
        }
        if !self.vmnet_bridged.is_ready() {
            blockers.push(ForwardingBlocker::BridgedVmnetHelperNotReady);
        }
        if !self.vmnet_host_only.is_ready() {
            blockers.push(ForwardingBlocker::HostOnlyVmnetHelperNotReady);
        }
        if !self.vfkit_leader.is_ready() {
            blockers.push(ForwardingBlocker::VfkitLeaderNotReady);
        }
        if !self.guest_agent.is_ready() {
            blockers.push(ForwardingBlocker::GuestAgentNotReady);
        }
        blockers
    }

    pub(crate) fn runtime_ready(&self, release_gate_open: bool) -> bool {
        self.runtime_blockers(release_gate_open).is_empty()
    }

    pub(crate) fn blockers(&self, release_gate_open: bool) -> Vec<ForwardingBlocker> {
        let mut blockers = self.runtime_blockers(release_gate_open);
        if !self.guest_packet_path.is_ready() {
            blockers.push(ForwardingBlocker::GuestPacketPathNotReady);
        }
        blockers
    }

    pub(crate) fn forwarding_allowed(&self, release_gate_open: bool) -> bool {
        self.blockers(release_gate_open).is_empty()
    }

    pub(crate) fn blocker_summary(&self, release_gate_open: bool) -> String {
        self.blockers(release_gate_open)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("、")
    }

    pub(crate) fn mark_starting(&mut self) {
        self.vmnet_bridged = ComponentReadiness::Starting;
        self.vmnet_host_only = ComponentReadiness::Starting;
        self.vfkit_leader = ComponentReadiness::Starting;
        self.guest_agent = GuestAgentReadiness::Unknown;
        self.guest_packet_path =
            ComponentReadiness::not_ready("guest packet path has not been verified");
    }

    pub(crate) fn mark_runtime_started(&mut self) {
        self.vmnet_bridged = ComponentReadiness::Ready;
        self.vmnet_host_only = ComponentReadiness::Ready;
        self.vfkit_leader = ComponentReadiness::Ready;
        self.guest_agent = GuestAgentReadiness::ready();
    }

    pub(crate) fn mark_failed(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.vmnet_bridged = ComponentReadiness::Failed(reason.clone());
        self.vmnet_host_only = ComponentReadiness::Failed(reason.clone());
        self.vfkit_leader = ComponentReadiness::Failed(reason.clone());
        self.guest_agent = GuestAgentReadiness::Failed(reason.clone());
        self.guest_packet_path = ComponentReadiness::not_ready(reason);
    }

    pub(crate) fn mark_guest_packet_path_ready(&mut self) {
        self.guest_packet_path = ComponentReadiness::Ready;
    }

    pub(crate) fn mark_guest_packet_path_not_ready(&mut self, reason: impl Into<String>) {
        self.guest_packet_path = ComponentReadiness::not_ready(reason);
    }

    pub(crate) fn mark_stopped(&mut self) {
        self.vmnet_bridged = ComponentReadiness::Stopped;
        self.vmnet_host_only = ComponentReadiness::Stopped;
        self.vfkit_leader = ComponentReadiness::Stopped;
        self.guest_agent = GuestAgentReadiness::Stopped;
        self.guest_packet_path = ComponentReadiness::Stopped;
    }

    pub(crate) fn forwarding_with_required_mitm_allowed(&self, release_gate_open: bool) -> bool {
        self.forwarding_allowed(release_gate_open) && self.mitm.is_ready()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completely_ready() -> GatewayReadiness {
        GatewayReadiness {
            vmnet_bridged: ComponentReadiness::Ready,
            vmnet_host_only: ComponentReadiness::Ready,
            vfkit_leader: ComponentReadiness::Ready,
            guest_agent: GuestAgentReadiness::ready(),
            guest_packet_path: ComponentReadiness::Ready,
            mitm: MitmReadiness::Disabled,
        }
    }

    #[test]
    fn closed_release_gate_is_always_fail_closed() {
        let readiness = completely_ready();
        assert!(!readiness.forwarding_allowed(false));
        assert_eq!(
            readiness.blockers(false),
            vec![ForwardingBlocker::ReleaseGateClosed]
        );
    }

    #[test]
    fn guest_agent_reachable_only_is_not_ready() {
        let mut readiness = completely_ready();
        readiness.guest_agent = GuestAgentReadiness::ReachableOnly;
        assert!(!readiness.forwarding_allowed(true));
        assert!(readiness
            .blockers(true)
            .contains(&ForwardingBlocker::GuestAgentNotReady));
    }

    #[test]
    fn healthy_but_not_ready_guest_is_fail_closed() {
        let mut readiness = completely_ready();
        readiness.guest_agent = GuestAgentReadiness::Status {
            healthy: true,
            ready: false,
        };
        assert!(!readiness.forwarding_allowed(true));
    }

    #[test]
    fn runtime_start_does_not_imply_guest_packet_path_ready() {
        let mut readiness = GatewayReadiness::default();
        readiness.mark_starting();
        readiness.mark_runtime_started();
        assert!(readiness.vmnet_bridged.is_ready());
        assert!(readiness.vmnet_host_only.is_ready());
        assert!(readiness.vfkit_leader.is_ready());
        assert!(readiness.guest_agent.is_ready());
        assert!(!readiness.guest_packet_path.is_ready());
        assert!(!readiness.forwarding_allowed(true));
    }

    #[test]
    fn default_readiness_is_not_a_valid_prelaunch_runtime_gate() {
        let readiness = GatewayReadiness::default();
        assert!(!readiness.runtime_ready(true));
        assert!(readiness
            .runtime_blockers(true)
            .contains(&ForwardingBlocker::BridgedVmnetHelperNotReady));
        assert!(readiness
            .runtime_blockers(true)
            .contains(&ForwardingBlocker::GuestAgentNotReady));
        assert!(!readiness
            .runtime_blockers(true)
            .contains(&ForwardingBlocker::GuestPacketPathNotReady));
    }

    #[test]
    fn manual_packet_path_acceptance_is_separate_from_runtime_readiness() {
        let mut readiness = completely_ready();
        readiness.guest_packet_path = ComponentReadiness::not_ready("manual acceptance pending");
        assert!(readiness.runtime_ready(true));
        assert!(!readiness.forwarding_allowed(true));
        assert_eq!(
            readiness.blockers(true),
            vec![ForwardingBlocker::GuestPacketPathNotReady]
        );
    }

    #[test]
    fn each_runtime_component_failure_is_fail_closed() {
        let mut readiness = completely_ready();
        readiness.vmnet_bridged = ComponentReadiness::Failed("exited".into());
        assert!(!readiness.forwarding_allowed(true));
        readiness = completely_ready();
        readiness.vmnet_host_only = ComponentReadiness::Failed("exited".into());
        assert!(!readiness.forwarding_allowed(true));
        readiness = completely_ready();
        readiness.vfkit_leader = ComponentReadiness::Failed("exited".into());
        assert!(!readiness.forwarding_allowed(true));
        readiness = completely_ready();
        readiness.guest_agent = GuestAgentReadiness::Failed("status failed".into());
        assert!(!readiness.forwarding_allowed(true));
        readiness = completely_ready();
        readiness.guest_packet_path = ComponentReadiness::not_ready("not verified");
        assert!(!readiness.forwarding_allowed(true));
    }

    #[test]
    fn startup_failure_marks_every_gateway_component_failed() {
        let mut readiness = GatewayReadiness::default();
        readiness.mark_starting();
        readiness.mark_failed("vfkit exited");
        assert!(matches!(
            readiness.vmnet_bridged,
            ComponentReadiness::Failed(_)
        ));
        assert!(matches!(
            readiness.vmnet_host_only,
            ComponentReadiness::Failed(_)
        ));
        assert!(matches!(
            readiness.vfkit_leader,
            ComponentReadiness::Failed(_)
        ));
        assert!(matches!(
            readiness.guest_agent,
            GuestAgentReadiness::Failed(_)
        ));
        assert!(!readiness.forwarding_allowed(true));
    }

    #[test]
    fn mitm_is_not_a_base_gateway_precondition() {
        let mut readiness = completely_ready();
        readiness.mitm = MitmReadiness::Failed("mitmproxy unavailable".into());
        assert!(readiness.forwarding_allowed(true));
        assert!(!readiness.forwarding_with_required_mitm_allowed(true));
    }

    #[test]
    fn blocker_summary_names_the_guest_path_gate() {
        let readiness = GatewayReadiness::default();
        assert!(readiness
            .blocker_summary(false)
            .contains("guest packet path release gate 未打开"));
        assert!(readiness
            .blocker_summary(false)
            .contains("guest packet path 未完成端到端验收"));
    }
}
