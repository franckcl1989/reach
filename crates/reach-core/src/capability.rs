use std::time::Duration;

/// Origin and timing of a fact. No platform adapter may synthesize provenance
/// for data it did not actually observe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    pub source: ProvenanceSource,
    pub observed_at: Option<Duration>,
    pub detail: Option<String>,
}

impl Provenance {
    #[must_use]
    pub const fn new(source: ProvenanceSource) -> Self {
        Self {
            source,
            observed_at: None,
            detail: None,
        }
    }

    #[must_use]
    pub fn at(mut self, elapsed_since_run_start: Duration) -> Self {
        self.observed_at = Some(elapsed_since_run_start);
        self
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProvenanceSource {
    CoreInputParser,
    SystemResolver,
    InterfaceSnapshot,
    RouteSnapshot,
    RoutingPolicySnapshot,
    ResolverConfigurationSnapshot,
    TargetedPathQuery,
    NeighborQuery,
    TcpSocket,
    IcmpApi,
    DirectDns,
    PlatformCapabilityProbe,
    SyntheticTest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityReason {
    NotExposedByOperatingSystem,
    OrdinaryUserPermissionDenied,
    SnapshotInconsistent,
    QuerySemanticsUnavailable,
    AttemptCorrelationUnavailable,
    UnsupportedEnvironment,
    Other(String),
}

/// A capability-bearing fact is never represented by an absent `Option`.
/// Unknown and unavailable are different, provenance-carrying states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityValue<T> {
    Available {
        value: T,
        provenance: Provenance,
    },
    Unknown {
        reason: CapabilityReason,
        provenance: Provenance,
    },
    Unavailable {
        reason: CapabilityReason,
        provenance: Provenance,
    },
}

impl<T> CapabilityValue<T> {
    #[must_use]
    pub fn available(value: T, provenance: Provenance) -> Self {
        Self::Available { value, provenance }
    }

    #[must_use]
    pub fn unknown(reason: CapabilityReason, provenance: Provenance) -> Self {
        Self::Unknown { reason, provenance }
    }

    #[must_use]
    pub fn unavailable(reason: CapabilityReason, provenance: Provenance) -> Self {
        Self::Unavailable { reason, provenance }
    }

    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        match self {
            Self::Available { provenance, .. }
            | Self::Unknown { provenance, .. }
            | Self::Unavailable { provenance, .. } => provenance,
        }
    }

    #[must_use]
    pub fn as_ref(&self) -> CapabilityValue<&T> {
        match self {
            Self::Available { value, provenance } => CapabilityValue::Available {
                value,
                provenance: provenance.clone(),
            },
            Self::Unknown { reason, provenance } => CapabilityValue::Unknown {
                reason: reason.clone(),
                provenance: provenance.clone(),
            },
            Self::Unavailable { reason, provenance } => CapabilityValue::Unavailable {
                reason: reason.clone(),
                provenance: provenance.clone(),
            },
        }
    }
}
