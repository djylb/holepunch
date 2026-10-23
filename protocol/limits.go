package protocol

// Structural limits checked by Validate: a list over one of them is a
// protocol violation. The exported ones bound what a sender may put in a
// message, so the library's senders build their messages against them.
const (
	maxFeatures       = 16
	maxFeatureName    = 32
	maxName           = 64 // names, ids, codes, map keys
	maxImpl           = 64
	maxCapsFamilies   = 2
	maxPortMapMethods = 3
	maxReportFamilies = 2
	maxTransportMode  = 16
	maxViewFamilies   = 2
	maxSharedFamilies = 2
	maxLadder         = 16
	maxSides          = 2
	maxMetaValue      = 64
	maxMetaTotal      = 1 << 10
	maxOutcomes       = 2
	maxTraitsUpdates  = 2
	maxPingSeq        = 8

	// MaxSessionID is the longest session id, in bytes.
	MaxSessionID = 64
	// MaxObservers bounds ProbeSpec.Observers.
	MaxObservers = 16
	// MaxReportSockets bounds FamilyReport.Sockets.
	MaxReportSockets = 6
	// MaxReportRows bounds SocketReport.Rows: one per observer.
	MaxReportRows = 16
	// MaxReportFilters bounds FamilyReport.Filters.
	MaxReportFilters = 24
	// MaxReportSTUNRows bounds FamilyReport.STUN.
	MaxReportSTUNRows = 8
	// MaxLocalAddrs bounds FamilyReport.LocalAddrs.
	MaxLocalAddrs = 16
	// MaxOverlayAddrs bounds FamilyReport.Overlay.
	MaxOverlayAddrs = 2
	// MaxTransportData bounds Transport.Data, in bytes.
	MaxTransportData = 8 << 10
	// MaxEndpoints bounds FamilyView.Endpoints.
	MaxEndpoints = 12
	// MaxRound is the highest round number; rescue rounds take one too.
	MaxRound = 8
	// MaxSeenFrom bounds FamilyOutcome.SeenFrom.
	MaxSeenFrom = 4
	// MaxWarn bounds PunchResult.Warn.
	MaxWarn = 8
	// MaxLowTTLHops bounds Policy.LowTTLHops.
	MaxLowTTLHops = 8
	// MaxDetail bounds punch_abort.detail and punch_result.detail, in bytes.
	MaxDetail = 256
	// MaxProgressDetail bounds punch_progress.detail, in bytes.
	MaxProgressDetail = 128
	// MaxPortWindowWidth bounds PortWindow: hi − lo.
	MaxPortWindowWidth = 63
)

// Ranges the receiver clamps (Normalize) instead of refusing the message.
const (
	maxRoundsMax     = 6
	maxAssistTargets = 16
	maxProgressMap   = 16
	maxAssistMeta    = 8
	maxDropKeys      = 16

	// MaxDelayMs bounds PunchGo.DelayMs.
	MaxDelayMs = 2000
	// MaxSendDelayMs bounds FamilySide.SendDelayMs.
	MaxSendDelayMs = 3000
	// MaxSideSockets bounds FamilySide.Sockets and a fresh stage's Count.
	MaxSideSockets = 256
	// MaxStages bounds FamilySide.Stages.
	MaxStages = 8
	// MaxStageTargets bounds Stage.Targets.
	MaxStageTargets = 16
	// MaxSteps bounds Stage.Steps.
	MaxSteps = 3
	// MaxSpanCount bounds Stage.Span and Stage.Count.
	MaxSpanCount = 4096
	// MaxRepeats bounds Stage.Repeats.
	MaxRepeats = 8
	// MinLowTTL and MaxLowTTL bound a set Stage.TTL.
	MinLowTTL = 2
	MaxLowTTL = 64
	// MaxSiblings bounds ProbeSpec.Siblings.
	MaxSiblings = 2
)

// Target rules both ends of a session apply: the coordinator plans and
// admits within them, and a client admits what it is sent within them, so a
// plan the coordinator grants is a plan the client runs.
const (
	// MaxLANTargets bounds a peer's private addresses that a side aims at
	// (a peer on the same LAN, or an upstream port mapping of one behind the
	// same public IP), per round, and the distinct LAN IPs of its peer a
	// client keeps.
	MaxLANTargets = 4
	// MaxOverlayTargets bounds a peer's overlay addresses that a side aims
	// at, per round, when both sides have some.
	MaxOverlayTargets = 2
	// LANRepeats is how many packets a side sends each LAN or overlay
	// target per round.
	LANRepeats = 2
	// MaxReportedIPs is how many distinct global IPs a peer reported itself
	// a side keeps as targets of a family the server could not verify.
	MaxReportedIPs = 4
	// MaxUnverifiedTargets bounds the distinct targets of an unverified
	// family per side and round; MaxRelayOnlyTargets replaces it when the
	// server verified none of the families (RelayOnly).
	MaxUnverifiedTargets = 4
	MaxRelayOnlyTargets  = 16
	// UnverifiedRepeats is how many packets a side sends each target of an
	// unverified family per round, at most.
	UnverifiedRepeats = 8
	// PushPackets is how many packets a client sends each peer_targets
	// target or window port, each round.
	PushPackets = 2
	// MaxPushPerRound bounds the peer_targets targets and window ports a
	// client takes per family and round.
	MaxPushPerRound = 64
	// MaxDrifted bounds the drifted mappings of a peer (peer_targets with
	// source drift) a server pushes, and a client keeps, per session.
	MaxDrifted = 16
)

// RelayOnly reports whether the server verified none of families fams in
// the pair: each is unverified (PairFacts.Unverified) without a
// LAN-observed side in views — a LAN-observed family keeps the tighter
// unverified bounds. This is the coordinator's NoObserver mode, or a
// registry that observes none of the families; an unverified family's
// distinct targets per side and round rise from MaxUnverifiedTargets to
// MaxRelayOnlyTargets. It is false without a family.
func RelayOnly(fams []Family, pair PairFacts, views [2]PeerView) bool {
	for _, f := range fams {
		if !pair.Unverified[f] || views[0].lanObserved(f) || views[1].lanObserved(f) {
			return false
		}
	}
	return len(fams) > 0
}

// lanObserved reports whether v's family f is LAN-observed
// (Traits.LANObserved).
func (v PeerView) lanObserved(f Family) bool {
	for _, fv := range v.Families {
		if fv.Family == f {
			return fv.Traits.LANObserved
		}
	}
	return false
}
