package proto

// Register opens a host's registration link (client → server).
type Register struct {
	// HostID names the host; dialers open sessions by it.
	HostID string `json:"host_id"`
	// AuthToken is the server's shared token, if it requires one.
	AuthToken string `json:"auth_token,omitempty"`
	// Credential is the credential of the host's previous registration
	// (Registered.Credential). It lets the host take its ID over from a link
	// the server still believes alive; without it a live ID is refused.
	Credential string `json:"credential,omitempty"`
	// Metadata is passed to the dialers' SessionInfo.HostMetadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Registered accepts a registration (server → client).
type Registered struct {
	// Credential lets the host take its ID over on its next registration;
	// every registration gets a new one.
	Credential string `json:"credential"`
	// HeartbeatMs is the heartbeat interval of the link: each side sends a
	// Heartbeat this often and drops a link silent for three intervals.
	HeartbeatMs uint32 `json:"heartbeat_ms"`
}

// Open asks for a session with a registered host (client → server).
type Open struct {
	HostID    string `json:"host_id"`
	DialerID  string `json:"dialer_id,omitempty"` // optional, self-declared; shown to the host
	AuthToken string `json:"auth_token,omitempty"`
	// Metadata is passed to SessionInfo.DialerMetadata on both sides.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Join takes up a session announced by Incoming (client → server). The
// ticket is the only credential the join needs.
type Join struct {
	SessionID string `json:"session_id"`
	Ticket    string `json:"ticket"`
}

// SessionInfo answers Open and Join (server → client): the session is
// created and holepunch's punch_start is the next frame on the stream. Both
// sides receive the same description.
type SessionInfo struct {
	SessionID      string            `json:"session_id"`
	HostID         string            `json:"host_id"`
	DialerID       string            `json:"dialer_id,omitempty"`
	HostMetadata   map[string]string `json:"host_metadata,omitempty"`
	DialerMetadata map[string]string `json:"dialer_metadata,omitempty"`
	// Policy restricts what the dialer may reach through the host.
	Policy AccessPolicy `json:"policy"`
}

// Incoming tells a host, on its registration link, that a dialer opened a
// session with it (server → client). The host joins with a new stream.
type Incoming struct {
	SessionID      string            `json:"session_id"`
	Ticket         string            `json:"ticket"`
	DialerID       string            `json:"dialer_id,omitempty"`
	DialerMetadata map[string]string `json:"dialer_metadata,omitempty"`
}

// Heartbeat keeps a registration link alive (both ways).
type Heartbeat struct{}

// Transport reports, on the host's registration link, whether the upper-layer
// transport of a session came up on the punched path (client → server). It
// is telemetry only: the server is no longer part of the session.
type Transport struct {
	SessionID string `json:"session_id"`
	OK        bool   `json:"ok"`
	Detail    string `json:"detail,omitempty"`
}

// Type returns TypeRegister.
func (*Register) Type() Type { return TypeRegister }

// Type returns TypeRegistered.
func (*Registered) Type() Type { return TypeRegistered }

// Type returns TypeOpen.
func (*Open) Type() Type { return TypeOpen }

// Type returns TypeJoin.
func (*Join) Type() Type { return TypeJoin }

// Type returns TypeSessionInfo.
func (*SessionInfo) Type() Type { return TypeSessionInfo }

// Type returns TypeIncoming.
func (*Incoming) Type() Type { return TypeIncoming }

// Type returns TypeHeartbeat.
func (*Heartbeat) Type() Type { return TypeHeartbeat }

// Type returns TypeTransport.
func (*Transport) Type() Type { return TypeTransport }

// Type returns TypeFail.
func (*Fail) Type() Type { return TypeFail }

func (m *Register) validate() error {
	return firstError(
		checkName("register.host_id", m.HostID, true),
		checkSecret("register.auth_token", m.AuthToken, false),
		checkSecret("register.credential", m.Credential, false),
		checkMetadata("register.metadata", m.Metadata),
	)
}

func (m *Registered) validate() error {
	return firstError(
		checkSecret("registered.credential", m.Credential, true),
		checkHeartbeat("registered.heartbeat_ms", m.HeartbeatMs),
	)
}

func (m *Open) validate() error {
	return firstError(
		checkName("open.host_id", m.HostID, true),
		checkName("open.dialer_id", m.DialerID, false),
		checkSecret("open.auth_token", m.AuthToken, false),
		checkMetadata("open.metadata", m.Metadata),
	)
}

func (m *Join) validate() error {
	return firstError(
		checkSessionID("join.session_id", m.SessionID),
		checkSecret("join.ticket", m.Ticket, true),
	)
}

func (m *SessionInfo) validate() error {
	return firstError(
		checkSessionID("session_info.session_id", m.SessionID),
		checkName("session_info.host_id", m.HostID, true),
		checkName("session_info.dialer_id", m.DialerID, false),
		checkMetadata("session_info.host_metadata", m.HostMetadata),
		checkMetadata("session_info.dialer_metadata", m.DialerMetadata),
		m.Policy.validate("session_info.policy"),
	)
}

func (m *Incoming) validate() error {
	return firstError(
		checkSessionID("incoming.session_id", m.SessionID),
		checkSecret("incoming.ticket", m.Ticket, true),
		checkName("incoming.dialer_id", m.DialerID, false),
		checkMetadata("incoming.dialer_metadata", m.DialerMetadata),
	)
}

func (*Heartbeat) validate() error { return nil }

func (m *Transport) validate() error {
	return firstError(
		checkSessionID("transport.session_id", m.SessionID),
		checkText("transport.detail", m.Detail),
	)
}

func (f *Fail) validate() error {
	return firstError(
		checkCode("fail.code", f.Code),
		checkText("fail.message", f.Message),
	)
}
