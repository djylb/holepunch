package proto

// Code is the reason of a Fail. A client matches a refusal with errors.As
// and compares Fail.Code.
type Code string

// Fail codes. A client treats a code it does not know like CodeInternal.
const (
	// CodeUnauthorized means the auth token or the server's Authorize hook
	// refused the request.
	CodeUnauthorized Code = "unauthorized"
	// CodeInvalidRequest means the first message was not a request, or not a
	// valid one.
	CodeInvalidRequest Code = "invalid_request"
	// CodeHostNotFound means no host is registered under the ID, or it went
	// away while the session was being set up.
	CodeHostNotFound Code = "host_not_found"
	// CodeHostExists means the host ID is registered by a live link and the
	// registration did not carry that link's credential.
	CodeHostExists Code = "host_exists"
	// CodeSessionNotFound means the session to join does not exist (any
	// more), was joined already, or the ticket is wrong.
	CodeSessionNotFound Code = "session_not_found"
	// CodeBusy means a server limit refused the request; retrying later may
	// work.
	CodeBusy Code = "busy"
	// CodeShutdown means the server is shutting down.
	CodeShutdown Code = "shutdown"
	// CodeInternal means anything else.
	CodeInternal Code = "internal"
)

// Retryable reports whether a request refused with c may succeed later
// without any change on the client's side.
func (c Code) Retryable() bool {
	switch c {
	case CodeUnauthorized, CodeInvalidRequest, CodeHostExists:
		return false
	}
	return true
}

// Fail refuses a request (server → client); the server closes the stream
// after it. A received Fail is also the error the client returns for it.
type Fail struct {
	Code    Code   `json:"code"`
	Message string `json:"message,omitempty"` // human readable, never a stack
}

// Error formats the refusal as "standalone: <code>", followed by
// ": <message>" when there is one.
func (f *Fail) Error() string {
	if f.Message == "" {
		return "standalone: " + string(f.Code)
	}
	return "standalone: " + string(f.Code) + ": " + f.Message
}
