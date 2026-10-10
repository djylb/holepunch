package proto

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// AccessPolicy restricts the forward targets a dialer may reach through the
// host of one session, as the server decided when it matched them. The host
// applies it on top of its own target list, which always has the last word.
type AccessPolicy struct {
	// Targets are canonical targets (CanonicalTarget). Empty means the
	// server does not restrict the session.
	Targets []string `json:"targets,omitempty"`
}

// Allows reports whether p admits target, compared in canonical form.
func (p AccessPolicy) Allows(target string) bool {
	if len(p.Targets) == 0 {
		return true
	}
	t, err := CanonicalTarget(target)
	if err != nil {
		return false
	}
	return slices.Contains(p.Targets, t)
}

func (p AccessPolicy) validate(field string) error {
	if len(p.Targets) > MaxTargets {
		return invalid(field+".targets", "%d entries > %d", len(p.Targets), MaxTargets)
	}
	for _, t := range p.Targets {
		c, err := CanonicalTarget(t)
		if err != nil || c != t {
			return invalid(field+".targets", "%q is not a canonical target", t)
		}
	}
	return nil
}

// errTarget is the error of a malformed forward target.
var errTarget = errors.New("proto: forward target must be host:port with a port in 1..65535")

// CanonicalTarget returns the canonical form of a forward target "host:port":
// an IP literal in its standard form, any other host in lower case, and a
// decimal port in 1..65535.
func CanonicalTarget(target string) (string, error) {
	if len(target) > MaxTargetLen {
		return "", errTarget
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", errTarget
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", errTarget
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		host = strings.ToLower(host)
		if !validHostName(host) {
			return "", errTarget
		}
	}
	return net.JoinHostPort(host, strconv.FormatUint(p, 10)), nil
}

// validHostName accepts DNS names made of letters, digits, '-', '_' and dots.
func validHostName(h string) bool {
	if len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !isAlnum(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}
