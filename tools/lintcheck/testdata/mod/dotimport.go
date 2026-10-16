package mod

import (
	. "net"  // want "nodirectnet"
	. "time" // want "nosleep"
)

// The dot imports would hide these calls from nosleep and nodirectnet.
func dotted() {
	Sleep(Millisecond)
	_, _ = Dial("udp", "x:1")
}

// holepunch:callback // want "directive"
func spacedCallback() {}

// holepunch: prose that happens to start like a directive is left alone.
func prose() {}

// holepunch:callback marks user code; a sentence that starts with it is
// prose too.
func proseCallback() {}
