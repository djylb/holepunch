package mod

import (
	"context"
	"net"
	tm "time"
)

func spin() {
	go spin()                // want "nobarego"
	tm.Sleep(tm.Millisecond) // want "nosleep"
	sleep := tm.Sleep        // want "nosleep"
	_ = sleep
}

func dial(ctx context.Context) {
	c, _ := net.ListenPacket("udp", ":0") // want "nodirectnet"
	_ = c
	var d net.Dialer // want "nodirectnet"
	_ = d
	lc := &net.ListenConfig{} // want "nodirectnet"
	_ = lc
	_, _ = net.DefaultResolver.LookupNetIP(ctx, "ip", "example.com") // want "nodirectnet"
	_, _ = net.InterfaceAddrs()                                      // want "nodirectnet"
	_ = net.JoinHostPort("a", "1")
}

var globalDial = net.Dial // want "nodirectnet"

// systemListen is the OS implementation of Network.ListenPacket.
//
//holepunch:netimpl
func systemListen() {
	c, _ := net.ListenUDP("udp", nil)
	_ = c
	go func() {}() // want "nobarego"
}

func shadowed(net fakeNet, tm fakeTime) {
	_ = net.ListenPacket()
	tm.Sleep()
}

type fakeNet struct{}

func (fakeNet) ListenPacket() error { return nil }

type fakeTime struct{}

func (fakeTime) Sleep() {}

// A Dialer field type is a declaration, not network use.
type dialerHolder struct {
	d *net.Dialer
}

//holepunch:callbak // want "directive"
func typo() {}

//holepunch:netimpl extra // want "directive"
func withArgument() {}

func misplaced() {
	//holepunch:callback // want "directive"
	_ = 1
}
