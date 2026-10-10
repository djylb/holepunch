package main

import "go/ast"

// netSelector implements nodirectnet for a selector on package net.
func (ps *pass) netSelector(sel *ast.SelectorExpr) {
	if !reachesOSNetwork(sel.Sel.Name) {
		return
	}
	if ps.fn != nil && ps.c.netimpl[ps.fn] {
		return
	}
	ps.c.report(sel.Pos(), ruleNoDirectNet, "net.%s reaches the OS network directly; go through holepunch.Network or annotate the OS implementation with //holepunch:netimpl", sel.Sel.Name)
}

// reachesOSNetwork reports whether the package net identifier name opens
// sockets or queries the operating system's network configuration or
// resolver.
func reachesOSNetwork(name string) bool {
	switch name {
	case "Dial", "DialTimeout", "DialIP", "DialTCP", "DialUDP", "DialUnix",
		"Listen", "ListenPacket", "ListenIP", "ListenMulticastUDP", "ListenTCP", "ListenUDP", "ListenUnix", "ListenUnixgram",
		"FileConn", "FileListener", "FilePacketConn",
		"Interfaces", "InterfaceAddrs", "InterfaceByIndex", "InterfaceByName",
		"LookupAddr", "LookupCNAME", "LookupHost", "LookupIP", "LookupMX", "LookupNS", "LookupPort", "LookupSRV", "LookupTXT",
		"ResolveIPAddr", "ResolveTCPAddr", "ResolveUDPAddr",
		"Dialer", "ListenConfig", "Resolver", "DefaultResolver":
		return true
	}
	return false
}
