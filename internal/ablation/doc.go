// Package ablation holds the ablation switches: each switch turns off one
// mechanism that relies on the control link both clients hold with the
// server before punching, so that the nightly ablation run can measure what
// the mechanism is worth.
//
// The switches travel in a context value. Only code inside this module can
// import the package, so callers of the public API cannot set them; library
// code only reads them with From, which adds no API surface. The zero Set is
// the full product with every mechanism on; Plain is the "ordinary hole
// punching" baseline with every switch set; Singles lists the ten one-switch
// ablations. One switch is not a control-link mechanism: NoOpener turns off
// the STUN-wrapped first datagram of each flow, for the cells that show what
// it is worth on a classifying network.
//
// The package has no state and starts no goroutines; a Set is a plain value
// that is safe to copy and share.
package ablation
