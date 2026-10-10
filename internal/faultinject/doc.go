// Package faultinject provides named fault injection points for robustness
// tests.
//
// Library code marks a place where a fault can be injected with
//
//	if err := faultinject.Point("ctl.read"); err != nil {
//		if errors.Is(err, faultinject.ErrCloseConn) {
//			_ = conn.Close() // the connection this code is using
//		}
//		return err
//	}
//
// Point names follow "<component>.<action>", optionally with further
// dot-separated parts ("coord.finish.notify"); each part is lower-case ASCII
// letters, digits and underscores and starts with a letter. Names must be
// string constants at the call site: in the default build Point is an empty
// function that the compiler inlines and removes together with a constant
// argument and the guarded branch, but a name built at run time (for example
// "coord.finish." + step) still costs the string concatenation.
//
// # Build modes
//
// Without the build tag holepunch_faultinject Point always returns nil;
// production binaries carry no injection code and no state. ErrInjected and
// ErrCloseConn exist in both builds because call sites refer to them.
//
// With -tags holepunch_faultinject, tests arm points; Arm, Action and the
// counters exist only in this build, so a fault test that forgets the tag
// does not compile instead of passing without injecting anything:
//
//	disarm := faultinject.Arm("probe.bind", faultinject.Error(nil), 0)
//	defer disarm()
//
// An arm with nth >= 1 fires once, on the nth call of Point for that name
// after Arm; with nth <= 0 it fires on every call until disarmed. Actions:
//
//   - Panic: Point panics with an error wrapping ErrInjected, exercising the
//     recover boundary around the caller (a *life.PanicError unwraps to it).
//   - Error: Point returns the given error unchanged, or an error naming the
//     point and wrapping ErrInjected when it is nil.
//   - Stall: Point blocks for the given duration, or until disarmed when the
//     duration is not positive, then returns nil.
//   - CloseConn: Point returns an error wrapping ErrCloseConn and
//     net.ErrClosed; the call site closes the connection it is using, so the
//     fault looks like the peer or the OS closing it.
//
// # Concurrency and state
//
// In the tagged build the armed points and the counters live in one
// process-wide registry, because Point takes no instance: an injection point
// is a fixed place in the library, not a property of a session. Arm, Point,
// Hits, Fired, Reset and the disarm functions are safe for concurrent use.
// Arming a name replaces its previous arm and releases callers stalled by
// it; disarming or Reset releases every caller stalled by the removed arms.
// Tests that arm points must not run in parallel with other tests that reach
// the same points.
package faultinject
