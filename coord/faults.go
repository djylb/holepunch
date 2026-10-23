package coord

// Fault injection points of coord. Every name is a constant, passed down to
// the point (callout passes its own); the default build compiles each point
// away.
const (
	fiAttach         = "coord.attach"          // Attach, before the connection is wrapped
	fiHandleReport   = "coord.handle.report"   // a probe_report is being handled
	fiHandleReady    = "coord.handle.ready"    // a punch_ready is being handled
	fiPlan           = "coord.plan"            // inside the planner's recover boundary
	fiMemory         = "coord.memory"          // inside the strategy memory's recover boundary
	fiTimer          = "coord.timer"           // the session timer callback
	fiCallback       = "coord.callback"        // the Observer and OnResult boundaries
	fiClose          = "coord.close"           // Coordinator.Close, once closed and before the sessions are ended
	fiFinishNotify   = "coord.finish.notify"   // finish: punch_abort notices
	fiFinishConns    = "coord.finish.conns"    // finish: closing the control links
	fiFinishRegistry = "coord.finish.registry" // finish: natprobe handle
	fiFinishQuota    = "coord.finish.quota"    // finish: quota reservations
	fiFinishIndex    = "coord.finish.index"    // finish: session index
	fiFinishParent   = "coord.finish.parent"   // finish: parent context registration
	fiFinishCtx      = "coord.finish.ctx"      // finish: session context
	fiFinishMemory   = "coord.finish.memory"   // finish: strategy memory feedback
	fiFinishTraits   = "coord.finish.traits"   // finish: traits memory feedback
	fiFinishStats    = "coord.finish.stats"    // finish: coordinator statistics
)
