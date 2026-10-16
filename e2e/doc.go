// Package e2e is holepunch's end-to-end acceptance suite: the real
// coordinator, a real natprobe Server and two real clients of the root
// package, all on the in-process NAT simulator nattest, with the clients'
// control links as nattest pipes. The package holds tests and test support
// only; nothing imports it. The command in kpiagg aggregates the kpi.json
// files the suite writes; testdata/kpi_baseline.json is the baseline it
// compares with.
//
// # Fixture
//
// A world is one simulated Internet with the server side on a public host
// (behind an identity device, so that a test can blackhole its UDP). A run
// is one session between two sides: each client's control link is a pipe
// whose server end is a tap — it forwards every frame unchanged, decodes it
// for the assertions, lets a test follow frames as they pass, and can hold
// a frame of either direction while a test injects a fault at that protocol
// point — and each client's Network is the nattest Host behind a thin
// wrapper that can drop packets by source or destination, fail reads and
// record destinations, keeping every capability the library probes for.
// On top of them the constructs silence a ladder rung, lose one direction,
// or put other subscribers behind a NAT to work; a world can record what
// natprobe measured by wrapping the default planner.
//
// # Suites
//
//   - TestMatrix: the NAT pair matrix and the same-host cell — among them
//     the allocator variants (a downward sequential NAT, a NAT keeping a
//     fresh socket's port) and the Background-mode PDF × RND cells of the
//     slow birthday, gated against its planned model, with scan defence on
//     two of them — each asserted by its expectation class — success or the
//     expected Reason, time bounds, packet counts, rates, distinct ports,
//     consecutive ports, scan bans and the per-socket packet shape — with
//     the resource checks and a kpi.json per cell. The hopeless SYMRND ×
//     SYMRND pair is judged by what natprobe measured; the deliberately
//     misclassified cells, whose
//     NAT changes its behaviour once natprobe has measured it, report their
//     success.
//   - TestShapeAcrossSessions: packet lengths and random ports over
//     consecutive sessions of one NAT pair.
//   - TestMultiPath: two confirmed paths handed over on both sides, each
//     carrying datagrams afterwards.
//   - TestClassifierOpener: the flow opener behind an outbound protocol
//     classifier, with it and without it (ablation NoOpener), written to
//     classifier_report.md.
//   - TestAblation: the ablation, written to ablation_report.md: the
//     combination gate, full at least 13 points above Plain over the 15
//     combinations of profile classes (the 49 ordered IPv4 cells are
//     reported), the class gates beside it (PDF×SEQ and SEQ×SEQ cells at
//     least 90%, model cells by the binomial test against P_model), the
//     per-cell gate against plain punching (on every ordered IPv4 cell and
//     every misclassified cell, full's successes at least Plain's less two
//     in twenty), the
//     per-mechanism table over representative cells — constructed so that
//     round 1 fails where the mechanism only acts after it — the
//     misclassified cells with the punch-time corrections switched off, and
//     the threshold table. It fails when the combination gate, a class gate,
//     the per-cell gate or any threshold not marked report only fails.
//   - TestDefaultTimeouts: twelve representative cells with the library's
//     default timeouts, which reach round 3 and beyond, gated by their class
//     as in the matrix, next to the same cells with the suite's shortened
//     timeouts; written to timeouts_report.md.
//   - TestFaultMatrix, TestFaultUserCode: the client fault matrix (fault ×
//     phase) and its user-code row, with the common assertions;
//     TestFaultInject, with -tags holepunch_faultinject, is its row of
//     injection-point panics.
//   - TestBackgroundEscalation: the eventual direct rate after background
//     escalation, written to escalation_report.md: per hard
//     IPv4 pair, an Interactive session, a Background one when the advice
//     is background_viable, and a third whose summary must say
//     background_only; a KPI beside the combination gate, never part of it.
//   - TestLoadControlPlane, TestLoadClients: the coordinator's control plane
//     under scripted sessions and the whole chain under real client pairs,
//     with -tags load.
//
// # Levels
//
// HOLEPUNCH_E2E_LEVEL selects the level; there is no command-line flag. The
// default level, pr, runs the must cells three times each, the fault
// matrix and the user-code row once, and the shape check on two pairs. The
// nightly level (HOLEPUNCH_E2E_LEVEL=nightly, or the default in a build with
// -tags e2e_nightly) runs every cell twenty times, the fault matrix three
// times, the shape check on three pairs, the ablation, the default-timeout
// comparison and the escalation sequences. HOLEPUNCH_E2E_RUNS and
// HOLEPUNCH_E2E_CELLS (a regular expression over cell names; in the
// ablation over cell@configuration and memory/pair@configuration, in the
// default-timeout comparison over cell@default-timeouts and
// cell@e2e-timeouts, in the escalation over escalation/<v4 cell>) narrow a
// run, HOLEPUNCH_E2E_ABLATION_RUNS and HOLEPUNCH_E2E_ESCALATION_RUNS run the
// ablation and the escalation at any level and HOLEPUNCH_E2E_SEED moves
// every seed. A variable that is set but does not parse fails the run.
// HOLEPUNCH_E2E_OUT names the directory that receives kpi.json files,
// ablation_report.md, timeouts_report.md, escalation_report.md,
// classifier_report.md and failure dumps. Without it nothing is kept:
// failure dumps go to the test's temporary directory and nothing is ever
// written into the source tree.
//
// # Concurrency and resources
//
// Cells run as parallel subtests, at most eight at a time, so that CPU
// contention does not distort the time KPIs; under the race detector every
// time bound is multiplied by three. Each run builds its own simulated
// Internet and coordinator and closes them before it returns; the top-level
// tests run one after the other, so goleak checks the whole process after
// every suite and in TestMain. Helper goroutines of a construct (the
// neighbours that load a NAT) end with their run and the world waits for
// them. TestFaultInject runs its points one at a time: the registry of
// injection points is process-wide.
package e2e
