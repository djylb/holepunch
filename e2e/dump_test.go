package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/protocol"
)

// failureDump is the file a failed run leaves: the seed, both
// clients' outcomes with their diagnostics, the coordinator's Result, the
// last 100 progress reports, the decoded control frames and the network
// dump, embedded as raw JSON.
type failureDump struct {
	Cell       string          `json:"cell"`
	Seed       int64           `json:"seed"`
	Ablation   string          `json:"ablation"`
	Violations []string        `json:"violations"`
	Metrics    runMetrics      `json:"metrics"`
	Clients    [2]dumpClient   `json:"clients"`
	Coord      *coord.Result   `json:"coord,omitempty"`
	Frames     [2][]dumpFrame  `json:"frames"`
	Network    json.RawMessage `json:"network"`
}

type dumpClient struct {
	Role        protocol.Role         `json:"role"`
	Error       string                `json:"error,omitempty"`
	Reason      protocol.Reason       `json:"reason,omitempty"`
	Phase       protocol.Phase        `json:"phase,omitempty"`
	Detail      string                `json:"detail,omitempty"`
	Result      *holepunch.Result     `json:"result,omitempty"`
	Diagnostics holepunch.Diagnostics `json:"diagnostics"`
	Duration    string                `json:"duration"`
	Progress    []*protocol.Progress  `json:"progress,omitempty"`
}

type dumpFrame struct {
	At   string `json:"at"`
	Dir  string `json:"dir"`
	Type string `json:"type"`
	Size int    `json:"size"`
	Msg  any    `json:"msg,omitempty"`
}

// maxDumpProgress is how many progress reports per side a dump keeps.
const maxDumpProgress = 100

// dump writes the failure file of a run and returns its path.
func (cr *cellRun) dump(t testing.TB, violations []string, ablationName string) (string, error) {
	r := cr.r
	d := failureDump{Cell: cr.c.name, Seed: cr.seed, Ablation: ablationName, Violations: violations, Metrics: cr.m}
	if r.resOK {
		res := r.res
		d.Coord = &res
	}
	for i := range 2 {
		o := &r.out[i]
		dc := dumpClient{Role: roles[i], Diagnostics: o.diag, Duration: o.dur().String()}
		if o.err != nil {
			dc.Error = o.err.Error()
		}
		if o.herr != nil {
			dc.Reason, dc.Phase, dc.Detail = o.herr.Reason, o.herr.Phase, o.herr.Detail
		}
		if o.sess != nil {
			res := o.sess.Result()
			dc.Result = &res
		}
		p := cr.links[i].progress
		if len(p) > maxDumpProgress {
			p = p[len(p)-maxDumpProgress:]
		}
		dc.Progress = p
		d.Clients[i] = dc
		var start time.Time
		for _, ev := range r.taps[i].log() {
			if start.IsZero() {
				start = ev.At
			}
			f := dumpFrame{At: ev.At.Sub(start).String(), Dir: ev.Dir.String(), Type: ev.Type.String(), Size: ev.Size}
			if ev.Msg != nil {
				f.Msg = ev.Msg
			}
			d.Frames[i] = append(d.Frames[i], f)
		}
	}
	var nb bytes.Buffer
	if err := cr.w.n.Dump(&nb); err == nil {
		d.Network = nb.Bytes()
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%d.json", strings.NewReplacer("/", "__", "~", "n", "+", "p").Replace(cr.c.name), cr.seed)
	if ablationName != "" && ablationName != "full" {
		name = ablationName + "/" + name
	}
	dir := failureDir(t)
	return filepath.Join(dir, name), writeOut(dir, name, b)
}
