package e2e

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// cellKPI is the kpi.json of one cell.
type cellKPI struct {
	Cell              string         `json:"cell"`
	Group             string         `json:"group"`
	Class             string         `json:"class"`
	Base              string         `json:"base"`
	Level             string         `json:"level"`
	Ablation          string         `json:"ablation"`
	Runs              int            `json:"runs"`
	Seeds             []int64        `json:"seeds"`
	Successes         int            `json:"successes"`
	SuccessRate       float64        `json:"success_rate"`
	HalfConfirmedRate float64        `json:"half_confirmed_rate"`
	ConfirmMs         quantiles      `json:"confirm_ms"` // successful runs, the slower side
	PacketsPerSide    quantiles      `json:"packets_per_side"`
	HostPacketsSide   quantiles      `json:"host_packets_per_side"`
	PeakPPS1s         int            `json:"peak_pps_1s"`
	PeakPPS100ms      int            `json:"peak_pps_100ms"`
	PeakPPSInitiated  int            `json:"peak_pps_initiated"`
	DistinctPorts     int            `json:"distinct_ports_per_ip_10s"`
	MaxConsecutiveRun int            `json:"max_consecutive_run"`
	ScanBans          uint64         `json:"scan_bans"`
	FilteredInbound   quantiles      `json:"filtered_inbound"`
	Rounds            quantiles      `json:"rounds"`
	RoundClass        map[string]int `json:"round_class"`
	VariantSequence   map[string]int `json:"variant_sequence"`
	ControlFrames     quantiles      `json:"control_frames_per_session"`
	RefreshRuns       int            `json:"refresh_runs"` // runs with an anchor refresh
	FirstSendSkewMs   quantiles      `json:"first_send_skew_ms"`
	FireSkewMs        quantiles      `json:"fire_skew_ms"`
	ConfirmRound      quantiles      `json:"confirm_round"`
	FailureCodes      map[string]int `json:"failure_codes"`
	CandKinds         map[string]int `json:"cand_kinds,omitempty"`
	Families          map[string]int `json:"families,omitempty"`
	Paths             map[string]int `json:"paths,omitempty"` // successful runs' sides by how many paths they handed over
	MaxClass          map[string]int `json:"max_class"`
	PModel            float64        `json:"p_model,omitempty"` // mean over runs (model class)
	Gate              string         `json:"gate"`
	Pass              bool           `json:"pass"`
	Problems          []string       `json:"problems,omitempty"`
	RunsDetail        []runMetrics   `json:"runs_detail,omitempty"`
	Elapsed           string         `json:"elapsed"`
}

// quantiles summarises a sample; -1 for an empty one.
type quantiles struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

// quant computes nearest-rank quantiles.
func quant(xs []float64) quantiles {
	if len(xs) == 0 {
		return quantiles{P50: -1, P90: -1, P95: -1, Max: -1}
	}
	s := slices.Clone(xs)
	sort.Float64s(s)
	at := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		return s[max(i, 0)]
	}
	return quantiles{N: len(s), P50: at(0.5), P90: at(0.9), P95: at(0.95), Max: s[len(s)-1]}
}

// kpiOf aggregates the runs of a cell.
func kpiOf(c *cell, ablationName string, runs []*cellRun, elapsed time.Duration) cellKPI {
	k := cellKPI{Cell: c.name, Group: c.group, Class: c.class.String(), Base: c.base.String(), Level: suite().level.String(),
		Ablation: ablationName, Runs: len(runs), RoundClass: map[string]int{}, VariantSequence: map[string]int{},
		FailureCodes: map[string]int{}, CandKinds: map[string]int{}, Families: map[string]int{}, Paths: map[string]int{}, MaxClass: map[string]int{},
		Elapsed: elapsed.Round(time.Millisecond).String()}
	var confirm, packets, host, filtered, rounds, frames, skew, fire, cround []float64
	half, pm := 0, 0.0
	for _, cr := range runs {
		m := &cr.m
		k.Seeds = append(k.Seeds, cr.seed)
		k.RunsDetail = append(k.RunsDetail, *m)
		if m.OK {
			k.Successes++
			confirm = append(confirm, max(m.ConfirmMs[0], m.ConfirmMs[1]))
			cround = append(cround, float64(m.ConfirmRound))
			k.CandKinds[string(m.CandKind)]++
			k.Families[string(m.Family)]++
			for _, n := range m.Paths {
				k.Paths[strconv.Itoa(n)]++
			}
			if m.HalfConfirmed {
				half++
			}
		} else {
			code := string(m.Code)
			if code == "" {
				code = fmt.Sprintf("%s/%s", m.Reasons[0], m.Reasons[1])
			}
			k.FailureCodes[code]++
		}
		for i := range 2 {
			packets = append(packets, float64(m.Packets[i]))
			host = append(host, float64(m.HostPackets[i]))
			filtered = append(filtered, float64(m.Filtered[i]))
			k.PeakPPS1s = max(k.PeakPPS1s, m.PeakPPS1s[i])
			k.PeakPPS100ms = max(k.PeakPPS100ms, m.PeakPPS100ms[i])
			k.PeakPPSInitiated = max(k.PeakPPSInitiated, m.PeakPPSInit[i])
			k.DistinctPorts = max(k.DistinctPorts, m.DistinctPorts[i])
			k.MaxConsecutiveRun = max(k.MaxConsecutiveRun, m.MaxRun[i])
		}
		k.ScanBans += m.ScanBans
		rounds = append(rounds, float64(m.Rounds))
		frames = append(frames, float64(m.CtlFrames))
		if m.Refreshes > 0 {
			k.RefreshRuns++
		}
		for _, rc := range m.RoundClasses {
			k.RoundClass[rc]++
		}
		if len(m.Variants) > 0 {
			k.VariantSequence[strings.Join(m.Variants, ">")]++
		}
		k.MaxClass[string(m.MaxClass)]++
		if m.SkewMs >= 0 {
			skew = append(skew, m.SkewMs)
		}
		if m.FireSkewMs >= 0 {
			fire = append(fire, m.FireSkewMs)
		}
		pm += m.PModel
	}
	if n := len(runs); n > 0 {
		k.SuccessRate = float64(k.Successes) / float64(n)
		k.PModel = pm / float64(n)
	}
	if k.Successes > 0 {
		k.HalfConfirmedRate = float64(half) / float64(k.Successes)
	}
	k.ConfirmMs, k.PacketsPerSide, k.HostPacketsSide = quant(confirm), quant(packets), quant(host)
	k.FilteredInbound, k.Rounds, k.ControlFrames = quant(filtered), quant(rounds), quant(frames)
	k.FirstSendSkewMs, k.FireSkewMs, k.ConfirmRound = quant(skew), quant(fire), quant(cround)
	return k
}

// writeKPI writes a cell's kpi.json below the output directory.
func writeKPI(dir string, k cellKPI) error {
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	name := strings.NewReplacer("/", "__", ">", "_", "~", "n", "+", "p").Replace(k.Cell)
	if k.Ablation != "" && k.Ablation != "full" {
		name += "@" + k.Ablation
	}
	return writeOut(dir, name+".kpi.json", b)
}

// binomialCDF returns P(X ≤ k) for X ~ Binomial(n, p).
func binomialCDF(k, n int, p float64) float64 {
	if k >= n {
		return 1
	}
	if p <= 0 {
		return 1
	}
	if p >= 1 {
		return 0
	}
	sum := 0.0
	for i := 0; i <= k; i++ {
		lg := lgamma(n+1) - lgamma(i+1) - lgamma(n-i+1)
		sum += math.Exp(lg + float64(i)*math.Log(p) + float64(n-i)*math.Log(1-p))
	}
	return min(sum, 1)
}

func lgamma(n int) float64 {
	v, _ := math.Lgamma(float64(n))
	return v
}
