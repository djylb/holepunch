package protocol

import (
	"testing"

	"github.com/djylb/holepunch/controlwire"
)

func benchFrame(b *testing.B, m Message) controlwire.Frame {
	f, err := Marshal(m)
	if err != nil {
		b.Fatal(err)
	}
	return f
}

func BenchmarkMarshalAssist(b *testing.B) {
	m := sample[Assist]()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Marshal(m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeAssist(b *testing.B) {
	f := benchFrame(b, sample[Assist]())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Unmarshal[Assist](f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeProbeReport(b *testing.B) {
	f := benchFrame(b, sample[ProbeReport]())
	b.SetBytes(int64(len(f.Payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Unmarshal[ProbeReport](f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalProbeSummary(b *testing.B) {
	m := sample[ProbeSummary]()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Marshal(m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodePunchGo(b *testing.B) {
	f := benchFrame(b, sample[PunchGo]())
	b.ReportAllocs()
	for b.Loop() {
		m, err := Decode(f)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = m.(*PunchGo).Normalize()
	}
}
