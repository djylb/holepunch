package cli

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// StringList is a repeatable string flag.
type StringList []string

// String joins the values.
func (s *StringList) String() string { return strings.Join(*s, ",") }

// Set appends a value; empty values are ignored.
func (s *StringList) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		*s = append(*s, v)
	}
	return nil
}

// Logger returns a text logger on stderr, at debug level when debug is set.
func Logger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// SignalContext is canceled by SIGINT or SIGTERM.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
