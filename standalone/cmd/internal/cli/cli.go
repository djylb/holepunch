package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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

// Status reports err, what a command's run returned, on w with the command
// name in front and returns the exit status: 0 for nil and for
// flag.ErrHelp, whose usage the flag set has printed already, 1 otherwise.
func Status(w io.Writer, name string, err error) int {
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	}
	_, _ = fmt.Fprintf(w, "%s: %v\n", name, err)
	return 1
}

// IsHelp reports whether arg, a command's first argument, asks for its
// usage: -h, -help, --help or help.
func IsHelp(arg string) bool {
	switch arg {
	case "-h", "-help", "--help", "help":
		return true
	}
	return false
}

// Dispatch runs the subcommand args[0] of the command name and exits with
// its status. Without a subcommand, or with an unknown one, it prints usage
// on stderr and exits with status 2; asked for help, it prints usage on
// stdout and exits with status 0.
func Dispatch(name, usage string, args []string, cmds map[string]func(args []string) error) {
	os.Exit(dispatch(os.Stdout, os.Stderr, name, usage, args, cmds))
}

func dispatch(stdout, stderr io.Writer, name, usage string, args []string, cmds map[string]func([]string) error) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	if IsHelp(args[0]) {
		_, _ = fmt.Fprintln(stdout, usage)
		return 0
	}
	run, ok := cmds[args[0]]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "%s: unknown command %q\n%s\n", name, args[0], usage)
		return 2
	}
	return Status(stderr, name, run(args[1:]))
}
