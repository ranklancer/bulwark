package api

import (
	"io"
	"log/slog"
)

// slogDiscard returns a logger that drops every record. Used by tests that
// don't care about log output but need a non-nil *slog.Logger.
func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
