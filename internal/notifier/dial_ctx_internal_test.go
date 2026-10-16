package notifier

import (
	"context"
	"testing"
)

// TestSMTPSendFuncTLSHonorsCanceledContext proves the TLS transport returns
// promptly instead of blocking on a dial when the caller context is already
// canceled -- the notifier must not hang on a dead relay when alerts matter.
func TestSMTPSendFuncTLSHonorsCanceledContext(t *testing.T) {
	send := smtpSendFunc(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// 203.0.113.0/24 (TEST-NET-3) is reserved and unroutable.
	err := send(ctx, "203.0.113.1:465", nil, "from@example.test", []string{"to@example.test"}, []byte("x"))
	if err == nil {
		t.Fatal("expected error from canceled-context TLS send, got nil")
	}
}
