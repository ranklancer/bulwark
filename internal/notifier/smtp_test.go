package notifier

import (
	"context"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

type capturedMail struct {
	Addr    string
	Auth    smtp.Auth
	From    string
	To      []string
	Message string
}

func captureSend(c *capturedMail) func(string, smtp.Auth, string, []string, []byte) error {
	return func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		c.Addr = addr
		c.Auth = auth
		c.From = from
		c.To = append([]string(nil), to...)
		c.Message = string(msg)
		return nil
	}
}

func TestNewSMTP_RequiredFields(t *testing.T) {
	cases := []struct {
		name string
		c    config.SMTPConfig
	}{
		{"missing host", config.SMTPConfig{From: "a@example.com", To: []string{"b@example.com"}}},
		{"missing from", config.SMTPConfig{Host: "smtp.example.com", To: []string{"b@example.com"}}},
		{"missing to", config.SMTPConfig{Host: "smtp.example.com", From: "a@example.com"}},
		{"bad from", config.SMTPConfig{Host: "smtp.example.com", From: "not-an-email", To: []string{"b@example.com"}}},
		{"bad to", config.SMTPConfig{Host: "smtp.example.com", From: "a@example.com", To: []string{"not-an-email"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSMTP(tc.c, types.RiskSafe, ""); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestSMTP_RendersMultipartMessage(t *testing.T) {
	cap := &capturedMail{}
	n, err := NewSMTP(config.SMTPConfig{
		Host: "smtp.example.com", Port: 587,
		From: "bulwark@example.com",
		To:   []string{"admin@example.com"},
	}, types.RiskSafe, "")
	if err != nil {
		t.Fatal(err)
	}
	n.Send = captureSend(cap)
	n.Now = func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) }

	if err := n.Notify(context.Background(), []Event{{
		Container: "demo", Image: "ghcr.io/owner/app:1.2.3",
		From: "1.2.2", To: "1.2.3", Risk: types.RiskReview, Kind: types.ChangePatch,
		Rationale:  "patch bump",
		ReleaseURL: "https://example.com/release",
	}}); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if cap.Addr != "smtp.example.com:587" {
		t.Errorf("addr = %q", cap.Addr)
	}
	if cap.From != "bulwark@example.com" {
		t.Errorf("from = %q", cap.From)
	}
	if len(cap.To) != 1 || cap.To[0] != "admin@example.com" {
		t.Errorf("to = %v", cap.To)
	}

	msg := cap.Message
	if !strings.Contains(msg, "From: bulwark@example.com") {
		t.Error("missing From header")
	}
	if !strings.Contains(msg, "To: admin@example.com") {
		t.Error("missing To header")
	}
	if !strings.Contains(msg, "Subject: ") {
		t.Error("missing Subject header")
	}
	if !strings.Contains(msg, "Content-Type: multipart/alternative") {
		t.Error("missing multipart content-type")
	}
	if !strings.Contains(msg, "Content-Type: text/plain") {
		t.Error("missing text/plain part")
	}
	if !strings.Contains(msg, "Content-Type: text/html") {
		t.Error("missing text/html part")
	}
	if !strings.Contains(msg, "demo") || !strings.Contains(msg, "ghcr.io/owner/app:1.2.3") {
		t.Error("body missing core event data")
	}
	if !strings.Contains(msg, "1.2.2") || !strings.Contains(msg, "1.2.3") {
		t.Error("body missing version transition")
	}
	if !strings.Contains(msg, "https://example.com/release") {
		t.Error("body missing release URL")
	}
}

func TestSMTP_SubjectForMultipleEventsCountsThem(t *testing.T) {
	cap := &capturedMail{}
	n, err := NewSMTP(config.SMTPConfig{
		Host: "smtp.example.com", From: "a@example.com", To: []string{"b@example.com"},
	}, types.RiskSafe, "")
	if err != nil {
		t.Fatal(err)
	}
	n.Send = captureSend(cap)

	events := []Event{
		{Container: "x", Risk: types.RiskSafe},
		{Container: "y", Risk: types.RiskReview},
		{Container: "z", Risk: types.RiskBreaking},
	}
	if err := n.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cap.Message, "Subject: Bulwark scan: 3 update(s)") {
		t.Errorf("multi-event subject missing count: %s", firstLineWithPrefix(cap.Message, "Subject:"))
	}
}

func TestSMTP_HTMLEscapesUntrustedFields(t *testing.T) {
	cap := &capturedMail{}
	n, err := NewSMTP(config.SMTPConfig{
		Host: "smtp.example.com", From: "a@example.com", To: []string{"b@example.com"},
	}, types.RiskSafe, "")
	if err != nil {
		t.Fatal(err)
	}
	n.Send = captureSend(cap)

	if err := n.Notify(context.Background(), []Event{{
		Container: `<script>alert(1)</script>`,
		Image:     "x",
		Risk:      types.RiskReview,
	}}); err != nil {
		t.Fatal(err)
	}

	// Look at the HTML part specifically — text/plain legitimately contains
	// the raw characters as a representation of the container name.
	htmlIdx := strings.Index(cap.Message, "Content-Type: text/html")
	if htmlIdx < 0 {
		t.Fatal("missing HTML part")
	}
	htmlPart := cap.Message[htmlIdx:]
	if strings.Contains(htmlPart, "<script>alert(1)</script>") {
		t.Error("unescaped script tag leaked into HTML part")
	}
	if !strings.Contains(htmlPart, "&lt;script&gt;") {
		t.Errorf("expected escaped form &lt;script&gt; in HTML body; got %s", htmlPart)
	}
}

func firstLineWithPrefix(msg, prefix string) string {
	for _, line := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}
