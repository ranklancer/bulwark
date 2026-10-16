package notifier

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"text/template"
	"time"

	htmltemplate "html/template"

	"github.com/ranklancer/bulwark/internal/config"
	"github.com/ranklancer/bulwark/pkg/types"
)

//go:embed templates/subject.tmpl templates/text.tmpl templates/html.tmpl
var smtpTemplatesFS embed.FS

// SMTPNotifier delivers a single multipart/alternative email per Notify
// call, batching all events into one message. Templates for subject,
// text body, and HTML body live under internal/notifier/templates/ and
// are embedded at build time so deployment is a single binary.
//
// Send is the function actually responsible for handing the assembled
// message to an SMTP server. Production wiring uses smtpSendFunc (which
// wraps net/smtp.SendMail with optional STARTTLS); tests inject a
// capturing stub.
type SMTPNotifier struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	UseTLS   bool

	Min types.RiskLevel

	// Send is the mail-sending hook. nil means use the default
	// net/smtp transport.
	Send func(ctx context.Context, addr string, auth smtp.Auth, from string, to []string, msg []byte) error

	// Now is injected for deterministic tests; nil = time.Now.
	Now func() time.Time

	subjectTmpl *template.Template
	textTmpl    *template.Template
	htmlTmpl    *htmltemplate.Template

	channelName string
}

// NewSMTP builds an SMTP notifier from the YAML config. The notifier
// fails to construct if Host or From or To are missing — silently
// dropping mail because of a typo'd config is exactly the failure mode
// operators ask us to avoid.
func NewSMTP(c config.SMTPConfig, min types.RiskLevel, name string) (*SMTPNotifier, error) {
	if c.Host == "" {
		return nil, errors.New("smtp: host is required")
	}
	if c.Port == 0 {
		c.Port = 25
	}
	if c.From == "" {
		return nil, errors.New("smtp: from is required")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return nil, fmt.Errorf("smtp: invalid from %q: %w", c.From, err)
	}
	if len(c.To) == 0 {
		return nil, errors.New("smtp: at least one recipient is required")
	}
	for _, addr := range c.To {
		if _, err := mail.ParseAddress(addr); err != nil {
			return nil, fmt.Errorf("smtp: invalid recipient %q: %w", addr, err)
		}
	}
	if min == types.RiskUnknown {
		min = types.RiskReview
	}
	if name == "" {
		name = "smtp"
	}

	subjectTmpl, err := template.ParseFS(smtpTemplatesFS, "templates/subject.tmpl")
	if err != nil {
		return nil, fmt.Errorf("smtp: parse subject template: %w", err)
	}
	textTmpl, err := template.ParseFS(smtpTemplatesFS, "templates/text.tmpl")
	if err != nil {
		return nil, fmt.Errorf("smtp: parse text template: %w", err)
	}
	htmlTmpl, err := htmltemplate.ParseFS(smtpTemplatesFS, "templates/html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("smtp: parse html template: %w", err)
	}

	return &SMTPNotifier{
		Host:        c.Host,
		Port:        c.Port,
		Username:    c.Username,
		Password:    c.Password,
		From:        c.From,
		To:          append([]string(nil), c.To...),
		UseTLS:      c.TLS,
		Min:         min,
		subjectTmpl: subjectTmpl,
		textTmpl:    textTmpl,
		htmlTmpl:    htmlTmpl,
		channelName: name,
	}, nil
}

func (s *SMTPNotifier) Name() string              { return s.channelName }
func (s *SMTPNotifier) MinLevel() types.RiskLevel { return s.Min }

// Notify renders subject + text + HTML, assembles a multipart/alternative
// message, and hands it to Send. A single transport error is returned —
// SMTP is all-or-nothing per call.
func (s *SMTPNotifier) Notify(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	now := s.now()

	view := smtpView{Now: now.UTC()}
	for _, e := range events {
		view.Events = append(view.Events, smtpEventView{
			Title:      titleFor(e),
			Container:  e.Container,
			Image:      e.Image,
			From:       e.From,
			To:         e.To,
			Kind:       e.Kind.String(),
			Risk:       riskLabel(e.Risk),
			Action:     e.Action.String(),
			Rationale:  e.Rationale,
			ReleaseURL: e.ReleaseURL,
			StackPeer:  stackPeerFromEvent(e),
			Project:    e.ComposeProject,
			Color:      colorForRisk(e.Risk, e.Action),
		})
	}

	var subjBuf, textBuf, htmlBuf bytes.Buffer
	if err := s.subjectTmpl.Execute(&subjBuf, view); err != nil {
		return fmt.Errorf("smtp: render subject: %w", err)
	}
	if err := s.textTmpl.Execute(&textBuf, view); err != nil {
		return fmt.Errorf("smtp: render text: %w", err)
	}
	if err := s.htmlTmpl.Execute(&htmlBuf, view); err != nil {
		return fmt.Errorf("smtp: render html: %w", err)
	}

	msg, err := buildMessage(s.From, s.To, strings.TrimSpace(subjBuf.String()), textBuf.String(), htmlBuf.String(), now)
	if err != nil {
		return fmt.Errorf("smtp: assemble message: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}

	send := s.Send
	if send == nil {
		send = smtpSendFunc(s.UseTLS)
	}
	if err := send(ctx, addr, auth, s.From, s.To, msg); err != nil {
		return fmt.Errorf("smtp: send: %w", err)
	}
	return nil
}

func (s *SMTPNotifier) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// smtpDialTimeout bounds the TCP/TLS dial to an SMTP server so a dead or
// slow relay cannot hang the notifier, which runs precisely when the system
// is already unhealthy. Overall cancellation is governed by the caller
// context threaded through Send.
const smtpDialTimeout = 10 * time.Second

// smtpSendFunc returns a transport. When useTLS is true it uses implicit TLS
// (dial-then-TLS, e.g. :465). Otherwise net/smtp.SendMail handles plain or STARTTLS transparently
// when the server advertises STARTTLS in EHLO; the explicit dial-then-tls
// path is taken only when the operator has flagged it.
func smtpSendFunc(useTLS bool) func(context.Context, string, smtp.Auth, string, []string, []byte) error {
	if !useTLS {
		return func(ctx context.Context, addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// net/smtp.SendMail refuses to send AUTH over an unencrypted link; keep it.
			// NOTE: SendMail's internal dial is unbounded, so a plaintext send to a
			// dead relay can still hang (tracked follow-up); ctx short-circuits pre-dial.
			return smtp.SendMail(addr, auth, from, to, msg)
		}
	}
	return func(ctx context.Context, addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		host, _, err := splitHostPort(addr)
		if err != nil {
			return err
		}
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: smtpDialTimeout},
			Config:    &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		// Client.Quit does not close the conn if QUIT errors (half-dead relay);
		// back it up so the socket fd is always released.
		defer func() { _ = conn.Close() }()
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return err
		}
		defer func() { _ = client.Quit() }()
		if auth != nil {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return err
				}
			}
		}
		if err := client.Mail(from); err != nil {
			return err
		}
		for _, rcpt := range to {
			if err := client.Rcpt(rcpt); err != nil {
				return err
			}
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(msg); err != nil {
			return err
		}
		return w.Close()
	}
}

func splitHostPort(addr string) (string, string, error) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, "", errors.New("smtp: addr missing port")
	}
	return addr[:idx], addr[idx+1:], nil
}

// buildMessage hand-rolls a multipart/alternative RFC822 message. The
// boundary is randomised so a malicious-looking event body can't smuggle
// its way into being interpreted as a part separator.
func buildMessage(from string, to []string, subject, textBody, htmlBody string, now time.Time) ([]byte, error) {
	boundary, err := randomBoundary()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeHeader(subject))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n", boundary)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(textBody)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

func randomBoundary() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "bulwark-" + hex.EncodeToString(buf), nil
}

// encodeHeader wraps non-ASCII subjects in MIME RFC2047 encoded-words.
// Pure ASCII passes through unchanged so plain subjects stay readable.
func encodeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return mime.QEncoding.Encode("utf-8", s)
		}
	}
	return s
}

// smtpView is the data passed to all three templates.
type smtpView struct {
	Events []smtpEventView
	Now    time.Time
}

type smtpEventView struct {
	Title      string
	Container  string
	Image      string
	From, To   string
	Kind       string
	Risk       string
	Action     string
	Rationale  string
	ReleaseURL string
	StackPeer  string
	Project    string
	Color      string
}

func riskLabel(r types.RiskLevel) string {
	switch r {
	case types.RiskBreaking:
		return "BREAKING"
	case types.RiskReview:
		return "REVIEW"
	case types.RiskSafe:
		return "SAFE"
	default:
		return "UNKNOWN"
	}
}

func colorForRisk(r types.RiskLevel, a types.UpdateAction) string {
	if a == types.ActionRolledBack {
		return "#c0392b"
	}
	switch r {
	case types.RiskBreaking:
		return "#c0392b"
	case types.RiskReview:
		return "#d68910"
	case types.RiskSafe:
		return "#229954"
	default:
		return "#7f8c8d"
	}
}

// stackPeerFromEvent decodes a "[stack-skipped: peer=foo]" hint that
// callers may have folded into the Rationale field. For Phase 13 we
// don't surface a structured StackPeer on Event yet — the apply path
// already records it in the audit log; the email/HA/etc. notifications
// just see the title prefix. Returns "" when there's nothing to extract.
func stackPeerFromEvent(e Event) string {
	if e.Action != types.ActionStackSkipped {
		return ""
	}
	// The audit log carries the precise reason; we keep the email body
	// intentionally short by not duplicating the same string here.
	return ""
}
