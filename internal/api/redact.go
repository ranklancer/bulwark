package api

// Sensitive YAML/JSON keys whose values are wholesale redacted before
// the dashboard sees them. Match is exact + case-sensitive — these
// are the literal yaml-tag forms used in internal/config.
var sensitiveKeys = map[string]struct{}{
	"token":          {},
	"password":       {},
	"hmac_secret":    {},
	"webhook_url":    {},
	"identity_token": {},
}

// redactSecrets walks an unmarshalled JSON tree (map[string]any /
// []any of strings, numbers, bools) and replaces every sensitive
// string value with "***". The walk is recursive so credentials
// nested inside notifications.smtp.password etc. are caught no matter
// how deep they live.
//
// Empty strings are left as-is so the dashboard can distinguish
// "field exists but no secret configured" from "field is a redacted
// secret". Non-string sensitive values (numbers, bools) are also
// left alone — Bulwark's schema doesn't put secrets in those
// positions, but if it ever does the walker can grow.
func redactSecrets(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			if _, ok := sensitiveKeys[k]; ok {
				if s, ok := vv.(string); ok && s != "" {
					x[k] = "***"
					continue
				}
			}
			redactSecrets(vv)
		}
	case []any:
		for _, item := range x {
			redactSecrets(item)
		}
	}
}
