package docker

import "strings"

// composeDependsOnLabel is the standard label Compose v2 sets on every
// container that has a depends_on stanza in its compose file. The value is
// a comma-joined list of "<service>:<condition>:<required>" triples, e.g.
//
//	db:service_started:true,cache:service_healthy:true
//
// Older Compose versions and hand-applied labels may omit the condition +
// required suffix, leaving a plain comma-separated list of service names.
// We accept both shapes — only the leading service name on each entry is
// used by Bulwark today; the condition / required hints are advisory and
// not consulted during the apply ordering pass.
const composeDependsOnLabel = "com.docker.compose.depends_on"

// ParseDependsOnLabel returns the Compose service names a container
// declares as dependencies, in the order they appear in the label.
//
// Tolerant by design: blank entries are dropped, surrounding whitespace is
// trimmed, and entries containing a ':' are split so only the leading
// service name survives. Returns nil for the empty string.
func ParseDependsOnLabel(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry == "" {
			continue
		}
		if i := strings.IndexByte(entry, ':'); i >= 0 {
			entry = strings.TrimSpace(entry[:i])
		}
		if entry == "" {
			continue
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DependsOn reports the Compose service names this container depends on,
// parsed from the standard com.docker.compose.depends_on label. Returns nil
// for non-Compose containers and for Compose containers without a
// depends_on stanza.
func (c Container) DependsOn() []string {
	return ParseDependsOnLabel(c.Labels[composeDependsOnLabel])
}
