package docker

import "testing"

func TestNewEndpointSelection(t *testing.T) {
	cases := map[string]string{
		"":                            "http://docker",
		"/var/run/docker.sock":        "http://docker",
		"unix:///var/run/docker.sock": "http://docker",
		"tcp://socket-proxy:2375":     "http://socket-proxy:2375",
		"http://127.0.0.1:2375":       "http://127.0.0.1:2375",
		"https://127.0.0.1:2376/":     "https://127.0.0.1:2376",
	}
	for in, want := range cases {
		if got := New(in).BaseURL; got != want {
			t.Errorf("New(%q).BaseURL = %q, want %q", in, got, want)
		}
	}
}
