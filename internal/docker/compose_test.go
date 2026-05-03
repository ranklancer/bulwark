package docker

import (
	"reflect"
	"testing"
)

func TestParseDependsOnLabel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single name", "db", []string{"db"}},
		{"two names", "db,cache", []string{"db", "cache"}},
		{
			"compose v2 triples",
			"db:service_started:true,cache:service_healthy:true",
			[]string{"db", "cache"},
		},
		{
			"mixed shapes",
			"db,cache:service_healthy:true",
			[]string{"db", "cache"},
		},
		{
			"surrounding whitespace",
			" db ,  cache:service_started:true ",
			[]string{"db", "cache"},
		},
		{
			"empty interior entries dropped",
			"db,,cache,",
			[]string{"db", "cache"},
		},
		{
			"colon-only entry dropped",
			"db,:service_started:true,cache",
			[]string{"db", "cache"},
		},
		{
			"duplicates de-duped, first occurrence wins",
			"db,cache,db:service_healthy:true",
			[]string{"db", "cache"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseDependsOnLabel(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseDependsOnLabel(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestContainer_DependsOn(t *testing.T) {
	t.Run("non-compose container returns nil", func(t *testing.T) {
		c := Container{Labels: map[string]string{"foo": "bar"}}
		if got := c.DependsOn(); got != nil {
			t.Errorf("non-compose container DependsOn() = %#v, want nil", got)
		}
	})
	t.Run("compose container with no depends_on returns nil", func(t *testing.T) {
		c := Container{Labels: map[string]string{
			"com.docker.compose.project": "demo",
			"com.docker.compose.service": "web",
		}}
		if got := c.DependsOn(); got != nil {
			t.Errorf("no-deps container DependsOn() = %#v, want nil", got)
		}
	})
	t.Run("compose container with depends_on", func(t *testing.T) {
		c := Container{Labels: map[string]string{
			"com.docker.compose.project":     "demo",
			"com.docker.compose.service":     "web",
			"com.docker.compose.depends_on":  "db:service_started:true,cache:service_healthy:true",
		}}
		got := c.DependsOn()
		want := []string{"db", "cache"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("DependsOn() = %#v, want %#v", got, want)
		}
	})
	t.Run("nil labels map is safe", func(t *testing.T) {
		c := Container{}
		if got := c.DependsOn(); got != nil {
			t.Errorf("nil-labels DependsOn() = %#v, want nil", got)
		}
	})
}
