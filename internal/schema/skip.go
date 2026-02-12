package schema

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reLabel = regexp.MustCompile(`:([A-Za-z0-9_]+)`)   // :User
	reRel   = regexp.MustCompile(`\[:([A-Za-z0-9_]+)`) // [:MemberOf
)

type Presence struct {
	Labels map[string]struct{}
	Rels   map[string]struct{}
}

func PresenceFromSummary(s Summary) Presence {
	p := Presence{Labels: map[string]struct{}{}, Rels: map[string]struct{}{}}
	for _, l := range s.Labels {
		p.Labels[strings.ToLower(l)] = struct{}{}
	}
	for _, r := range s.Rels {
		p.Rels[strings.ToLower(r)] = struct{}{}
	}
	return p
}

func CanRunCypher(cypher string, p Presence) (bool, string) {
	// Best-effort: if we reference a label/rel that doesn't exist, skip.
	labels := reLabel.FindAllStringSubmatch(cypher, -1)
	for _, m := range labels {
		l := strings.ToLower(m[1])
		if l == "" {
			continue
		}
		if _, ok := p.Labels[l]; !ok {
			return false, fmt.Sprintf("missing label: %s", m[1])
		}
	}
	rels := reRel.FindAllStringSubmatch(cypher, -1)
	for _, m := range rels {
		r := strings.ToLower(m[1])
		if r == "" {
			continue
		}
		if _, ok := p.Rels[r]; !ok {
			return false, fmt.Sprintf("missing relationship type: %s", m[1])
		}
	}
	return true, ""
}
