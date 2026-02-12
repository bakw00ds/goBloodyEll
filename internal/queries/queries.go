package queries

import (
	"fmt"
	"sort"
	"strings"
)

type Query struct {
	ID           string
	Title        string
	Category     string // AD | EntraID | INFO
	SheetName    string
	Headers      []string
	Description  string
	FindingTitle string
	Cypher       string
	ColumnKeys   []string // resolved from Headers
}

func (q Query) WithResolvedKeys() Query {
	q.ColumnKeys = make([]string, 0, len(q.Headers))
	for _, h := range q.Headers {
		q.ColumnKeys = append(q.ColumnKeys, HeaderToKey(h))
	}
	return q
}

func HeaderToKey(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	switch h {
	case "hostname", "computer":
		return "computer"
	case "operating system", "os":
		return "os"
	case "user", "username":
		return "user"
	case "principal":
		return "principal"
	case "type":
		return "type"
	case "description":
		return "description"
	case "group names", "group_names", "group":
		return "group"
	case "groupname":
		return "groupname"
	case "password set", "password_set":
		return "pwdlastset"
	case "service acct?", "service_acct?", "service acct", "service_acct":
		return "service_acct"
	case "samaccountname":
		return "samaccountname"
	case "fqdn":
		return "fqdn"
	default:
		h = strings.ReplaceAll(h, " ", "_")
		return h
	}
}

func FilterCategoryStrict(in []Query, category string) ([]Query, error) {
	category = strings.TrimSpace(category)
	if category == "" || strings.EqualFold(category, "all") {
		return in, nil
	}
	allowed := map[string]struct{}{"ad": {}, "entraid": {}, "info": {}}
	if _, ok := allowed[strings.ToLower(category)]; !ok {
		return nil, fmt.Errorf("invalid --category %q (expected: all|AD|EntraID|INFO)", category)
	}
	out := make([]Query, 0)
	for _, q := range in {
		if strings.EqualFold(q.Category, category) {
			out = append(out, q)
		}
	}
	return out, nil
}

// Order enforces tab ordering:
// 1) All Users
// 2) All Computers
// 3) Domain Admins
// 4) Domain Controllers
// then grouped by Category: AD, EntraID, INFO (each in existing order)
func Order(in []Query) []Query {
	idx := map[string]int{
		"ad-all-users-samaccountname": 1,
		"ad-all-computers-fqdn":       2,
		"ad-domain-admins":            3,
		"ad-domain-controllers":       4,
	}
	out := append([]Query(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		iq, jq := out[i], out[j]
		ii, iok := idx[iq.ID]
		jj, jok := idx[jq.ID]
		if iok || jok {
			if !iok {
				return false
			}
			if !jok {
				return true
			}
			return ii < jj
		}

		ci := catRank(iq.Category)
		cj := catRank(jq.Category)
		if ci != cj {
			return ci < cj
		}
		// preserve input order within category
		return false
	})
	return out
}

func catRank(cat string) int {
	switch strings.ToLower(cat) {
	case "ad":
		return 10
	case "entraid":
		return 20
	case "info":
		return 30
	default:
		return 99
	}
}
