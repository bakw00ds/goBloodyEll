package queries

import "strings"

// ApplyDisplayModes mutates selected queries to display usernames/hostnames the way the user wants.
// This is intentionally conservative: it targets the high-visibility inventory tabs and common
// "user" / "computer" outputs without trying to rewrite all Cypher.
func ApplyDisplayModes(in []Query, userMode, hostMode string) []Query {
	out := make([]Query, 0, len(in))
	for _, q := range in {
		qq := q
		switch qq.ID {
		case "ad-all-users-samaccountname":
			if userMode == "upn" {
				qq.SheetName = "All Users (UPN)"
				qq.Headers = []string{"upn"}
				qq.Cypher = `MATCH (u:User)
WHERE u.userprincipalname IS NOT NULL OR u.name IS NOT NULL
RETURN coalesce(u.userprincipalname, u.name) AS upn
ORDER BY upn`
			} else {
				qq.SheetName = "All Users"
				qq.Headers = []string{"samaccountname"}
				// keep original cypher
			}
			qq = qq.WithResolvedKeys()

		case "ad-all-computers-fqdn":
			switch hostMode {
			case "hostname":
				qq.SheetName = "All Computers (hostname)"
				qq.Headers = []string{"hostname"}
				qq.Cypher = `MATCH (c:Computer)
WITH c, split(c.name,'.') AS parts
RETURN parts[0] AS hostname
ORDER BY hostname`
			case "both":
				qq.SheetName = "All Computers"
				qq.Headers = []string{"hostname", "fqdn"}
				qq.Cypher = `MATCH (c:Computer)
WITH c, split(c.name,'.') AS parts
RETURN parts[0] AS hostname, c.name AS fqdn
ORDER BY fqdn`
			default: // fqdn
				// keep original
			}
			qq = qq.WithResolvedKeys()

		case "ad-domain-controllers":
			// computer + os
			qq = adjustComputerColumns(qq, hostMode)

		case "ad-domain-admin-sessions-non-dc", "ad-domain-users-local-admin", "ad-unconstrained-delegation-non-dc", "ad-computers-unconstrained-delegation":
			qq = adjustComputerColumns(qq, hostMode)

		case "ad-old-passwords-2y", "ad-highvalue-kerberoast", "ad-asrep-roastable", "ad-userpassword-attr", "ad-password-not-required", "info-users-in-vpn-groups":
			// For user rows we only adjust the column header on the All Users sheet.
			// Most other queries are already "u.name" which is often UPN-like in BloodHound.
			_ = userMode
		}

		out = append(out, qq)
	}
	return out
}

func adjustComputerColumns(q Query, hostMode string) Query {
	// If query returns computer as fqdn in key "computer", optionally add a hostname column.
	// We avoid rewriting Cypher for complex queries; only handle obvious patterns.
	if hostMode != "both" {
		return q
	}
	// Already has hostname?
	for _, h := range q.Headers {
		if strings.EqualFold(strings.TrimSpace(h), "hostname") {
			return q
		}
	}
	// Add hostname as first column; derive from computer/fqdn.
	// We can only do this safely when query returns a single computer value alias.
	// For now, handle by adding a post-processing column key by expecting cypher to provide it.
	// We'll rewrite known cyphers that return "AS computer".
	if strings.Contains(q.Cypher, " AS computer") {
		q.Headers = append([]string{"hostname"}, q.Headers...)
		// Inject a WITH/RETURN rewrite is risky; instead do a minimal replacement on the RETURN line.
		lines := strings.Split(q.Cypher, "\n")
		for i := range lines {
			if strings.HasPrefix(strings.TrimSpace(strings.ToUpper(lines[i])), "RETURN ") {
				// This is a best-effort rewrite.
				lines[i] = strings.Replace(lines[i], "RETURN ", "RETURN split(computer,'.')[0] AS hostname, ", 1)
				break
			}
		}
		q.Cypher = strings.Join(lines, "\n")
		q = q.WithResolvedKeys()
	}
	return q
}
