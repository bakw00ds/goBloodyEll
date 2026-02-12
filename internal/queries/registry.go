package queries

// Registry holds the built-in query packs.
// These are populated from the project-level queries (ported from bloodyEll_example + additions).

var FindingQueries = []Query{
	// Baseline inventory (always first tabs)
	Query{
		ID:           "ad-all-users-samaccountname",
		Title:        "All users (samAccountName)",
		Category:     "AD",
		SheetName:    "All Users",
		Headers:      []string{"samaccountname"},
		Description:  "All users in the domain (samAccountName)",
		FindingTitle: "",
		Cypher: `MATCH (u:User)
WHERE u.samaccountname IS NOT NULL
RETURN u.samaccountname AS samaccountname
ORDER BY samaccountname`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-all-computers-fqdn",
		Title:        "All computers (FQDN)",
		Category:     "AD",
		SheetName:    "All Computers",
		Headers:      []string{"fqdn"},
		Description:  "All computers in the domain (FQDN/hostname)",
		FindingTitle: "",
		Cypher: `MATCH (c:Computer)
RETURN c.name AS fqdn
ORDER BY fqdn`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-domain-admins",
		Title:        "Domain Admins",
		Category:     "AD",
		SheetName:    "Domain Admins",
		Headers:      []string{"Principal", "Type"},
		Description:  "Members of Domain Admins.",
		FindingTitle: "",
		Cypher: `MATCH (g:Group)
WHERE toUpper(g.name) ENDS WITH "DOMAIN ADMINS" OR g.objectid ENDS WITH "-512"
MATCH (u)-[:MemberOf*1..]->(g)
RETURN u.name AS principal, labels(u) AS type
ORDER BY principal`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-domain-controllers",
		Title:        "Domain Controllers",
		Category:     "AD",
		SheetName:    "Domain Controllers",
		Headers:      []string{"Hostname", "Operating System"},
		Description:  "Computer objects that are members of the Domain Controllers group.",
		FindingTitle: "",
		Cypher: `MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-516'
RETURN c.name AS computer, c.operatingsystem AS os
ORDER BY computer`,
	}.WithResolvedKeys(),

	// Findings (ported + additions)
	Query{
		ID:           "ad-unconstrained-delegation-non-dc",
		Title:        "Non-DCs w/ Unconstrained Delegation enabled",
		Category:     "AD",
		SheetName:    "Uncons. Delegation",
		Headers:      []string{"Hostname", "Operating System"},
		Description:  "Non-DCs w/ Unconstrained Delegation enabled",
		FindingTitle: "Unconstrained Delegation present",
		Cypher: `MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-516'
WITH COLLECT(c1.name) AS domainControllers
MATCH (c2:Computer {unconstraineddelegation:true})
WHERE NOT c2.name IN domainControllers
RETURN c2.name AS computer, c2.operatingsystem AS os
ORDER BY computer ASC`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-unsupported-os-recent",
		Title:        "Unsupported operating system(s) in use (recently active)",
		Category:     "AD",
		SheetName:    "Unsupported OS (recently active)",
		Headers:      []string{"Hostname", "Operating System"},
		Description:  "AD Computer objects identified as running unsupported operating systems (checked in last 90 days)",
		FindingTitle: "Unsupported operating system(s) in use",
		Cypher: `MATCH (c:Computer)
WHERE c.operatingsystem =~ '.*(2000|2003|2008|xp|vista|7|me).*'
  AND c.operatingsystem =~ '.*Windows.*'
  AND c.pwdlastset > (datetime().epochseconds - (90 * 86400))
RETURN c.name AS computer, c.operatingsystem AS os
ORDER BY computer`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-domain-users-local-admin",
		Title:        "Domain Users are local admins",
		Category:     "AD",
		SheetName:    "All Users LA",
		Headers:      []string{"Hostname"},
		Description:  "Systems where the Domain Users group is in the local Administrators group",
		FindingTitle: "Standard domain accounts are members of local Administrators group",
		Cypher: `MATCH (m:Group)
WHERE m.name =~ 'DOMAIN USERS@.*'
MATCH (m)-[:AdminTo]->(n:Computer)
RETURN n.name AS computer`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-old-passwords-2y",
		Title:        "Enabled accounts with old passwords",
		Category:     "AD",
		SheetName:    "Old Passwords",
		Headers:      []string{"User", "Password Set", "Service Acct?"},
		Description:  "Enabled accounts with passwords older than two years. Service accounts first.",
		FindingTitle: "Old Active Directory password(s)",
		Cypher: `MATCH (u:User)
WHERE u.pwdlastset < (datetime().epochseconds - (730 * 86400))
  AND NOT u.pwdlastset IN [-1.0, 0.0]
  AND u.enabled=true
RETURN u.name AS user, u.pwdlastset AS pwdlastset, u.hasspn AS service_acct
ORDER BY service_acct DESC, pwdlastset DESC`,
	}.WithResolvedKeys(),

	// --- EntraID (best-effort, depends on ingestion schema) ---
	Query{
		ID:           "entra-guest-users",
		Title:        "Entra ID guest users",
		Category:     "EntraID",
		SheetName:    "Entra Guests",
		Headers:      []string{"Guest"},
		Description:  "List guest users (external identities) for review.",
		FindingTitle: "Review guest/external identities",
		Cypher: `MATCH (u:AzureUser)
WHERE toLower(u.usertype) = "guest" OR toLower(u.userType) = "guest"
RETURN u.name AS guest
ORDER BY guest`,
	}.WithResolvedKeys(),
	Query{
		ID:           "entra-privileged-roles",
		Title:        "Entra ID privileged role assignments",
		Category:     "EntraID",
		SheetName:    "Entra Roles",
		Headers:      []string{"Role", "Sample Members"},
		Description:  "Privileged/admin role assignments (best-effort).",
		FindingTitle: "Privileged role assignments",
		Cypher: `MATCH (r:AzureRole)
WHERE toLower(r.name) CONTAINS "admin" OR toLower(r.name) CONTAINS "privileged"
OPTIONAL MATCH (p)-[:AZRoleMember]->(r)
RETURN r.name AS role, collect(distinct p.name)[0..50] AS sample_members
ORDER BY role`,
	}.WithResolvedKeys(),
	Query{
		ID:           "entra-service-principals",
		Title:        "Entra ID service principals",
		Category:     "EntraID",
		SheetName:    "Service Principals",
		Headers:      []string{"Service Principal"},
		Description:  "Surface application identities for review.",
		FindingTitle: "Review application identities",
		Cypher: `MATCH (sp:ServicePrincipal)
RETURN sp.name AS service_principal
ORDER BY service_principal
LIMIT 500`,
	}.WithResolvedKeys(),
	Query{
		ID:           "entra-admin-role-membership",
		Title:        "Entra admin roles and members (top 50 per role)",
		Category:     "EntraID",
		SheetName:    "Entra Admin Roles",
		Headers:      []string{"Role", "Members"},
		Description:  "Role membership for roles containing 'admin'. Collector schema varies.",
		FindingTitle: "Review Entra privileged role membership",
		Cypher: `MATCH (r:AzureRole)
WHERE toLower(r.name) CONTAINS "admin"
OPTIONAL MATCH (p)-[:AZRoleMember]->(r)
RETURN r.name AS role, collect(distinct p.name)[0..50] AS members
ORDER BY role`,
	}.WithResolvedKeys(),
	Query{
		ID:           "entra-oauth-grants",
		Title:        "OAuth permission grants (consents)",
		Category:     "EntraID",
		SheetName:    "OAuth Grants",
		Headers:      []string{"Client", "Resource", "Scope"},
		Description:  "Consent grants can create long-lived access paths. Best-effort; labels/edges differ by tool.",
		FindingTitle: "Review OAuth consent grants",
		Cypher: `MATCH (g:OAuth2PermissionGrant)
OPTIONAL MATCH (c)-[:Client]->(g)
OPTIONAL MATCH (r)-[:Resource]->(g)
RETURN coalesce(c.name, c.appid, c.objectid) AS client,
       coalesce(r.name, r.appid, r.objectid) AS resource,
       g.scope AS scope
ORDER BY client
LIMIT 2000`,
	}.WithResolvedKeys(),
	Query{
		ID:           "entra-app-role-assignments",
		Title:        "App role assignments",
		Category:     "EntraID",
		SheetName:    "AppRole Assign",
		Headers:      []string{"Principal", "ServicePrincipal", "Role"},
		Description:  "App role assignments can grant app-specific privileges. Best-effort schema.",
		FindingTitle: "Review app role assignments",
		Cypher: `MATCH (u)-[r:AppRoleAssignment]->(sp:ServicePrincipal)
RETURN u.name AS principal, sp.name AS service_principal, r.appRoleId AS role
ORDER BY principal
LIMIT 2000`,
	}.WithResolvedKeys(),
}

var InfoQueries = []Query{
	Query{
		ID:           "info-groups-admin-to",
		Title:        "Groups with admin rights to AD computers",
		Category:     "INFO",
		SheetName:    "Groups with admin privs",
		Headers:      []string{"Group Names"},
		Description:  "[INFO] Groups with admin rights to AD computers [INFO]",
		FindingTitle: "[VARIABLE]",
		Cypher: `MATCH (m:Group)-[:AdminTo]->(n:Computer)
RETURN distinct(m.name) AS group
ORDER BY group`,
	}.WithResolvedKeys(),
	Query{
		ID:           "info-users-in-vpn-groups",
		Title:        "Users in VPN groups",
		Category:     "INFO",
		SheetName:    "Users in VPN group",
		Headers:      []string{"username", "groupname"},
		Description:  "[INFO] AD users that are in a group that contains the string VPN [INFO]",
		FindingTitle: "[VARIABLE]",
		Cypher: `Match (u:User)-[:MemberOf]->(g:Group)
WHERE g.name =~ '.*VPN.*'
RETURN u.name AS user, g.name AS groupname`,
	}.WithResolvedKeys(),
	Query{
		ID:           "info-groups-force-change-password",
		Title:        "Groups with ForceChangePassword",
		Category:     "INFO",
		SheetName:    "Groups with forceChangePassword",
		Headers:      []string{"group", "count"},
		Description:  "[INFO] Groups with the ForceChangePassword privilege in the domain [INFO]",
		FindingTitle: "[VARIABLE]",
		Cypher: `MATCH (m:Group)-[:ForceChangePassword]->(n:User)
RETURN m.name AS group, count(n) AS count`,
	}.WithResolvedKeys(),
	Query{
		ID:           "info-systems-with-descriptions",
		Title:        "Systems with descriptions",
		Category:     "INFO",
		SheetName:    "Systems with Descriptions",
		Headers:      []string{"Hostname", "Operating System", "Description"},
		Description:  "[INFO] AD Computer objects with Descriptions to investigate [INFO]",
		FindingTitle: "Plaintext credentials stored in the description Active Directory attribute",
		Cypher: `MATCH (c:Computer)
WHERE EXISTS(c.description)
RETURN c.name AS computer, c.operatingsystem AS os, c.description AS description`,
	}.WithResolvedKeys(),
}
