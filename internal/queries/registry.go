package queries

// Registry holds the built-in query packs.
// Ported from bloodyEll_example + later additions.

var FindingQueries = []Query{
	// --- Baseline inventory (always first tabs) ---
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

	// --- Ported from bloodyEll_example (findings) ---
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
		ID:           "ad-highvalue-kerberoast",
		Title:        "High value accounts with SPNs",
		Category:     "AD",
		SheetName:    "High Value Kerberoast",
		Headers:      []string{"User"},
		Description:  "High value users with SPNs that could allow kerberoasting",
		FindingTitle: "Accounts Susceptible to Kerberoasting",
		Cypher: `MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.highvalue=true AND u.hasspn=true
RETURN distinct(u.name) AS user
ORDER BY user`,
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
	Query{
		ID:           "ad-domain-admin-sessions-non-dc",
		Title:        "Domain Admin sessions on non-DCs",
		Category:     "AD",
		SheetName:    "DAs on Non-DCs",
		Headers:      []string{"User", "Computer"},
		Description:  "Domain admin sessions on systems that are not domain controllers.",
		FindingTitle: "Domain Administrator logged onto non-Domain Controller",
		Cypher: `MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-516'
WITH COLLECT(c1.name) AS domainControllers
MATCH (n:User)-[:MemberOf]->(g2:Group)
WHERE g2.objectid ENDS WITH '-512'
MATCH (c:Computer)-[:HasSession]->(n)
WHERE NOT c.name IN domainControllers
RETURN n.name AS user, c.name AS computer`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-userpassword-attr",
		Title:        "userPassword attribute set",
		Category:     "AD",
		SheetName:    "Users with userpassword",
		Headers:      []string{"username", "userpassword"},
		Description:  "AD users in the domain with the userpassword attribute set",
		FindingTitle: "Plaintext credentials stored in the userpassword Active Directory attribute",
		Cypher: `MATCH (u:User)
WHERE u.userpassword IS NOT NULL
RETURN u.name AS user, u.userpassword AS userpassword`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-asrep-roastable",
		Title:        "AS-REP roastable users",
		Category:     "AD",
		SheetName:    "ASREP Roastable Users",
		Headers:      []string{"username"},
		Description:  "AD users with dontreqpreauth set to true",
		FindingTitle: "Kerberos preauthentication not required by domain account(s)",
		Cypher: `MATCH (u:User {dontreqpreauth: true})
RETURN u.name AS user`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-gpo-acl-weirdness",
		Title:        "Unusual rights over GPOs",
		Category:     "AD",
		SheetName:    "GPO Weirdness",
		Headers:      []string{"User", "GPO", "ACL"},
		Description:  "AD users with unusual GPO privileges",
		FindingTitle: "Unusual rights over GPO objects",
		Cypher: `MATCH (u:User)-[a:AllExtendedRights|GenericAll|Owns|GenericWrite|WriteOwner|WriteDacl]->(g:GPO)
RETURN u.name AS user, g.name AS gpo, type(a) AS acl
ORDER BY user, gpo`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-password-not-required",
		Title:        "Password not required (enabled users)",
		Category:     "AD",
		SheetName:    "Pass Not Reqd",
		Headers:      []string{"User"},
		Description:  "Enabled users with passwordnotreqd=true",
		FindingTitle: "Password not required for domain accounts",
		Cypher: `MATCH (u:User)
WHERE u.passwordnotreqd AND u.enabled
RETURN u.name AS user`,
	}.WithResolvedKeys(),

	// --- Additional defender cleanup / hygiene ---
	Query{
		ID:           "ad-admincount",
		Title:        "adminCount=1 principals",
		Category:     "AD",
		SheetName:    "AdminCount=1",
		Headers:      []string{"Principal", "Type"},
		Description:  "Principals protected by AdminSDHolder (adminCount=1).",
		FindingTitle: "AdminSDHolder protected objects",
		Cypher: `MATCH (n)
WHERE (n:User OR n:Computer) AND n.admincount = true
RETURN n.name AS principal, labels(n) AS type
ORDER BY principal`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-password-never-expires",
		Title:        "Password never expires",
		Category:     "AD",
		SheetName:    "Pwd Never Expires",
		Headers:      []string{"User", "Enabled"},
		Description:  "Users with password never expires set.",
		FindingTitle: "Non-expiring passwords",
		Cypher: `MATCH (u:User)
WHERE u.pwdneverexpires = true
RETURN u.name AS user, u.enabled AS enabled
ORDER BY user`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-kerberoastable",
		Title:        "Service accounts (SPNs present)",
		Category:     "AD",
		SheetName:    "SPN Users",
		Headers:      []string{"User", "SPNs"},
		Description:  "Users with SPNs.",
		FindingTitle: "Accounts susceptible to kerberoasting",
		Cypher: `MATCH (u:User)
WHERE u.hasspn = true
RETURN u.name AS user, u.serviceprincipalnames AS spns
ORDER BY user`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-highvalue-objects",
		Title:        "High value objects",
		Category:     "AD",
		SheetName:    "High Value",
		Headers:      []string{"Name", "Type"},
		Description:  "Objects marked highvalue=true.",
		FindingTitle: "High-value assets require protection",
		Cypher: `MATCH (n)
WHERE n.highvalue = true
RETURN n.name AS name, labels(n) AS type
ORDER BY type, name`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-users-description-possible-creds",
		Title:        "User descriptions containing pw/pass",
		Category:     "AD",
		SheetName:    "User Desc pw/pass",
		Headers:      []string{"User", "Description"},
		Description:  "User accounts with 'pw' or 'pass' in description",
		FindingTitle: "Possible plaintext creds in user descriptions",
		Cypher: `MATCH (n:User)
WHERE toLower(n.description) CONTAINS 'pw' OR toLower(n.description) CONTAINS 'pass'
RETURN n.name AS user, n.description AS description
ORDER BY user`,
	}.WithResolvedKeys(),

	// --- Entra ID (best-effort) ---
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
		ID:           "ad-dcsync-rights",
		Title:        "Principals with DCSync rights",
		Category:     "AD",
		SheetName:    "DCSync Rights",
		Headers:      []string{"Principal", "Right", "Domain"},
		Description:  "Principals with replication (DCSync) rights on the domain object.",
		FindingTitle: "Excessive directory replication rights",
		Cypher: `MATCH (d:Domain)
MATCH (p)-[r:GetChanges|GetChangesAll|GetChangesInFilteredSet]->(d)
RETURN p.name AS principal, type(r) AS right, d.name AS domain
ORDER BY principal`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-computers-unconstrained-delegation",
		Title:        "Computers with unconstrained delegation",
		Category:     "AD",
		SheetName:    "Uncons. Delegation (All)",
		Headers:      []string{"Computer", "OS"},
		Description:  "All computers with unconstrained delegation enabled.",
		FindingTitle: "Unconstrained delegation enabled",
		Cypher: `MATCH (c:Computer)
WHERE c.unconstraineddelegation = true
RETURN c.name AS computer, c.operatingsystem AS os
ORDER BY computer`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-users-unconstrained-delegation",
		Title:        "Users with unconstrained delegation",
		Category:     "AD",
		SheetName:    "User Unconstrained Deleg",
		Headers:      []string{"User"},
		Description:  "Users with unconstrained delegation enabled.",
		FindingTitle: "Unconstrained delegation enabled",
		Cypher: `MATCH (u:User)
WHERE u.unconstraineddelegation = true
RETURN u.name AS user
ORDER BY user`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-rbcd-allowedtoact",
		Title:        "Resource-based constrained delegation (RBCD) relationships",
		Category:     "AD",
		SheetName:    "RBCD AllowedToAct",
		Headers:      []string{"From", "To"},
		Description:  "Principals that can act on behalf of other identities to a computer (AllowedToAct edge).",
		FindingTitle: "Review RBCD configuration",
		Cypher: `MATCH (p)-[:AllowedToAct]->(c:Computer)
RETURN p.name AS principal, c.name AS computer
ORDER BY principal, computer`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-genericall-users",
		Title:        "Users with GenericAll over other principals",
		Category:     "AD",
		SheetName:    "GenericAll (Users)",
		Headers:      []string{"From", "To", "ToType"},
		Description:  "GenericAll is effectively full control. Review and remediate excessive rights.",
		FindingTitle: "Excessive object control (GenericAll)",
		Cypher: `MATCH (a:User)-[:GenericAll]->(b)
RETURN a.name AS principal, b.name AS target, labels(b) AS target_type
ORDER BY principal, target
LIMIT 2000`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-genericwrite-users",
		Title:        "Users with GenericWrite over other principals",
		Category:     "AD",
		SheetName:    "GenericWrite (Users)",
		Headers:      []string{"From", "To", "ToType"},
		Description:  "GenericWrite can allow attribute abuse depending on target type. Review for least privilege.",
		FindingTitle: "Excessive object write rights",
		Cypher: `MATCH (a:User)-[:GenericWrite]->(b)
RETURN a.name AS principal, b.name AS target, labels(b) AS target_type
ORDER BY principal, target
LIMIT 2000`,
	}.WithResolvedKeys(),
	Query{
		ID:           "ad-owned-objects",
		Title:        "Non-admin owners of high value objects",
		Category:     "AD",
		SheetName:    "Owned HighValue",
		Headers:      []string{"Owner", "Object", "Type"},
		Description:  "Ownership can enable permission changes. Review owners of high value objects.",
		FindingTitle: "Unsafe ownership on high value objects",
		Cypher: `MATCH (o)-[:Owns]->(n)
WHERE n.highvalue = true
RETURN o.name AS owner, n.name AS object, labels(n) AS type
ORDER BY owner, object
LIMIT 2000`,
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
		Description:  "Consent grants can create long-lived access paths. This is best-effort; labels/edges differ by tool.",
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
		ID:           "info-constrained-delegation-users",
		Title:        "Users with constrained delegation",
		Category:     "INFO",
		SheetName:    "const. deleg computers",
		Headers:      []string{"username", "services"},
		Description:  "[INFO] AD users that have constrained delegation turned on and to which services [INFO]",
		FindingTitle: "Constrained Delegation present",
		Cypher: `MATCH (u:User)
WHERE u.allowedtodelegate IS NOT NULL
RETURN u.name AS user, u.allowedtodelegate AS allowedtodelegate`,
	}.WithResolvedKeys(),
	Query{
		ID:           "info-linux-computers",
		Title:        "Linux OS computer objects",
		Category:     "INFO",
		SheetName:    "Linux OS",
		Headers:      []string{"Hostname", "Operating System"},
		Description:  "[INFO] AD Linux based computer objects [INFO]",
		FindingTitle: "[VARIABLE]",
		Cypher: `MATCH (c:Computer)
WHERE c.operatingsystem =~ '.*Linux.*' OR c.operatingsystem =~ '.*(Debian|Ubuntu|Fedora|BSD).*'
RETURN c.name AS computer, c.operatingsystem AS os`,
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
	Query{
		ID:           "info-web-apps",
		Title:        "Web applications (inventory)",
		Category:     "INFO",
		SheetName:    "Web Applications",
		Headers:      []string{"Hostname", "Operating System", "Description"},
		Description:  "[INFO] Web Application Servers to inventory and harden [INFO]",
		FindingTitle: "[VARIABLE]",
		Cypher: `MATCH (c:Computer)
WHERE toLower(c.name) CONTAINS 'web' OR toLower(c.description) CONTAINS 'web'
   OR toLower(c.name) CONTAINS 'appli' OR toLower(c.description) CONTAINS 'appli'
RETURN c.name AS computer, c.operatingsystem AS os, c.description AS description`,
	}.WithResolvedKeys(),
}
