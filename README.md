# goBloodyEll

Go-based Neo4j query runner for BloodHound-style graphs, focused on **defensive hygiene / cleanup** findings for AD and Entra ID.

> This tool is intended for authorized defensive auditing and remediation planning.

## Install

```bash
# Install latest (recommended)
go install github.com/bakw00ds/goBloodyEll@latest

# Ensure Go bin dir is on PATH (common default)
export PATH="$(go env GOPATH)/bin:$PATH"
```

## Build

```bash
go mod tidy
go build -o goBloodyEll .
```

## Usage

List available queries:

```bash
./goBloodyEll --list
./goBloodyEll --list --category AD
./goBloodyEll --list --category EntraID
```

Run all queries in a category:

```bash
export NEO4J_PASS='yourpassword'
./goBloodyEll --neo4j-ip 10.0.0.5 --user neo4j --db neo4j --category AD --format json --out ad.json
```

Run a single query:

```bash
./goBloodyEll --neo4j-uri bolt://10.0.0.5:7687 --id ad-unconstrained-delegation-computers --format text
```

CSV output:

```bash
./goBloodyEll --neo4j-ip 10.0.0.5 --category AD --format csv --out findings.csv
```

## Notes

- Queries assume a BloodHound-like schema; different collectors/versions may use different labels/properties.
- The runner will apply a safety `LIMIT` if your query does not include one.
- Add/edit queries in `queries.go`.
- Entra ID queries are best-effort; depending on whether you ingested data via AzureHound or ROADtools, labels/relationships may differ.

## Schema discovery

```bash
./goBloodyEll --neo4j-ip 10.0.0.5 --schema
```

Prints node labels + relationship types, plus a small sample of properties for each.
