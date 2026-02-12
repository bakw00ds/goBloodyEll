package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bakw00ds/goBloodyEll/internal/neo4jrunner"
	"github.com/bakw00ds/goBloodyEll/internal/queries"
	"github.com/bakw00ds/goBloodyEll/internal/report"
	"github.com/bakw00ds/goBloodyEll/internal/schema"
)

var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	var (
		neo4jHost string
		neo4jURI  string
		user      string
		pass      string
		db        string

		id         string
		category   string
		list       bool
		schemaFlag bool

		outTxt  string
		outXLSX string
		verbose bool
		format  string
		outPath string

		includeInfo  bool
		includeEntra bool

		limit          int
		timeoutS       int
		queryTimeout   int
		parallel       int
		retries        int
		failFast       bool
		skipEmpty      bool
		showVersion    bool
		userNameMode   string
		hostNameMode   string
		schemaSkip     bool
		exportCoreCSVs string
	)

	// build-time values
	// set via -ldflags "-X main.version=v1.2.3 -X main.commit=... -X main.date=..."

	flag.Usage = func() {
		const help = `goBloodyEll - BloodHound/Neo4j defensive query runner (AD + EntraID)

INSTALL:
  go install github.com/bakw00ds/goBloodyEll/cmd/goBloodyEll@latest

USAGE:
  goBloodyEll [connection] [query selection] [output]

CONNECTION:
  --neo4j-ip <host>          (default 127.0.0.1)
  --neo4j-uri <bolt://...>   overrides --neo4j-ip
  --db <name>                (default neo4j)
  -u/--username <user>       (default neo4j)
  -p/--password <pass>       or env NEO4J_PASS

QUERY SELECTION:
  --list                     list available queries
  --schema                   print labels/rel-types
  --id <query-id>            run a single query
  --category <all|AD|INFO|EntraID> (default all)
  -i/--info                  include INFO queries
  --entra                    include EntraID queries

OUTPUT (choose any; default is console output):
  -t/--text <file>           write a text report
  -x/--xlsx <file>           write an XLSX report
  -v/--verbose               print to console

STRUCTURED OUTPUT (alternative):
  --format <json|csv|text>   structured output
  --out <file>               structured output file

PERFORMANCE/ROBUSTNESS:
  --limit <n>                rows per query (0 = unlimited)
  --timeout <sec>            overall run timeout (default 60)
  --query-timeout <sec>      per-query timeout (default 30)
  --parallel <n>             parallel query workers (default 4)
  --retries <n>              transient error retries (default 1)
  --fail-fast                stop on first query error
  --skip-empty               do not create empty/failed sheets

FLAGS (including aliases):
`
		fmt.Fprint(os.Stderr, help)
		flag.PrintDefaults()
	}

	flag.StringVar(&user, "u", "neo4j", "Neo4j username")
	flag.StringVar(&user, "username", "neo4j", "Neo4j username")
	flag.StringVar(&pass, "p", "", "Neo4j password (or set NEO4J_PASS)")
	flag.StringVar(&pass, "password", "", "Neo4j password (or set NEO4J_PASS)")
	flag.StringVar(&outTxt, "t", "", "write text report to file")
	flag.StringVar(&outTxt, "text", "", "write text report to file")
	flag.StringVar(&outXLSX, "x", "", "write XLSX report to file")
	flag.StringVar(&outXLSX, "xlsx", "", "write XLSX report to file")
	flag.BoolVar(&includeInfo, "i", false, "include informational/inventory queries")
	flag.BoolVar(&includeInfo, "info", false, "include informational/inventory queries")
	flag.BoolVar(&verbose, "v", false, "print results to console")
	flag.BoolVar(&verbose, "verbose", false, "print results to console")

	flag.StringVar(&neo4jHost, "neo4j-ip", "127.0.0.1", "Neo4j server IP/host (used if --neo4j-uri not set)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.StringVar(&userNameMode, "usernames", "upn", "username display mode: sam|upn")
	flag.StringVar(&hostNameMode, "hostnames", "fqdn", "hostname display mode: hostname|fqdn|both")
	flag.BoolVar(&schemaSkip, "schema-skip", true, "skip queries when required labels/relationships are missing")
	flag.StringVar(&exportCoreCSVs, "export-core-csvs", "", "write core exports (users, computers, domain admins, domain controllers) as separate CSVs into this directory")
	flag.StringVar(&neo4jURI, "neo4j-uri", "", "Neo4j URI (e.g. bolt://10.0.0.5:7687). Overrides --neo4j-ip")
	flag.StringVar(&db, "db", "neo4j", "Neo4j database name")
	flag.StringVar(&id, "id", "", "run a single query by id")
	flag.StringVar(&category, "category", "all", "filter queries by category: all|AD|EntraID|INFO")
	flag.BoolVar(&list, "list", false, "list available queries")
	flag.BoolVar(&schemaFlag, "schema", false, "print Neo4j schema summary (labels/relationship types)")
	flag.BoolVar(&includeEntra, "entra", false, "include EntraID queries (best-effort, schema varies)")
	flag.IntVar(&limit, "limit", 0, "max rows per query (0 = unlimited); if >0, also appends LIMIT if query lacks one")
	flag.IntVar(&timeoutS, "timeout", 60, "overall run timeout seconds")
	flag.IntVar(&queryTimeout, "query-timeout", 30, "per-query timeout seconds")
	flag.IntVar(&parallel, "parallel", 4, "number of queries to run in parallel")
	flag.IntVar(&retries, "retries", 1, "retries for transient Neo4j errors")
	flag.BoolVar(&failFast, "fail-fast", false, "stop on first query error")
	flag.BoolVar(&skipEmpty, "skip-empty", false, "skip creating empty/skipped/error sheets")
	flag.StringVar(&format, "format", "", "structured output format: json|csv|text (optional; default uses -t/-x/-v behavior)")
	flag.StringVar(&outPath, "out", "", "structured output file (default stdout)")
	flag.Parse()

	if showVersion {
		fmt.Printf("goBloodyEll %s\n", version)
		if commit != "" {
			fmt.Printf("commit: %s\n", commit)
		}
		if date != "" {
			fmt.Printf("date: %s\n", date)
		}
		return
	}

	userNameMode = strings.ToLower(strings.TrimSpace(userNameMode))
	if userNameMode != "sam" && userNameMode != "upn" {
		fatalf("invalid --usernames %q (expected: sam|upn)", userNameMode)
	}
	hostNameMode = strings.ToLower(strings.TrimSpace(hostNameMode))
	if hostNameMode != "hostname" && hostNameMode != "fqdn" && hostNameMode != "both" {
		fatalf("invalid --hostnames %q (expected: hostname|fqdn|both)", hostNameMode)
	}

	if pass == "" {
		pass = os.Getenv("NEO4J_PASS")
	}
	if outTxt == "" && outXLSX == "" && !verbose && format == "" {
		verbose = true
	}

	qs := append([]queries.Query{}, queries.FindingQueries...)
	if includeInfo {
		qs = append(qs, queries.InfoQueries...)
	}
	if !includeEntra {
		filtered := qs[:0]
		for _, q := range qs {
			if !strings.EqualFold(q.Category, "EntraID") {
				filtered = append(filtered, q)
			}
		}
		qs = append([]queries.Query(nil), filtered...)
	}

	// Apply display modes (usernames/hostnames) to relevant queries.
	qs = queries.ApplyDisplayModes(qs, userNameMode, hostNameMode)
	qs, err := queries.FilterCategoryStrict(qs, category)
	if err != nil {
		fatalf("%v", err)
	}
	qs = queries.Order(qs)

	if list {
		printQueryList(qs)
		return
	}
	if id != "" {
		q, ok := findQueryByID(qs, id)
		if !ok {
			fatalf("unknown query id: %s", id)
		}
		qs = []queries.Query{q}
	}
	if len(qs) == 0 {
		fatalf("no queries selected (try --list)")
	}

	if neo4jURI == "" {
		neo4jURI = fmt.Sprintf("bolt://%s:7687", neo4jHost)
	}
	if pass == "" {
		fatalf("missing password: provide -p/--password or set NEO4J_PASS")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutS)*time.Second)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[+] Connecting to %s (db=%s) as %s\n", neo4jURI, db, user)
	driver, err := neo4j.NewDriverWithContext(neo4jURI, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		fatalf("neo4j connect error: %v", err)
	}
	defer driver.Close(ctx)

	sess := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: db})
	defer sess.Close(ctx)

	sum, err := schema.Discover(ctx, sess)
	if err != nil {
		fatalf("schema discovery error: %v", err)
	}
	if schemaFlag {
		schema.Print(sum)
		return
	}
	presence := schema.PresenceFromSummary(sum)

	if limit > 0 {
		fmt.Fprintf(os.Stderr, "[+] Running %d queries (limit=%d, parallel=%d, per-query-timeout=%ds)\n", len(qs), limit, parallel, queryTimeout)
	} else {
		fmt.Fprintf(os.Stderr, "[+] Running %d queries (no row limit, parallel=%d, per-query-timeout=%ds)\n", len(qs), parallel, queryTimeout)
	}

	outs := make([]report.Output, len(qs))
	jobs := make([]neo4jrunner.QueryJob, 0, len(qs))
	jobToQueryIdx := make([]int, 0, len(qs))

	for i, q := range qs {
		if schemaSkip {
			ok, why := schema.CanRunCypher(q.Cypher, presence)
			if !ok {
				outs[i] = report.Output{Query: q, Skipped: true, SkipWhy: why}
				continue
			}
		}
		jobs = append(jobs, neo4jrunner.QueryJob{Index: len(jobs), ID: q.ID, Name: q.SheetName, Cypher: q.Cypher})
		jobToQueryIdx = append(jobToQueryIdx, i)
	}

	results := neo4jrunner.Run(ctx, driver, jobs, neo4jrunner.RunnerOpts{DB: db, Limit: limit, Parallel: parallel, PerQueryTimeout: time.Duration(queryTimeout) * time.Second, Retries: retries, FailFast: failFast, Verbose: true}, neo4jrunner.ExecCypher)

	for j, r := range results {
		i := jobToQueryIdx[j]
		o := report.Output{Query: qs[i], Result: r.ResultSet}
		if r.Err != nil {
			o.Error = r.Err.Error()
		}
		outs[i] = o
	}

	if format != "" {
		format = strings.ToLower(strings.TrimSpace(format))
		if err := report.WriteStructured(outs, format, outPath); err != nil {
			fatalf("write structured failed: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Success. Wrote structured output to %s\n", firstNonEmpty(outPath, "stdout"))
		return
	}

	if outTxt != "" {
		fmt.Fprintf(os.Stderr, "[+] Writing text report -> %s\n", outTxt)
		if err := report.WriteTextFile(outs, outTxt); err != nil {
			fatalf("write txt failed: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Wrote text report -> %s\n", outTxt)
	}
	if outXLSX != "" {
		fmt.Fprintf(os.Stderr, "[+] Writing XLSX report -> %s\n", outXLSX)
		if err := report.WriteXLSX(outs, outXLSX, skipEmpty); err != nil {
			fatalf("write xlsx failed: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Wrote XLSX report -> %s\n", outXLSX)
	}
	if strings.TrimSpace(exportCoreCSVs) != "" {
		fmt.Fprintf(os.Stderr, "[+] Writing core CSV exports -> %s\n", exportCoreCSVs)
		if err := report.WriteCoreCSVs(exportCoreCSVs, outs); err != nil {
			fatalf("write core CSVs failed: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Wrote core CSV exports -> %s\n", exportCoreCSVs)
	}
	if verbose {
		report.WriteConsole(outs)
	}

	fmt.Fprintf(os.Stderr, "[+] Success.\n")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	fmt.Fprintf(os.Stderr, "hint: run with -h for usage/examples\n")
	os.Exit(2)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func findQueryByID(in []queries.Query, id string) (queries.Query, bool) {
	for _, q := range in {
		if q.ID == id {
			return q, true
		}
	}
	return queries.Query{}, false
}

func printQueryList(qs []queries.Query) {
	for _, q := range qs {
		fmt.Printf("[%s] %s\n  id: %s\n  sheet: %s\n  %s\n\n", q.Category, q.Title, q.ID, q.SheetName, q.Description)
	}
}
