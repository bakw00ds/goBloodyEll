package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/xuri/excelize/v2"
)

type row map[string]any

type queryOutput struct {
	Query Query  `json:"query"`
	Rows  []row  `json:"rows"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

func main() {
	var (
		neo4jHost string
		neo4jURI  string
		user      string
		pass      string
		db        string

		id       string
		category string
		list     bool
		schema   bool

		// Output modes
		outTxt  string
		outXLSX string
		verbose bool
		format  string
		outPath string

		includeInfo  bool
		includeEntra bool

		limit    int
		timeoutS int
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "goBloodyEll - BloodHound/Neo4j defensive query runner (AD + EntraID)\n\n")
		fmt.Fprintf(os.Stderr, "USAGE:\n")
		fmt.Fprintf(os.Stderr, "  goBloodyEll [connection] [query selection] [output]\n\n")
		fmt.Fprintf(os.Stderr, "CONNECTION:\n")
		fmt.Fprintf(os.Stderr, "  --neo4j-ip <host>          (default 127.0.0.1)\n")
		fmt.Fprintf(os.Stderr, "  --neo4j-uri <bolt://...>   overrides --neo4j-ip\n")
		fmt.Fprintf(os.Stderr, "  --db <name>                (default neo4j)\n")
		fmt.Fprintf(os.Stderr, "  -u, --username <user>      (default neo4j)\n")
		fmt.Fprintf(os.Stderr, "  -p, --password <pass>      or env NEO4J_PASS\n\n")
		fmt.Fprintf(os.Stderr, "QUERY SELECTION:\n")
		fmt.Fprintf(os.Stderr, "  --list                     list available queries\n")
		fmt.Fprintf(os.Stderr, "  --schema                   print labels/rel-types/property samples\n")
		fmt.Fprintf(os.Stderr, "  --id <query-id>            run a single query\n")
		fmt.Fprintf(os.Stderr, "  --category <all|AD|INFO|EntraID> (default all)\n")
		fmt.Fprintf(os.Stderr, "  --info                     include INFO queries\n")
		fmt.Fprintf(os.Stderr, "  --entra                    include EntraID queries\n\n")
		fmt.Fprintf(os.Stderr, "OUTPUT (choose any; default is console output):\n")
		fmt.Fprintf(os.Stderr, "  -t, --text <file>          write a text report\n")
		fmt.Fprintf(os.Stderr, "  -x, --xlsx <file>          write an XLSX report\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose              print to console\n")
		fmt.Fprintf(os.Stderr, "\nSTRUCTURED OUTPUT (optional alternative):\n")
		fmt.Fprintf(os.Stderr, "  --format <json|csv|text>   structured output\n")
		fmt.Fprintf(os.Stderr, "  --out <file>               structured output file\n\n")
		fmt.Fprintf(os.Stderr, "MISC:\n")
		fmt.Fprintf(os.Stderr, "  --limit <n>                safety cap (default 500)\n")
		fmt.Fprintf(os.Stderr, "  --timeout <sec>            query timeout (default 30)\n\n")
		fmt.Fprintf(os.Stderr, "EXAMPLES:\n")
		fmt.Fprintf(os.Stderr, "  goBloodyEll --list --category AD\n")
		fmt.Fprintf(os.Stderr, "  NEO4J_PASS=neo4j goBloodyEll --neo4j-ip 10.0.0.5 -x report.xlsx --info\n")
		fmt.Fprintf(os.Stderr, "  NEO4J_PASS=neo4j goBloodyEll --neo4j-ip 10.0.0.5 --schema\n\n")
		fmt.Fprintf(os.Stderr, "FLAGS (including aliases):\n")
		flag.PrintDefaults()
	}

	// Compatibility-ish flags (based on bloodyEll_example)
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

	// Extended flags
	flag.StringVar(&neo4jHost, "neo4j-ip", "127.0.0.1", "Neo4j server IP/host (used if --neo4j-uri not set)")
	flag.StringVar(&neo4jURI, "neo4j-uri", "", "Neo4j URI (e.g. bolt://10.0.0.5:7687). Overrides --neo4j-ip")
	flag.StringVar(&db, "db", "neo4j", "Neo4j database name")
	flag.StringVar(&id, "id", "", "run a single query by id")
	flag.StringVar(&category, "category", "all", "filter queries by category: all|AD|EntraID|INFO")
	flag.BoolVar(&list, "list", false, "list available queries")
	flag.BoolVar(&schema, "schema", false, "print Neo4j schema summary (labels/relationship types/properties)")
	flag.BoolVar(&includeEntra, "entra", false, "include EntraID queries (best-effort, schema varies)")
	flag.IntVar(&limit, "limit", 500, "max rows per query (safety cap); also appends LIMIT if query lacks one")
	flag.IntVar(&timeoutS, "timeout", 30, "query timeout seconds")

	// Programmatic output (if you want structured output)
	flag.StringVar(&format, "format", "", "structured output format: json|csv|text (optional; default uses -t/-x/-v behavior)")
	flag.StringVar(&outPath, "out", "", "structured output file (default stdout)")
	flag.Parse()

	if pass == "" {
		pass = os.Getenv("NEO4J_PASS")
	}

	// Default to console output if nothing specified (like example)
	if outTxt == "" && outXLSX == "" && !verbose && format == "" {
		verbose = true
	}

	qs := collectQueries(includeInfo, includeEntra)
	qs, err := filterQueriesStrict(qs, category)
	if err != nil {
		fatalf("%v", err)
	}

	if list {
		printQueryList(qs)
		return
	}

	// --schema requires DB access; we do it after arg validation but before running queries.

	if id != "" {
		q, ok := findQueryByID(qs, id)
		if !ok {
			fatalf("unknown query id: %s", id)
		}
		qs = []Query{q}
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

	fmt.Fprintf(os.Stderr, "[+] Connecting to %s (db=%s) as %s\n", neo4jURI, db, user)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutS)*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriverWithContext(neo4jURI, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		fatalf("neo4j connect error: %v", err)
	}
	defer driver.Close(ctx)

	sess := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: db})
	defer sess.Close(ctx)

	if schema {
		if err := printSchema(ctx, sess); err != nil {
			fatalf("schema error: %v", err)
		}
		return
	}

	outs := make([]queryOutput, 0, len(qs))
	fmt.Fprintf(os.Stderr, "[+] Running %d queries (limit=%d)\n", len(qs), limit)
	for i, q := range qs {
		fmt.Fprintf(os.Stderr, "[+] (%d/%d) %s [%s]\n", i+1, len(qs), q.SheetName, q.ID)
		o := queryOutput{Query: q}
		rows, err := runCypher(ctx, sess, q.Cypher, limit)
		if err != nil {
			o.Error = err.Error()
		} else {
			o.Rows = rows
			o.Count = len(rows)
		}
		outs = append(outs, o)
	}

	// Structured output mode
	if format != "" {
		format = strings.ToLower(strings.TrimSpace(format))
		switch format {
		case "json", "csv", "text":
			writeStructured(outs, format, outPath)
			fmt.Fprintf(os.Stderr, "[+] Success. Wrote structured output to %s\n", firstNonEmpty(outPath, "stdout"))
			return
		default:
			fatalf("invalid --format %q (expected json|csv|text)", format)
		}
	}

	// Example-like output mode
	if outTxt != "" {
		fmt.Fprintf(os.Stderr, "[+] Writing text report -> %s\n", outTxt)
		if err := writeTextFile(outs, outTxt); err != nil {
			fatalf("write txt failed: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Wrote text report -> %s\n", outTxt)
	}
	if outXLSX != "" {
		fmt.Fprintf(os.Stderr, "[+] Writing XLSX report -> %s\n", outXLSX)
		if err := writeXLSX(outs, outXLSX); err != nil {
			fatalf("write xlsx failed: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Wrote XLSX report -> %s\n", outXLSX)
	}
	if verbose {
		writeConsole(outs)
	}

	fmt.Fprintf(os.Stderr, "[+] Success.\n")
}

func collectQueries(includeInfo, includeEntra bool) []Query {
	out := append([]Query{}, FindingQueries...)
	if includeInfo {
		out = append(out, InfoQueries...)
	}
	if !includeEntra {
		filtered := out[:0]
		for _, q := range out {
			if !strings.EqualFold(q.Category, "EntraID") {
				filtered = append(filtered, q)
			}
		}
		out = append([]Query(nil), filtered...)
	}
	return out
}

func runCypher(ctx context.Context, sess neo4j.SessionWithContext, cypher string, limit int) ([]row, error) {
	cy := strings.TrimSpace(cypher)
	if limit > 0 && !strings.Contains(strings.ToLower(cy), "limit") {
		cy = cy + fmt.Sprintf("\nLIMIT %d", limit)
	}

	recs, err := sess.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cy, nil)
		if err != nil {
			return nil, err
		}
		var rows []row
		for res.Next(ctx) {
			rec := res.Record()
			r := make(row)
			for _, k := range rec.Keys {
				val, _ := rec.Get(k)
				r[k] = val
			}
			rows = append(rows, r)
			if limit > 0 && len(rows) >= limit {
				break
			}
		}
		if err := res.Err(); err != nil {
			return nil, err
		}
		return rows, nil
	})
	if err != nil {
		return nil, err
	}
	return recs.([]row), nil
}

func writeConsole(outs []queryOutput) {
	for _, o := range outs {
		fmt.Println(o.Query.SheetName)
		fmt.Println(o.Query.Description)
		fmt.Println("finding title:", o.Query.FindingTitle)
		fmt.Println()
		if o.Error != "" {
			fmt.Println("ERROR:", o.Error)
			fmt.Println(strings.Repeat("=", 100))
			continue
		}
		for _, r := range o.Rows {
			// Print in record-values order if headers match returned keys.
			vals := make([]string, 0, len(r))
			// If headers exist, try to print those keys first.
			for _, h := range o.Query.Headers {
				key := headerToKey(h)
				if v, ok := r[key]; ok {
					vals = append(vals, fmt.Sprintf("%v", v))
				}
			}
			if len(vals) == 0 {
				for _, v := range r {
					vals = append(vals, fmt.Sprintf("%v", v))
				}
			}
			fmt.Println(strings.Join(vals, ", "))
		}
		fmt.Println(strings.Repeat("=", 100))
	}
}

func writeTextFile(outs []queryOutput, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	for _, o := range outs {
		_, _ = w.WriteString(o.Query.SheetName + "\n")
		_, _ = w.WriteString(o.Query.Description + "\n")
		_, _ = w.WriteString("finding title: " + o.Query.FindingTitle + "\n\n")
		if o.Error != "" {
			_, _ = w.WriteString("ERROR: " + o.Error + "\n")
			_, _ = w.WriteString(strings.Repeat("=", 100) + "\n")
			continue
		}
		for _, r := range o.Rows {
			// write values in stable key order
			keys := make([]string, 0, len(r))
			for k := range r {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			vals := make([]string, 0, len(keys))
			for _, k := range keys {
				v := r[k]
				if v != nil {
					vals = append(vals, fmt.Sprintf("%v", v))
				}
			}
			_, _ = w.WriteString(strings.Join(vals, ",") + "\n")
		}
		_, _ = w.WriteString(strings.Repeat("=", 100) + "\n")
	}
	return nil
}

func writeXLSX(outs []queryOutput, path string) error {
	f := excelize.NewFile()
	// remove default sheet
	defaultSheet := f.GetSheetName(0)
	if defaultSheet != "" {
		_ = f.DeleteSheet(defaultSheet)
	}

	for _, o := range outs {
		sheet := safeSheetName(o.Query.SheetName)
		idx, err := f.NewSheet(sheet)
		if err != nil {
			return err
		}
		_ = idx

		r := 1
		c := 1
		// description
		_ = f.SetCellValue(sheet, cell(c, r), o.Query.Description)
		r++
		_ = f.SetCellValue(sheet, cell(c, r), "finding title:")
		_ = f.SetCellValue(sheet, cell(c+1, r), o.Query.FindingTitle)
		r++
		_ = f.SetCellValue(sheet, cell(c, r), "finding write-up:")
		r += 2 // space

		// headers
		for i, h := range o.Query.Headers {
			_ = f.SetCellValue(sheet, cell(c+i, r), h)
		}
		r++

		if o.Error != "" {
			_ = f.SetCellValue(sheet, cell(c, r), "ERROR")
			_ = f.SetCellValue(sheet, cell(c+1, r), o.Error)
			continue
		}

		// results
		for _, row := range o.Rows {
			for i, h := range o.Query.Headers {
				key := headerToKey(h)
				_ = f.SetCellValue(sheet, cell(c+i, r), fmt.Sprintf("%v", row[key]))
			}
			r++
		}
	}

	// Set first sheet active
	if len(outs) > 0 {
		f.SetActiveSheet(0)
	}
	return f.SaveAs(path)
}

func writeStructured(outs []queryOutput, format, outPath string) {
	w := os.Stdout
	var f *os.File
	if strings.TrimSpace(outPath) != "" {
		var err error
		f, err = os.Create(outPath)
		if err != nil {
			fatalf("cannot create output file: %v", err)
		}
		defer f.Close()
		w = f
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(outs)
	case "csv":
		writeCSV(w, outs)
	case "text":
		// text is the same as the "-t" format but to stdout
		_ = writeTextToWriter(w, outs)
	}
}

func writeCSV(w *os.File, outs []queryOutput) {
	// Determine union of keys.
	keySet := map[string]struct{}{}
	for _, o := range outs {
		for _, r := range o.Rows {
			for k := range r {
				keySet[k] = struct{}{}
			}
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	header := append([]string{"query_id", "query_title", "category"}, keys...)
	cw := csv.NewWriter(w)
	_ = cw.Write(header)

	for _, o := range outs {
		if o.Error != "" {
			_ = cw.Write([]string{o.Query.ID, o.Query.Title, o.Query.Category, "ERROR", o.Error})
			continue
		}
		for _, r := range o.Rows {
			rowOut := []string{o.Query.ID, o.Query.Title, o.Query.Category}
			for _, k := range keys {
				rowOut = append(rowOut, fmt.Sprintf("%v", r[k]))
			}
			_ = cw.Write(rowOut)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		fatalf("csv write error: %v", err)
	}
}

func writeTextToWriter(w *os.File, outs []queryOutput) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	for _, o := range outs {
		fmt.Fprintf(bw, "%s\n%s\nfinding title: %s\n\n", o.Query.SheetName, o.Query.Description, o.Query.FindingTitle)
		if o.Error != "" {
			fmt.Fprintf(bw, "ERROR: %s\n", o.Error)
			fmt.Fprintf(bw, "%s\n", strings.Repeat("=", 100))
			continue
		}
		for _, r := range o.Rows {
			keys := make([]string, 0, len(r))
			for k := range r {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			vals := make([]string, 0, len(keys))
			for _, k := range keys {
				v := r[k]
				if v != nil {
					vals = append(vals, fmt.Sprintf("%v", v))
				}
			}
			fmt.Fprintln(bw, strings.Join(vals, ","))
		}
		fmt.Fprintln(bw, strings.Repeat("=", 100))
	}
	return nil
}

func filterQueriesStrict(in []Query, category string) ([]Query, error) {
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

func findQueryByID(in []Query, id string) (Query, bool) {
	for _, q := range in {
		if q.ID == id {
			return q, true
		}
	}
	return Query{}, false
}

func printQueryList(qs []Query) {
	sort.Slice(qs, func(i, j int) bool {
		if qs[i].Category != qs[j].Category {
			return qs[i].Category < qs[j].Category
		}
		return qs[i].ID < qs[j].ID
	})
	for _, q := range qs {
		fmt.Printf("[%s] %s\n  id: %s\n  sheet: %s\n  %s\n\n", q.Category, q.Title, q.ID, q.SheetName, q.Description)
	}
}

func safeSheetName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "Sheet"
	}
	// Excel sheet name constraints: <= 31 chars; cannot contain : \ / ? * [ ]
	repl := strings.NewReplacer(":", "-", "\\", "-", "/", "-", "?", "", "*", "", "[", "(", "]", ")")
	s = repl.Replace(s)
	if len(s) > 31 {
		s = s[:31]
	}
	return s
}

func cell(col, row int) string {
	// 1-indexed col/row
	name, _ := excelize.ColumnNumberToName(col)
	return fmt.Sprintf("%s%d", name, row)
}

func headerToKey(h string) string {
	// We return keys based on our Cypher aliases (we used consistent aliases).
	// For legacy headers (like "Hostname"), map to common aliases.
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
	default:
		// try to make a reasonable key
		h = strings.ReplaceAll(h, " ", "_")
		return h
	}
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
