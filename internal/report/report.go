package report

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/bakw00ds/goBloodyEll/internal/format"
	"github.com/bakw00ds/goBloodyEll/internal/neo4jrunner"
	"github.com/bakw00ds/goBloodyEll/internal/queries"
)

type Output struct {
	Query   queries.Query         `json:"query"`
	Result  neo4jrunner.ResultSet `json:"result"`
	Error   string                `json:"error,omitempty"`
	Skipped bool                  `json:"skipped,omitempty"`
	SkipWhy string                `json:"skipWhy,omitempty"`
}

func WriteStructured(outs []Output, formatName, outPath string) error {
	w := os.Stdout
	var f *os.File
	if strings.TrimSpace(outPath) != "" {
		var err error
		f, err = os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch formatName {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(outs)
	case "csv":
		return writeCSV(w, outs)
	case "text":
		return writeTextToWriter(w, outs)
	default:
		return fmt.Errorf("unknown structured format: %s", formatName)
	}
}

func WriteConsole(outs []Output) {
	f := format.New()
	for _, o := range outs {
		fmt.Println(o.Query.SheetName)
		fmt.Println(o.Query.Description)
		if !strings.EqualFold(o.Query.Category, "INFO") && strings.TrimSpace(o.Query.FindingTitle) != "" {
			fmt.Println("finding title:", o.Query.FindingTitle)
		}
		fmt.Println("neo4j query:", f.OneLine(o.Query.Cypher))
		fmt.Println()
		if o.Skipped {
			fmt.Println("SKIPPED:", o.SkipWhy)
			fmt.Println(strings.Repeat("=", 100))
			continue
		}
		if o.Error != "" {
			fmt.Println("ERROR:", o.Error)
			fmt.Println(strings.Repeat("=", 100))
			continue
		}
		cols := o.Result.Columns
		colIndex := o.Result.ColumnIndex()
		for _, row := range o.Result.Rows {
			vals := make([]string, 0, len(o.Query.ColumnKeys))
			for _, key := range o.Query.ColumnKeys {
				idx, ok := colIndex[key]
				if !ok || idx >= len(row) {
					vals = append(vals, "")
					continue
				}
				vals = append(vals, f.Value(key, row[idx]))
			}
			if len(vals) == 0 {
				// fallback to printing all columns
				vals = make([]string, 0, len(row))
				for i, v := range row {
					vals = append(vals, f.Value(cols[i], v))
				}
			}
			fmt.Println(strings.Join(vals, ", "))
		}
		fmt.Println(strings.Repeat("=", 100))
	}
}

func WriteTextFile(outs []Output, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeTextToWriter(f, outs)
}

func writeTextToWriter(w *os.File, outs []Output) error {
	fmtter := format.New()
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	for _, o := range outs {
		fmt.Fprintf(bw, "%s\n%s\n", o.Query.SheetName, o.Query.Description)
		if !strings.EqualFold(o.Query.Category, "INFO") && strings.TrimSpace(o.Query.FindingTitle) != "" {
			fmt.Fprintf(bw, "finding title: %s\n", o.Query.FindingTitle)
		}
		fmt.Fprintf(bw, "neo4j query: %s\n\n", fmtter.OneLine(o.Query.Cypher))
		if o.Skipped {
			fmt.Fprintf(bw, "SKIPPED: %s\n", o.SkipWhy)
			fmt.Fprintf(bw, "%s\n", strings.Repeat("=", 100))
			continue
		}
		if o.Error != "" {
			fmt.Fprintf(bw, "ERROR: %s\n", o.Error)
			fmt.Fprintf(bw, "%s\n", strings.Repeat("=", 100))
			continue
		}
		colIndex := o.Result.ColumnIndex()
		for _, row := range o.Result.Rows {
			vals := make([]string, 0, len(o.Query.ColumnKeys))
			for _, key := range o.Query.ColumnKeys {
				idx, ok := colIndex[key]
				if !ok || idx >= len(row) {
					vals = append(vals, "")
					continue
				}
				vals = append(vals, fmtter.Value(key, row[idx]))
			}
			fmt.Fprintln(bw, strings.Join(vals, ","))
		}
		fmt.Fprintln(bw, strings.Repeat("=", 100))
	}
	return nil
}

func WriteXLSX(outs []Output, path string, skipEmpty bool) error {
	fmtter := format.New()
	f := excelize.NewFile()
	defaultSheet := f.GetSheetName(0)
	firstSheet := true

	for _, o := range outs {
		if skipEmpty && (o.Skipped || o.Error != "" || len(o.Result.Rows) == 0) {
			continue
		}
		sheet := safeSheetName(o.Query.SheetName)
		idx, err := f.NewSheet(sheet)
		if err != nil {
			return err
		}
		if firstSheet {
			f.SetActiveSheet(idx)
			for _, name := range []string{"Sheet1", defaultSheet} {
				name = strings.TrimSpace(name)
				if name != "" && name != sheet {
					_ = f.DeleteSheet(name)
				}
			}
			firstSheet = false
		}

		r := 1
		c := 1
		_ = f.SetCellValue(sheet, cell(c, r), o.Query.Description)
		r++
		if !strings.EqualFold(o.Query.Category, "INFO") && strings.TrimSpace(o.Query.FindingTitle) != "" {
			_ = f.SetCellValue(sheet, cell(c, r), "finding title:")
			_ = f.SetCellValue(sheet, cell(c+1, r), o.Query.FindingTitle)
			r++
		}
		_ = f.SetCellValue(sheet, cell(c, r), "neo4j query:")
		_ = f.SetCellValue(sheet, cell(c+1, r), o.Query.Cypher)
		r += 2

		for i, h := range o.Query.Headers {
			_ = f.SetCellValue(sheet, cell(c+i, r), h)
		}
		r++

		// Track widths for a simple "auto-fit" (Excelize doesn't do real autofit).
		colWidths := make([]int, len(o.Query.Headers))
		for i, h := range o.Query.Headers {
			colWidths[i] = displayWidth(h)
		}

		if o.Skipped {
			_ = f.SetCellValue(sheet, cell(c, r), "SKIPPED")
			_ = f.SetCellValue(sheet, cell(c+1, r), o.SkipWhy)
			continue
		}
		if o.Error != "" {
			_ = f.SetCellValue(sheet, cell(c, r), "ERROR")
			_ = f.SetCellValue(sheet, cell(c+1, r), o.Error)
			continue
		}

		colIndex := o.Result.ColumnIndex()
		rowCountForFit := 0
		for _, row := range o.Result.Rows {
			for i, key := range o.Query.ColumnKeys {
				idx, ok := colIndex[key]
				if !ok || idx >= len(row) {
					continue
				}
				val := fmtter.Value(key, row[idx])
				_ = f.SetCellValue(sheet, cell(c+i, r), val)
				// update width estimate (cap work)
				if rowCountForFit < 300 {
					w := displayWidth(val)
					if w > colWidths[i] {
						colWidths[i] = w
					}
				}
			}
			r++
			rowCountForFit++
		}

		// Apply widths (simple heuristic).
		applyColumnWidths(f, sheet, colWidths)
	}

	// If everything was skipped/empty, keep default sheet and write a message.
	if firstSheet {
		_ = f.SetCellValue(defaultSheet, "A1", "No sheets were produced (all empty/skipped/error).")
	}

	return f.SaveAs(path)
}

func safeSheetName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "Sheet"
	}
	repl := strings.NewReplacer(":", "-", "\\", "-", "/", "-", "?", "", "*", "", "[", "(", "]", ")")
	s = repl.Replace(s)
	if len(s) > 31 {
		s = s[:31]
	}
	return s
}

func cell(col, row int) string {
	name, _ := excelize.ColumnNumberToName(col)
	return fmt.Sprintf("%s%d", name, row)
}

func applyColumnWidths(f *excelize.File, sheet string, widths []int) {
	// widths in approximate characters. Clamp to keep Excel readable.
	for i, w := range widths {
		if w <= 0 {
			continue
		}
		if w < 10 {
			w = 10
		}
		if w > 60 {
			w = 60
		}
		colName, err := excelize.ColumnNumberToName(i + 1)
		if err != nil {
			continue
		}
		_ = f.SetColWidth(sheet, colName, colName, float64(w))
	}
}

func displayWidth(s string) int {
	// rough "Excel-like" width in monospace chars.
	// count runes but cap extreme long strings.
	if len(s) == 0 {
		return 0
	}
	w := 0
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		w++
		if w > 200 {
			break
		}
	}
	return w
}

func writeCSV(w *os.File, outs []Output) error {
	// Determine union of keys (query_id/title/category + result columns)
	keySet := map[string]struct{}{}
	for _, o := range outs {
		for _, c := range o.Result.Columns {
			keySet[c] = struct{}{}
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	header := append([]string{"query_id", "query_title", "category", "status"}, keys...)
	cw := csv.NewWriter(w)
	_ = cw.Write(header)

	fmtter := format.New()
	for _, o := range outs {
		status := "ok"
		if o.Skipped {
			status = "skipped"
		}
		if o.Error != "" {
			status = "error"
		}

		colIndex := o.Result.ColumnIndex()
		if len(o.Result.Rows) == 0 {
			rowOut := []string{o.Query.ID, o.Query.Title, o.Query.Category, status}
			for range keys {
				rowOut = append(rowOut, "")
			}
			_ = cw.Write(rowOut)
			continue
		}
		for _, row := range o.Result.Rows {
			rowOut := []string{o.Query.ID, o.Query.Title, o.Query.Category, status}
			for _, k := range keys {
				idx, ok := colIndex[k]
				if !ok || idx >= len(row) {
					rowOut = append(rowOut, "")
					continue
				}
				rowOut = append(rowOut, fmtter.Value(k, row[idx]))
			}
			_ = cw.Write(rowOut)
		}
	}
	cw.Flush()
	return cw.Error()
}
