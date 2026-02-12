package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bakw00ds/goBloodyEll/internal/format"
)

// WriteCoreCSVs writes four focused CSV exports alongside the main report.
// It expects the corresponding queries to exist in outs (by ID).
func WriteCoreCSVs(outDir string, outs []Output) error {
	outDir = strings.TrimSpace(outDir)
	if outDir == "" {
		return nil
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	core := []struct {
		id   string
		file string
	}{
		{"ad-all-users-samaccountname", "users.csv"},
		{"ad-all-computers-fqdn", "computers.csv"},
		{"ad-domain-admins", "domain_admins.csv"},
		{"ad-domain-controllers", "domain_controllers.csv"},
	}

	byID := map[string]Output{}
	for _, o := range outs {
		byID[o.Query.ID] = o
	}

	for _, c := range core {
		o, ok := byID[c.id]
		if !ok {
			continue
		}
		path := filepath.Join(outDir, c.file)
		if err := writeSingleCSV(path, o); err != nil {
			return fmt.Errorf("write %s: %w", c.file, err)
		}
	}
	return nil
}

func writeSingleCSV(path string, o Output) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	fmtter := format.New()

	// If we have query headers, use those. Otherwise use result columns.
	headers := o.Query.Headers
	keys := o.Query.ColumnKeys
	if len(headers) == 0 {
		headers = o.Result.Columns
		keys = o.Result.Columns
	}
	_ = w.Write(headers)

	if o.Skipped {
		_ = w.Write([]string{"SKIPPED", o.SkipWhy})
		return w.Error()
	}
	if o.Error != "" {
		_ = w.Write([]string{"ERROR", o.Error})
		return w.Error()
	}

	colIndex := o.Result.ColumnIndex()
	for _, row := range o.Result.Rows {
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			idx, ok := colIndex[k]
			if !ok || idx >= len(row) {
				out = append(out, "")
				continue
			}
			out = append(out, fmtter.Value(k, row[idx]))
		}
		_ = w.Write(out)
	}

	return w.Error()
}
