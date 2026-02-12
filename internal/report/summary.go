package report

import (
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/bakw00ds/goBloodyEll/internal/format"
)

func writeSummarySheet(f *excelize.File, sheet string, outs []Output) error {
	fmtter := format.New()
	// header
	headers := []string{"order", "category", "sheet", "id", "status", "rows", "cypher"}
	for i, h := range headers {
		_ = f.SetCellValue(sheet, cell(i+1, 1), h)
	}

	ok, errc, skipped, empty := 0, 0, 0, 0
	row := 2
	for i, o := range outs {
		status := "ok"
		rows := len(o.Result.Rows)
		if o.Skipped {
			status = "skipped"
			skipped++
		} else if o.Error != "" {
			status = "error"
			errc++
		} else if rows == 0 {
			status = "empty"
			empty++
		} else {
			ok++
		}

		_ = f.SetCellValue(sheet, cell(1, row), i+1)
		_ = f.SetCellValue(sheet, cell(2, row), o.Query.Category)
		_ = f.SetCellValue(sheet, cell(3, row), o.Query.SheetName)
		_ = f.SetCellValue(sheet, cell(4, row), o.Query.ID)
		_ = f.SetCellValue(sheet, cell(5, row), status)
		_ = f.SetCellValue(sheet, cell(6, row), rows)
		_ = f.SetCellValue(sheet, cell(7, row), fmtter.OneLine(o.Query.Cypher))
		row++
	}

	// totals
	row++
	_ = f.SetCellValue(sheet, cell(1, row), "totals")
	_ = f.SetCellValue(sheet, cell(2, row), fmt.Sprintf("ok=%d", ok))
	_ = f.SetCellValue(sheet, cell(3, row), fmt.Sprintf("empty=%d", empty))
	_ = f.SetCellValue(sheet, cell(4, row), fmt.Sprintf("skipped=%d", skipped))
	_ = f.SetCellValue(sheet, cell(5, row), fmt.Sprintf("error=%d", errc))
	_ = f.SetCellValue(sheet, cell(6, row), fmt.Sprintf("total=%d", len(outs)))

	// width hints
	_ = f.SetColWidth(sheet, "A", "A", 8)
	_ = f.SetColWidth(sheet, "B", "B", 10)
	_ = f.SetColWidth(sheet, "C", "C", 30)
	_ = f.SetColWidth(sheet, "D", "D", 30)
	_ = f.SetColWidth(sheet, "E", "F", 10)
	_ = f.SetColWidth(sheet, "G", "G", 80)

	// freeze header row
	_ = f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
		Selection: []excelize.Selection{{
			SQRef:      "A2:G1048576",
			ActiveCell: "A2",
			Pane:       "bottomLeft",
		}},
	})

	// Add a note if any query has empty sheetname
	for _, o := range outs {
		if strings.TrimSpace(o.Query.SheetName) == "" {
			_ = f.SetCellValue(sheet, "A1", "warning: some queries have empty sheet names")
			break
		}
	}

	return nil
}
