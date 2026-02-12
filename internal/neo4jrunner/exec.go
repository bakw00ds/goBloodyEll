package neo4jrunner

import (
	"context"
	"fmt"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func ExecCypher(ctx context.Context, sess neo4j.SessionWithContext, cypher string, limit int) (ResultSet, error) {
	cy := strings.TrimSpace(cypher)
	if limit > 0 && !strings.Contains(strings.ToLower(cy), "limit") {
		cy = cy + fmt.Sprintf("\nLIMIT %d", limit)
	}

	anyRes, err := sess.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cy, nil)
		if err != nil {
			return nil, err
		}
		var cols []string
		rows := make([][]any, 0)
		for res.Next(ctx) {
			rec := res.Record()
			if cols == nil {
				cols = append([]string(nil), rec.Keys...)
			}
			row := make([]any, 0, len(rec.Keys))
			for _, k := range rec.Keys {
				v, _ := rec.Get(k)
				row = append(row, v)
			}
			rows = append(rows, row)
			if limit > 0 && len(rows) >= limit {
				break
			}
		}
		if err := res.Err(); err != nil {
			return nil, err
		}
		if cols == nil {
			cols = []string{}
		}
		return ResultSet{Columns: cols, Rows: rows}, nil
	})
	if err != nil {
		return ResultSet{}, err
	}
	return anyRes.(ResultSet), nil
}
