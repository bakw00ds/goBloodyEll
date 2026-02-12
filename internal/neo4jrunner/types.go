package neo4jrunner

type ResultSet struct {
	Columns []string
	Rows    [][]any
}

func (rs ResultSet) ColumnIndex() map[string]int {
	m := make(map[string]int, len(rs.Columns))
	for i, c := range rs.Columns {
		m[c] = i
	}
	return m
}
