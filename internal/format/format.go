package format

import (
	"fmt"
	"strings"
	"time"
)

type Formatter struct{}

func New() *Formatter { return &Formatter{} }

func (f *Formatter) OneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func (f *Formatter) Value(columnKey string, v any) string {
	if v == nil {
		return ""
	}
	lk := strings.ToLower(columnKey)
	if strings.Contains(lk, "pwdlastset") || strings.Contains(lk, "lastlogon") || strings.Contains(lk, "lastlogontimestamp") {
		switch x := v.(type) {
		case int64:
			return time.Unix(x, 0).Format(time.RFC3339)
		case int:
			return time.Unix(int64(x), 0).Format(time.RFC3339)
		case float64:
			return time.Unix(int64(x), 0).Format(time.RFC3339)
		case float32:
			return time.Unix(int64(x), 0).Format(time.RFC3339)
		case string:
			return x
		}
	}
	return fmt.Sprintf("%v", v)
}
