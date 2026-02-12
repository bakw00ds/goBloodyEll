package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// printSchema prints a quick inventory of labels + relationship types,
// and for each a sample of properties. This helps tailor query packs
// across different ingestors (SharpHound/RustHound/BHCE, AzureHound, ROADtools).
func printSchema(ctx context.Context, sess neo4j.SessionWithContext) error {
	fmt.Println("== Neo4j schema summary ==")

	labels, err := listNodeLabels(ctx, sess)
	if err != nil {
		return err
	}
	rels, err := listRelTypes(ctx, sess)
	if err != nil {
		return err
	}

	fmt.Printf("Node labels (%d): %s\n", len(labels), strings.Join(labels, ", "))
	fmt.Printf("Relationship types (%d): %s\n", len(rels), strings.Join(rels, ", "))

	fmt.Println("\n-- Label property samples --")
	for _, l := range labels {
		props, err := sampleNodeProperties(ctx, sess, l)
		if err != nil {
			fmt.Printf("%s: (error: %v)\n", l, err)
			continue
		}
		fmt.Printf("%s: %s\n", l, strings.Join(props, ", "))
	}

	fmt.Println("\n-- Relationship property samples --")
	for _, t := range rels {
		props, err := sampleRelProperties(ctx, sess, t)
		if err != nil {
			fmt.Printf("%s: (error: %v)\n", t, err)
			continue
		}
		fmt.Printf("%s: %s\n", t, strings.Join(props, ", "))
	}

	return nil
}

func listNodeLabels(ctx context.Context, sess neo4j.SessionWithContext) ([]string, error) {
	rows, err := runCypher(ctx, sess, "CALL db.labels() YIELD label RETURN label ORDER BY label", 10000)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if v, ok := r["label"]; ok {
			out = append(out, fmt.Sprintf("%v", v))
		}
	}
	return out, nil
}

func listRelTypes(ctx context.Context, sess neo4j.SessionWithContext) ([]string, error) {
	rows, err := runCypher(ctx, sess, "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType ORDER BY relationshipType", 10000)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if v, ok := r["relationshipType"]; ok {
			out = append(out, fmt.Sprintf("%v", v))
		}
	}
	return out, nil
}

func sampleNodeProperties(ctx context.Context, sess neo4j.SessionWithContext, label string) ([]string, error) {
	cy := fmt.Sprintf(`MATCH (n:%s)
WITH n LIMIT 25
UNWIND keys(n) AS k
RETURN DISTINCT k AS key
ORDER BY key`, neo4jQuoteIdent(label))
	rows, err := runCypher(ctx, sess, cy, 10000)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		if v, ok := r["key"]; ok {
			keys = append(keys, fmt.Sprintf("%v", v))
		}
	}
	// Keep it readable
	if len(keys) > 40 {
		keys = keys[:40]
		keys = append(keys, "…")
	}
	return keys, nil
}

func sampleRelProperties(ctx context.Context, sess neo4j.SessionWithContext, relType string) ([]string, error) {
	cy := fmt.Sprintf(`MATCH ()-[r:%s]-()
WITH r LIMIT 25
UNWIND keys(r) AS k
RETURN DISTINCT k AS key
ORDER BY key`, neo4jQuoteIdent(relType))
	rows, err := runCypher(ctx, sess, cy, 10000)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		if v, ok := r["key"]; ok {
			keys = append(keys, fmt.Sprintf("%v", v))
		}
	}
	if len(keys) > 40 {
		keys = keys[:40]
		keys = append(keys, "…")
	}
	return keys, nil
}

// Neo4j doesn't allow parameterizing label/type; quote defensively.
// BloodHound labels/types are simple; we still sanitize.
func neo4jQuoteIdent(s string) string {
	// allow only [A-Za-z0-9_]
	b := strings.Builder{}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return "X"
	}
	return out
}

// helper to keep imports used (sort is used by gofmt for potential future)
var _ = sort.Strings
