package schema

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Summary struct {
	Labels []string
	Rels   []string
}

func Discover(ctx context.Context, sess neo4j.SessionWithContext) (Summary, error) {
	labels, err := list(ctx, sess, "CALL db.labels() YIELD label RETURN label")
	if err != nil {
		return Summary{}, err
	}
	rels, err := list(ctx, sess, "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType")
	if err != nil {
		return Summary{}, err
	}
	sort.Strings(labels)
	sort.Strings(rels)
	return Summary{Labels: labels, Rels: rels}, nil
}

func Print(summary Summary) {
	fmt.Println("== Neo4j schema summary ==")
	fmt.Printf("Node labels (%d): %s\n", len(summary.Labels), strings.Join(summary.Labels, ", "))
	fmt.Printf("Relationship types (%d): %s\n", len(summary.Rels), strings.Join(summary.Rels, ", "))
}

func list(ctx context.Context, sess neo4j.SessionWithContext, cypher string) ([]string, error) {
	res, err := sess.Run(ctx, cypher, nil)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0)
	for res.Next(ctx) {
		rec := res.Record()
		if len(rec.Keys) == 0 {
			continue
		}
		v, _ := rec.Get(rec.Keys[0])
		out = append(out, fmt.Sprintf("%v", v))
	}
	if err := res.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
