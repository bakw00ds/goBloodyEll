package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func runQueriesParallel(
	ctx context.Context,
	driver neo4j.DriverWithContext,
	db string,
	qs []Query,
	limit int,
	perQueryTimeout time.Duration,
	parallel int,
	retries int,
) []queryOutput {
	outs := make([]queryOutput, len(qs))

	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(parallel)

	for w := 0; w < parallel; w++ {
		go func() {
			defer wg.Done()
			sess := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: db})
			defer sess.Close(ctx)

			for idx := range jobs {
				q := qs[idx]
				fmt.Fprintf(os.Stderr, "[+] (%d/%d) %s [%s]\n", idx+1, len(qs), q.SheetName, q.ID)

				o := queryOutput{Query: q}
				qctx := ctx
				var cancel context.CancelFunc
				if perQueryTimeout > 0 {
					qctx, cancel = context.WithTimeout(ctx, perQueryTimeout)
				}

				rows, err := runCypherWithRetries(qctx, sess, q.Cypher, limit, retries)
				if cancel != nil {
					cancel()
				}

				if err != nil {
					o.Error = err.Error()
				} else {
					o.Rows = rows
					o.Count = len(rows)
				}
				outs[idx] = o
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := range qs {
			jobs <- i
		}
	}()

	wg.Wait()
	return outs
}

func runCypherWithRetries(ctx context.Context, sess neo4j.SessionWithContext, cypher string, limit int, retries int) ([]row, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		rows, err := runCypher(ctx, sess, cypher, limit)
		if err == nil {
			return rows, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !looksTransient(err) {
			return nil, err
		}
		// small backoff
		sleep := time.Duration(200*(attempt+1)) * time.Millisecond
		t := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	return nil, lastErr
}

func looksTransient(err error) bool {
	// The driver surfaces a range of error types. Keep this conservative.
	var neo4jErr *neo4j.Neo4jError
	if errors.As(err, &neo4jErr) {
		// transient, service unavailable, deadlocks, etc.
		if neo4jErr.Classification() == "TransientError" {
			return true
		}
		// Some auth/statement errors should not retry.
		return false
	}
	// Fallback: some network-ish errors may be transient.
	msg := err.Error()
	if containsAny(msg, []string{"connection refused", "i/o timeout", "temporary", "EOF", "broken pipe", "reset by peer", "ServiceUnavailable"}) {
		return true
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && (len(s) >= len(sub)) {
			if containsCaseInsensitive(s, sub) {
				return true
			}
		}
	}
	return false
}

func containsCaseInsensitive(s, sub string) bool {
	// cheap case-insensitive contains
	return stringIndexFold(s, sub) >= 0
}

func stringIndexFold(s, sub string) int {
	// naive but fine for short messages
	ls := []rune(s)
	lsub := []rune(sub)
	for i := 0; i+lsubLen(lsub) <= len(ls); i++ {
		match := true
		for j := 0; j < len(lsub); j++ {
			if toLower(ls[i+j]) != toLower(lsub[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func lsubLen(r []rune) int { return len(r) }

func toLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}
