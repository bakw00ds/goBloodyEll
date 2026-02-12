package neo4jrunner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type QueryJob struct {
	Index  int
	ID     string
	Name   string
	Cypher string
}

type QueryResult struct {
	ResultSet ResultSet
	Err       error
	Skipped   bool
	SkipWhy   string
}

type RunnerOpts struct {
	DB              string
	Limit           int
	Parallel        int
	PerQueryTimeout time.Duration
	Retries         int
	FailFast        bool
	Verbose         bool
}

func Run(
	ctx context.Context,
	driver neo4j.DriverWithContext,
	jobs []QueryJob,
	opts RunnerOpts,
	exec func(context.Context, neo4j.SessionWithContext, string, int) (ResultSet, error),
) []QueryResult {
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	out := make([]QueryResult, len(jobs))

	jobsCh := make(chan QueryJob)
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopCh) }) }

	var wg sync.WaitGroup
	wg.Add(opts.Parallel)
	for w := 0; w < opts.Parallel; w++ {
		go func() {
			defer wg.Done()
			sess := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: opts.DB})
			defer sess.Close(ctx)

			for {
				select {
				case <-stopCh:
					return
				case job, ok := <-jobsCh:
					if !ok {
						return
					}
					if opts.Verbose {
						fmt.Fprintf(os.Stderr, "[+] (%d/%d) %s [%s]\n", job.Index+1, len(jobs), job.Name, job.ID)
					}
					qctx := ctx
					var cancel context.CancelFunc
					if opts.PerQueryTimeout > 0 {
						qctx, cancel = context.WithTimeout(ctx, opts.PerQueryTimeout)
					}
					rs, err := execWithRetries(qctx, sess, job.Cypher, opts.Limit, opts.Retries, exec)
					if cancel != nil {
						cancel()
					}
					out[job.Index] = QueryResult{ResultSet: rs, Err: err}
					if err != nil && opts.FailFast {
						stop()
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobsCh)
		for _, job := range jobs {
			select {
			case <-stopCh:
				return
			case jobsCh <- job:
			}
		}
	}()

	wg.Wait()
	return out
}

func execWithRetries(ctx context.Context, sess neo4j.SessionWithContext, cypher string, limit int, retries int, exec func(context.Context, neo4j.SessionWithContext, string, int) (ResultSet, error)) (ResultSet, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		rs, err := exec(ctx, sess, cypher, limit)
		if err == nil {
			return rs, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return ResultSet{}, ctx.Err()
		}
		if !looksTransient(err) {
			return ResultSet{}, err
		}
		// small backoff
		sleep := time.Duration(200*(attempt+1)) * time.Millisecond
		t := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			t.Stop()
			return ResultSet{}, ctx.Err()
		case <-t.C:
		}
	}
	return ResultSet{}, lastErr
}

func looksTransient(err error) bool {
	var neo4jErr *neo4j.Neo4jError
	if errors.As(err, &neo4jErr) {
		if neo4jErr.Classification() == "TransientError" {
			return true
		}
		return false
	}
	msg := err.Error()
	for _, sub := range []string{"connection refused", "i/o timeout", "temporary", "EOF", "broken pipe", "reset by peer", "ServiceUnavailable"} {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
