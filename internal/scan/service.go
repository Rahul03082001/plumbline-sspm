// Package scan runs scans: a small in-process queue with two workers, the
// atomic publish of results, drift, score and coverage. The web handlers
// (both JSON and HTML) call this service and contain no business logic.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/rules"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

// Errors returned by RequestScan.
var (
	ErrUnknownConnection = errors.New("unknown connection")
	ErrShuttingDown      = errors.New("shutting down")
	ErrQueueFull         = errors.New("scan queue is full")
)

// Scan failure codes stored in scans.error.
const (
	FailUnauthorized  = "unauthorized"
	FailRateLimited   = "rate_limited"
	FailTimeout       = "timeout"
	FailInterrupted   = "interrupted"
	FailPanic         = "panic"
	FailPublish       = "publish_failed"
	FailCollection    = "collection_failed"
	FailQueueFull     = "queue_full"
	defaultWorkers    = 2
	defaultQueueSize  = 16
	defaultScanTimout = 2 * time.Minute
)

// Metrics receives scan events. The metrics package implements it; nil is
// allowed (tests).
type Metrics interface {
	ScanFinished(mode, status string, d time.Duration)
	CheckResults(connectionID string, counts map[model.Result]int)
}

// Options configures the service.
type Options struct {
	Workers     int
	QueueSize   int
	ScanTimeout time.Duration
	Logger      *slog.Logger
	Metrics     Metrics
}

// registration pairs a connection with the connector that scans it.
type registration struct {
	conn      model.Connection
	connector connector.Connector
}

type job struct {
	scanID       string
	connectionID string
}

// Service is the scan engine and the read model for the UI/API.
type Service struct {
	store  *store.Store
	rules  []model.Rule
	titles map[string]string // rule ID -> title
	opts   Options
	log    *slog.Logger

	conns map[string]registration // written only before Start

	queue chan job      // buffered channel = the job queue
	stop  chan struct{} // closed on shutdown to tell workers to exit
	wg    sync.WaitGroup

	baseCtx    context.Context // parent of every scan's context
	cancelBase context.CancelFunc

	mu     sync.Mutex // guards closed and sending on queue
	closed bool

	// beforeCommit is a test hook: if set, it runs at the end of the publish
	// transaction, and returning an error makes the publish roll back.
	beforeCommit func() error
}

// New creates a service. Call Register for each connection, then Start.
func New(st *store.Store, ruleset []model.Rule, opts Options) *Service {
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.ScanTimeout <= 0 {
		opts.ScanTimeout = defaultScanTimout
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	titles := make(map[string]string, len(ruleset))
	for _, r := range ruleset {
		titles[r.ID] = r.Title
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		store: st, rules: ruleset, titles: titles, opts: opts, log: opts.Logger,
		conns: map[string]registration{},
		queue: make(chan job, opts.QueueSize), stop: make(chan struct{}),
		baseCtx: ctx, cancelBase: cancel,
	}
}

// Register adds a connection (and saves it in the database).
func (s *Service) Register(ctx context.Context, c model.Connection, conn connector.Connector) error {
	if err := s.store.UpsertConnection(ctx, c); err != nil {
		return err
	}
	s.conns[c.ID] = registration{conn: c, connector: conn}
	return nil
}

// Start launches the worker goroutines.
func (s *Service) Start() {
	for i := 0; i < s.opts.Workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
}

// QueueDepth is the number of scans waiting for a worker (for /metrics).
func (s *Service) QueueDepth() int { return len(s.queue) }

// RequestScan creates a queued scan and hands it to the workers. If the
// connection already has an active scan it returns *store.ActiveScanError
// (the API turns that into 409 with the active scan's ID).
func (s *Service) RequestScan(ctx context.Context, connectionID string) (model.Scan, error) {
	if _, ok := s.conns[connectionID]; !ok {
		return model.Scan{}, ErrUnknownConnection
	}
	if s.isClosed() {
		return model.Scan{}, ErrShuttingDown
	}
	sc, err := s.store.CreateScan(ctx, connectionID)
	if err != nil {
		return model.Scan{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.markFailed(sc.ID, FailInterrupted, nil)
		return model.Scan{}, ErrShuttingDown
	}
	// select with default = "send if there is room, otherwise don't block".
	select {
	case s.queue <- job{scanID: sc.ID, connectionID: connectionID}:
		return sc, nil
	default:
		s.markFailed(sc.ID, FailQueueFull, nil)
		return model.Scan{}, ErrQueueFull
	}
}

// SeedInitialScans queues a scan for every connection that has never
// succeeded, so a fresh (or reset) deployment never shows an empty dashboard.
func (s *Service) SeedInitialScans(ctx context.Context) {
	for id := range s.conns {
		n, err := s.store.CountSucceeded(ctx, id)
		if err != nil || n > 0 {
			continue
		}
		if _, err := s.RequestScan(ctx, id); err != nil {
			s.log.Warn("initial scan not queued", "connection_id", id, "error", err)
		}
	}
}

// Shutdown stops accepting scans, lets running scans finish for up to the
// ctx deadline (main uses 8s), then cancels them. Queued scans that never
// started are marked failed "interrupted".
func (s *Service) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	close(s.stop)

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn("shutdown deadline reached; cancelling running scans")
		s.cancelBase()
		<-done // workers return promptly once their context is cancelled
	}
	s.cancelBase()

	// Drain jobs nobody picked up.
	for {
		select {
		case j := <-s.queue:
			s.markFailed(j.scanID, FailInterrupted, nil)
		default:
			return
		}
	}
}

func (s *Service) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// worker processes jobs until shutdown.
func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		case j := <-s.queue:
			s.process(j)
		}
	}
}

// process runs one scan end to end and records the outcome.
func (s *Service) process(j job) {
	reg := s.conns[j.connectionID]
	log := s.log.With("scan_id", j.scanID, "connection_id", j.connectionID, "mode", string(reg.conn.Mode))
	start := time.Now()

	ctx, cancel := context.WithTimeout(s.baseCtx, s.opts.ScanTimeout)
	defer cancel()

	totals, err := s.execute(ctx, j, reg)
	status := string(model.ScanSucceeded)
	if err != nil {
		status = string(model.ScanFailed)
		code, retryAt := failureCode(err)
		s.markFailed(j.scanID, code, retryAt)
		log.Error("scan failed", "error", code, "detail", err.Error(), "duration_ms", time.Since(start).Milliseconds())
	} else {
		log.Info("scan succeeded", "duration_ms", time.Since(start).Milliseconds(),
			"checks_assessed", totals.Assessed, "checks_unknown", totals.Unknown, "score", totals.Score)
	}
	if s.opts.Metrics != nil {
		s.opts.Metrics.ScanFinished(string(reg.conn.Mode), status, time.Since(start))
	}
}

// execute is separated from process so a panic anywhere inside a scan is
// recovered here, turned into an error, and the worker keeps running.
func (s *Service) execute(ctx context.Context, j job, reg registration) (totals Totals, err error) {
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("scan panicked", "scan_id", j.scanID, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = &panicError{value: p}
		}
	}()
	if err := s.store.MarkRunning(ctx, j.scanID); err != nil {
		return Totals{}, err
	}
	snap, err := reg.connector.Collect(ctx)
	if err != nil {
		return Totals{}, err
	}
	totals, err = s.publish(ctx, j.scanID, reg, snap)
	if err != nil {
		return Totals{}, &publishError{err: err}
	}
	return totals, nil
}

type panicError struct{ value any }

func (e *panicError) Error() string { return fmt.Sprintf("panic: %v", e.value) }

type publishError struct{ err error }

func (e *publishError) Error() string { return "publish: " + e.err.Error() }
func (e *publishError) Unwrap() error { return e.err }

// failureCode maps an error to the short code stored in scans.error.
func failureCode(err error) (string, *time.Time) {
	var rl *connector.RateLimitError
	var pe *panicError
	var pub *publishError
	switch {
	case errors.As(err, &rl):
		t := rl.RetryAt.UTC()
		return FailRateLimited, &t
	case errors.Is(err, connector.ErrUnauthorized):
		return FailUnauthorized, nil
	case errors.As(err, &pe):
		return FailPanic, nil
	case errors.Is(err, context.Canceled):
		return FailInterrupted, nil
	case errors.Is(err, context.DeadlineExceeded):
		return FailTimeout, nil
	case errors.As(err, &pub):
		return FailPublish, nil
	default:
		return FailCollection, nil
	}
}

// markFailed records a failure using a fresh context: the scan's own context
// may already be cancelled, but we still want the row updated.
func (s *Service) markFailed(scanID, code string, retryAt *time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.MarkFailed(ctx, scanID, code, retryAt); err != nil {
		s.log.Error("could not mark scan failed", "scan_id", scanID, "error", err)
	}
}

// publish writes collections, assets, check results and the scan's final
// status/score/coverage in ONE transaction. Either all of it becomes visible
// at once, or (on any error) none of it does and the previous succeeded scan
// stays current.
func (s *Service) publish(ctx context.Context, scanID string, reg registration, snap connector.Snapshot) (Totals, error) {
	var totals Totals
	var counts map[model.Result]int
	err := s.store.WithTx(ctx, func(tx *store.Tx) error {
		var prevScan *model.Scan
		var prevAssets []model.Asset
		prevResults := map[string]model.CheckResult{}
		if p, err := tx.LatestSucceeded(ctx, reg.conn.ID); err == nil {
			prevScan = &p
			if prevAssets, err = tx.Assets(ctx, p.ID); err != nil {
				return err
			}
			if prevResults, err = tx.Results(ctx, p.ID); err != nil {
				return err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		cols := completeCollections(snap.Collections)
		assets := buildAssets(scanID, snap.Assets, prevAssets, cols)
		results := rules.EvaluateAll(s.rules, reg.conn.Provider, reg.conn.ID, scanID, assets)
		// Tell carried-forward results WHY their asset wasn't seen.
		carriedKind := map[string]model.AssetKind{} // asset ID -> kind
		for _, a := range assets {
			if a.CarriedForward {
				carriedKind[a.ID] = a.Kind
			}
		}
		for i := range results {
			if kind, ok := carriedKind[results[i].AssetID]; ok {
				results[i].Evidence.CollectionStatus = string(cols[kind].Status)
			}
		}
		applyHistory(results, prevResults, scanID)
		totals = computeTotals(results)

		final := model.Scan{ID: scanID, Score: totals.Score, ChecksTotal: totals.Total,
			ChecksAssessed: totals.Assessed, ChecksUnknown: totals.Unknown, Status: model.ScanSucceeded}
		for _, c := range cols {
			if c.Status != model.CollectionComplete {
				final.CollectionIncomplete = true
			}
		}
		final.Comparable = isComparable(results, prevResults, prevScan, final)

		for _, k := range model.AllKinds {
			if err := tx.InsertCollection(ctx, scanID, cols[k]); err != nil {
				return err
			}
		}
		for _, a := range assets {
			if err := tx.InsertAsset(ctx, a); err != nil {
				return err
			}
		}
		counts = map[model.Result]int{}
		for _, r := range results {
			counts[r.Result]++
			if err := tx.InsertResult(ctx, r); err != nil {
				return err
			}
		}
		if err := tx.FinishScan(ctx, final); err != nil {
			return err
		}
		if s.beforeCommit != nil {
			return s.beforeCommit()
		}
		return nil
	})
	if err == nil && s.opts.Metrics != nil {
		s.opts.Metrics.CheckResults(reg.conn.ID, counts)
	}
	return totals, err
}
