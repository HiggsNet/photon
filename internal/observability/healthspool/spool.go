package healthspool

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

const SamplesFile = "samples.jsonl"

var ErrNotConfigured = errors.New("health local spool not configured")

type Sample struct {
	UnixMs        int64                     `json:"unix_ms"`
	ProbeID       string                    `json:"probe_id,omitempty"`
	InstanceID    string                    `json:"instance_id"`
	ProbeRole     string                    `json:"probe_role,omitempty"`
	InterfaceName string                    `json:"interface_name,omitempty"`
	State         string                    `json:"state"`
	ProbeType     string                    `json:"probe_type,omitempty"`
	RTTMs         int64                     `json:"rtt_ms,omitempty"`
	LossRatioPct  int                       `json:"loss_ratio_pct"`
	JitterMs      int64                     `json:"jitter_ms,omitempty"`
	Sent          int                       `json:"sent,omitempty"`
	Received      int                       `json:"received,omitempty"`
	Lost          int                       `json:"lost,omitempty"`
	LargeProbe    *inspect.LargeProbeSample `json:"large_probe,omitempty"`
}

type SeriesPoint struct {
	UnixMs int64   `json:"unix_ms"`
	Value  float64 `json:"value"`
}

type SeriesLine struct {
	ProbeID   string        `json:"probe_id,omitempty"`
	ProbeRole string        `json:"probe_role,omitempty"`
	Points    []SeriesPoint `json:"points"`
}

type SeriesResult struct {
	Metric    string        `json:"metric"`
	Unit      string        `json:"unit"`
	Range     string        `json:"range"`
	Step      string        `json:"step"`
	Window    string        `json:"window"`
	Points    []SeriesPoint `json:"points"`
	Lines     []SeriesLine  `json:"lines,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
}

type SeriesQuery struct {
	Metric    string
	ProbeRole string
	Range     time.Duration
	Step      time.Duration
	Now       time.Time
}

type Config struct {
	Enabled bool
	Path    string
	MaxAge  time.Duration
}

func (c Config) Configured() bool {
	return c.Enabled && strings.TrimSpace(c.Path) != ""
}

func (c Config) File() string {
	dir := strings.TrimSpace(c.Path)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, SamplesFile)
}

func (c Config) Datasource() map[string]any {
	if !c.Configured() {
		return map[string]any{
			"configured": false,
			"type":       "none",
		}
	}
	return map[string]any{
		"configured":    true,
		"type":          "local_spool",
		"local":         true,
		"series_window": c.MaxAge.String(),
	}
}

type Store struct {
	config Config
	mu     sync.Mutex
}

func New(config Config) *Store {
	return &Store{config: config}
}

func (s *Store) Config() Config {
	if s == nil {
		return Config{}
	}
	return s.config
}

func (s *Store) Append(now time.Time, samples []Sample) error {
	if s == nil || !s.config.Configured() {
		return ErrNotConfigured
	}
	path := s.config.File()
	if path == "" {
		return ErrNotConfigured
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, sample := range samples {
		if sample.InstanceID == "" {
			continue
		}
		sample.UnixMs = now.UnixMilli()
		if err := enc.Encode(sample); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return pruneHealthSpoolFile(path, now.Add(-s.config.MaxAge))
}

func (s *Store) Query(linkID string, q SeriesQuery) (SeriesResult, error) {
	if s == nil || !s.config.Configured() {
		return SeriesResult{}, ErrNotConfigured
	}
	metric, unit, err := normalizeHealthSeriesMetric(q.Metric)
	if err != nil {
		return SeriesResult{}, err
	}
	if linkID == "" {
		return SeriesResult{}, fmt.Errorf("link id is required")
	}
	if q.Now.IsZero() {
		q.Now = time.Now()
	}
	if q.Range <= 0 {
		q.Range = time.Hour
	}
	if s.config.MaxAge > 0 && q.Range > s.config.MaxAge {
		q.Range = s.config.MaxAge
	}
	if q.Step <= 0 {
		q.Step = 30 * time.Second
	}
	if q.Step < time.Second {
		q.Step = time.Second
	}
	if q.Step > q.Range {
		q.Step = q.Range
	}
	since := q.Now.Add(-q.Range)
	path := s.config.File()
	s.mu.Lock()
	samples, err := readHealthSpoolSamples(path, since, q.Now, linkID)
	s.mu.Unlock()
	if err != nil {
		return SeriesResult{}, err
	}
	if q.ProbeRole != "" {
		samples = filterHealthSamplesByProbeRole(samples, q.ProbeRole)
	}
	points := bucketHealthSamples(samples, metric, since, q.Step)
	lines := bucketHealthSamplesByLine(samples, metric, since, q.Step)
	return SeriesResult{
		Metric: metric,
		Unit:   unit,
		Range:  q.Range.String(),
		Step:   q.Step.String(),
		Window: s.config.MaxAge.String(),
		Points: points,
		Lines:  lines,
	}, nil
}

func normalizeHealthSeriesMetric(metric string) (string, string, error) {
	switch strings.TrimSpace(metric) {
	case "", "rtt":
		return "rtt", "ms", nil
	case "loss":
		return "loss", "percent", nil
	case "large_loss":
		return "large_loss", "percent", nil
	case "large_rtt":
		return "large_rtt", "ms", nil
	case "jitter":
		return "jitter", "ms", nil
	case "state":
		return "state", "code", nil
	case "babel_rtt", "babel_metric":
		return "", "", fmt.Errorf("metric %q is not available in the local health spool yet", metric)
	default:
		return "", "", fmt.Errorf("unsupported health series metric %q", metric)
	}
}

func filterHealthSamplesByProbeRole(samples []Sample, role string) []Sample {
	out := make([]Sample, 0, len(samples))
	for _, sample := range samples {
		if sample.ProbeRole == role {
			out = append(out, sample)
		}
	}
	return out
}

func readHealthSpoolSamples(path string, since, until time.Time, linkID string) ([]Sample, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Sample
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var sample Sample
		if err := json.Unmarshal(scanner.Bytes(), &sample); err != nil {
			continue
		}
		if sample.InstanceID != linkID {
			continue
		}
		ts := time.UnixMilli(sample.UnixMs)
		if ts.Before(since) || ts.After(until) {
			continue
		}
		out = append(out, sample)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UnixMs < out[j].UnixMs })
	return out, nil
}

func bucketHealthSamplesByLine(samples []Sample, metric string, start time.Time, step time.Duration) []SeriesLine {
	if len(samples) == 0 {
		return []SeriesLine{}
	}
	byLine := map[string][]Sample{}
	meta := map[string]Sample{}
	for _, sample := range samples {
		key := sample.ProbeID
		if key == "" {
			key = probeID(sample.InstanceID, sample.ProbeRole)
		}
		if key == "" {
			key = sample.InstanceID
		}
		byLine[key] = append(byLine[key], sample)
		if _, ok := meta[key]; !ok {
			meta[key] = sample
		}
	}
	keys := make([]string, 0, len(byLine))
	for key := range byLine {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]SeriesLine, 0, len(keys))
	for _, key := range keys {
		sample := meta[key]
		lines = append(lines, SeriesLine{
			ProbeID:   key,
			ProbeRole: sample.ProbeRole,
			Points:    bucketHealthSamples(byLine[key], metric, start, step),
		})
	}
	return lines
}

func probeID(instanceID, role string) string {
	if role == "" || role == "active" {
		return instanceID
	}
	return instanceID + "#" + role
}

func bucketHealthSamples(samples []Sample, metric string, start time.Time, step time.Duration) []SeriesPoint {
	if len(samples) == 0 {
		return []SeriesPoint{}
	}
	type aggregate struct {
		ts    int64
		sum   float64
		count int
	}
	buckets := map[int64]*aggregate{}
	seenLarge := map[string]map[int64]bool{}
	startMs := start.UnixMilli()
	stepMs := step.Milliseconds()
	if stepMs <= 0 {
		stepMs = 1000
	}
	for _, sample := range samples {
		// Spool rows are snapshots flushed by either stream. Only plot an
		// actual large probe once, at its measurement time, rather than making
		// every small probe look like another large sample.
		if metric == "large_loss" || metric == "large_rtt" {
			if sample.LargeProbe == nil || sample.LargeProbe.LastProbeUnix <= 0 {
				continue
			}
			at := sample.LargeProbe.LastProbeUnix * 1000
			if sample.LargeProbe.LastProbeUnixMs > 0 {
				at = sample.LargeProbe.LastProbeUnixMs
			}
			if at < startMs || at > sample.UnixMs {
				continue
			}
			id := sample.ProbeID
			if id == "" {
				id = probeID(sample.InstanceID, sample.ProbeRole)
			}
			if seenLarge[id] == nil {
				seenLarge[id] = map[int64]bool{}
			}
			if seenLarge[id][at] {
				continue
			}
			seenLarge[id][at] = true
			sample.UnixMs = at
		}
		value, ok := healthSampleValue(sample, metric)
		if !ok {
			continue
		}
		bucket := startMs + ((sample.UnixMs-startMs)/stepMs)*stepMs
		agg := buckets[bucket]
		if agg == nil {
			agg = &aggregate{ts: bucket}
			buckets[bucket] = agg
		}
		agg.sum += value
		agg.count++
	}
	keys := make([]int64, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	points := make([]SeriesPoint, 0, len(keys))
	for _, key := range keys {
		agg := buckets[key]
		if agg.count == 0 {
			continue
		}
		points = append(points, SeriesPoint{UnixMs: agg.ts, Value: agg.sum / float64(agg.count)})
	}
	return points
}

func healthSampleValue(sample Sample, metric string) (float64, bool) {
	switch metric {
	case "rtt":
		return float64(sample.RTTMs), sample.RTTMs > 0
	case "loss":
		return float64(sample.LossRatioPct), true
	case "large_loss":
		if sample.LargeProbe != nil && sample.LargeProbe.Sent > 0 {
			return sample.LargeProbe.LossRatioPct, true
		}
	case "large_rtt":
		if sample.LargeProbe != nil && sample.LargeProbe.LastRTTMs > 0 {
			return float64(sample.LargeProbe.LastRTTMs), true
		}
	case "jitter":
		return float64(sample.JitterMs), sample.JitterMs > 0
	case "state":
		return healthStateCode(sample.State), true
	default:
		return 0, false
	}
	return 0, false
}

func healthStateCode(state string) float64 {
	switch state {
	case "healthy":
		return 0
	case "degraded":
		return 1
	case "down":
		return 2
	case "unknown":
		return 3
	case "probe_error":
		return 4
	case "suppressed":
		return 5
	default:
		return 3
	}
}

func pruneHealthSpoolFile(path string, cutoff time.Time) error {
	if cutoff.IsZero() {
		return nil
	}
	samples, err := readAllHealthSpoolSamples(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, sample := range samples {
		if time.UnixMilli(sample.UnixMs).Before(cutoff) {
			continue
		}
		if err := enc.Encode(sample); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readAllHealthSpoolSamples(path string) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Sample
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var sample Sample
		if err := json.Unmarshal(scanner.Bytes(), &sample); err != nil {
			continue
		}
		out = append(out, sample)
	}
	return out, scanner.Err()
}
