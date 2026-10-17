package gossip

import (
	"errors"
	"math/bits"
	"sync"
	"time"
)

var ErrQuotaExceeded = errors.New("gossip peer quota exceeded")

type QuotaConfig struct {
	ByteRate    int64
	ByteBurst   int64
	ObjectRate  int64
	ObjectBurst int64
	PeerTTL     time.Duration
}

type QuotaExceededError struct {
	Direction          string
	MessageType        MessageType
	PeerID             string
	RequestedBytes     int64
	RequestedObjects   int64
	AvailableBytes     int64
	AvailableObjects   int64
	ByteRate           int64
	ByteBurst          int64
	ObjectRate         int64
	ObjectBurst        int64
	LastRefillUnixNano int64
}

func (e *QuotaExceededError) Error() string {
	return ErrQuotaExceeded.Error()
}

func (e *QuotaExceededError) Unwrap() error {
	return ErrQuotaExceeded
}

type PeerQuotas struct {
	config    QuotaConfig
	mu        sync.Mutex
	peers     map[string]*quotaBucket
	nextPrune time.Time
}

type quotaBucket struct {
	bytes                          int64
	objects                        int64
	last                           time.Time
	byteRemainder, objectRemainder int64
}

func NewPeerQuotas(config QuotaConfig) *PeerQuotas {
	if config.ByteRate <= 0 {
		config.ByteRate = 256 << 10
	}
	if config.ByteBurst <= 0 {
		config.ByteBurst = config.ByteRate
	}
	if config.ObjectRate <= 0 {
		config.ObjectRate = 128
	}
	if config.ObjectBurst <= 0 {
		config.ObjectBurst = config.ObjectRate
	}
	if config.PeerTTL <= 0 {
		config.PeerTTL = 10 * time.Minute
	}
	return &PeerQuotas{
		config: config,
		peers:  make(map[string]*quotaBucket),
	}
}

func (pq *PeerQuotas) Allow(peerID string, bytes int64, objects int64, now time.Time) error {
	if pq == nil {
		return nil
	}
	if bytes < 0 || objects < 0 {
		return ErrQuotaExceeded
	}
	pq.mu.Lock()
	defer pq.mu.Unlock()
	pq.pruneExpired(now)
	bucket := pq.peers[peerID]
	if bucket == nil {
		bucket = &quotaBucket{
			bytes:   pq.config.ByteBurst,
			objects: pq.config.ObjectBurst,
			last:    now,
		}
		pq.peers[peerID] = bucket
	}
	pq.refill(bucket, now)
	if bytes > bucket.bytes || objects > bucket.objects {
		return &QuotaExceededError{
			PeerID:             peerID,
			RequestedBytes:     bytes,
			RequestedObjects:   objects,
			AvailableBytes:     bucket.bytes,
			AvailableObjects:   bucket.objects,
			ByteRate:           pq.config.ByteRate,
			ByteBurst:          pq.config.ByteBurst,
			ObjectRate:         pq.config.ObjectRate,
			ObjectBurst:        pq.config.ObjectBurst,
			LastRefillUnixNano: bucket.last.UnixNano(),
		}
	}
	bucket.bytes -= bytes
	bucket.objects -= objects
	return nil
}

func (pq *PeerQuotas) pruneExpired(now time.Time) {
	if pq == nil || pq.config.PeerTTL <= 0 || now.Before(pq.nextPrune) {
		return
	}
	pruneInterval := pq.config.PeerTTL / 2
	if pruneInterval <= 0 {
		pruneInterval = time.Second
	} else if pq.config.PeerTTL >= 2*time.Minute && pruneInterval < time.Minute {
		pruneInterval = time.Minute
	}
	pq.nextPrune = now.Add(pruneInterval)
	cutoff := now.Add(-pq.config.PeerTTL)
	for peerID, bucket := range pq.peers {
		if bucket == nil || bucket.last.Before(cutoff) {
			delete(pq.peers, peerID)
		}
	}
}

func (pq *PeerQuotas) refill(bucket *quotaBucket, now time.Time) {
	if !now.After(bucket.last) {
		return
	}
	elapsed := uint64(now.Sub(bucket.last))
	bucket.bytes, bucket.byteRemainder = refillTokens(bucket.bytes, bucket.byteRemainder, pq.config.ByteRate, pq.config.ByteBurst, elapsed)
	bucket.objects, bucket.objectRemainder = refillTokens(bucket.objects, bucket.objectRemainder, pq.config.ObjectRate, pq.config.ObjectBurst, elapsed)
	bucket.last = now
}

// Keep the fractional token numerator across checks, including rejected and
// zero-cost checks. A full bucket discards excess credit. The wide product
// also handles long idle periods and large configured rates without overflow.
func refillTokens(balance, remainder, rate, burst int64, elapsed uint64) (int64, int64) {
	hi, lo := bits.Mul64(elapsed, uint64(rate))
	lo, carry := bits.Add64(lo, uint64(remainder), 0)
	hi += carry
	if hi >= uint64(time.Second) {
		return burst, 0
	}
	added, fraction := bits.Div64(hi, lo, uint64(time.Second))
	if added >= uint64(burst-balance) {
		return burst, 0
	}
	return balance + int64(added), int64(fraction)
}
