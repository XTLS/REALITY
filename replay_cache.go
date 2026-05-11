package reality

import (
	"crypto/sha256"
	"sync"
	"time"
)

const (
	realityReplayCacheDefaultTTL = 2 * time.Minute
	realityReplayCacheMaxEntries = 262144
)

var realityReplayCache = struct {
	sync.Mutex
	entries map[[32]byte]time.Time
}{
	entries: make(map[[32]byte]time.Time),
}

func realityReplayCacheTTL(maxTimeDiff time.Duration) time.Duration {
	if maxTimeDiff <= 0 {
		return realityReplayCacheDefaultTTL
	}
	return maxTimeDiff + 30*time.Second
}

func realityReplayCacheKey(authKey []byte, clientHello *clientHelloMsg) [32]byte {
	h := sha256.New()
	h.Write(authKey)
	h.Write(clientHello.original)
	return [32]byte(h.Sum(nil))
}

func realityClientHelloSeenOrStore(key [32]byte, ttl time.Duration, now time.Time) bool {
	expiresAt := now.Add(ttl)

	realityReplayCache.Lock()
	defer realityReplayCache.Unlock()

	if seenUntil, ok := realityReplayCache.entries[key]; ok {
		if seenUntil.After(now) {
			return true
		}
		delete(realityReplayCache.entries, key)
	}

	if len(realityReplayCache.entries) >= realityReplayCacheMaxEntries {
		for cachedKey, cachedUntil := range realityReplayCache.entries {
			if !cachedUntil.After(now) {
				delete(realityReplayCache.entries, cachedKey)
			}
		}
		if len(realityReplayCache.entries) >= realityReplayCacheMaxEntries {
			return true
		}
	}

	realityReplayCache.entries[key] = expiresAt
	return false
}
