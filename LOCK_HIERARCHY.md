# Lock Hierarchy Documentation (RULES.md §4.2)

## Global Lock Ordering

Locks MUST be acquired in the following order (lowest to highest priority) to prevent deadlocks:

### Priority Level 1 (Lowest) - Application State
- `globalRateLimiter.mu` (RWMutex) - Rate limiting buckets map
- `challengeRateLimiters mutex` - PoW challenge rate limiters map
- `issuedChallenges mutex` - PoW issued challenges map
- `realtime.Hub.mu` (`utils.SafeMutex`, 5 s timeout) - SSE subscriber map; leaf lock, channel sends under it never block
- `pendingStore.mu` - Pending registration map (leaf lock)

### Priority Level 2 - Per-Resource Locks
- `TokenBucket.mu` - Individual rate limit bucket
- `RateLimiter per-bucket locks` - Individual PoW rate limiter

### Priority Level 3 (Highest) - Database/Critical Resources
- Database transaction locks (implicit via GORM)
- `users` row locks (`SELECT … FOR UPDATE`, `ChatRepository.LockUsers`): always taken in ascending
  `uuid` order inside one transaction (redeem, burn, index prune) — a global order rules out deadlocks
- `conversations` row lock (`ChatRepository.NextSeq`, `UPDATE … RETURNING`): serialises senders of
  one conversation until the transaction ends; never held while acquiring a `users` row lock
- Master key initialization lock (`masterKeyOnce`)

## Acquisition Rules

1. **Always acquire locks from lowest to highest priority**
2. **Never acquire a lower-priority lock while holding a higher-priority lock**
3. **Release locks in LIFO order (stack discipline)**
4. **New in-process locks use `utils.SafeMutex` (timeout-bounded); database locks are bounded by
   their transaction**

## Examples

### CORRECT - Acquire low-priority first
```go
// Acquire global map lock first (Priority 1)
rl.mu.RLock()
bucket, exists := rl.buckets[ip]
rl.mu.RUnlock()

// Then acquire bucket lock (Priority 2)
if exists {
    bucket.mu.Lock()
    defer bucket.mu.Unlock()
    // ... use bucket
}
```

### INCORRECT - Would cause deadlock
```go
// Holding bucket lock (Priority 2)
bucket.mu.Lock()

// Then trying to acquire global lock (Priority 1) - DEADLOCK RISK!
rl.mu.Lock()
```

## Lock Timeout Policy

- All locks MUST use `SafeMutex` or `SafeRWMutex` with timeout
- Default timeout: 5 seconds
- On timeout: return error, log warning, trigger monitoring alert

## Audit Process

- Code reviews MUST verify lock ordering
- Use `go test -race` to detect race conditions
- Document any new locks in this file with assigned priority level

---

**Last Updated**: 2026-10-24
**Next Review**: Every sprint or when adding new locks
