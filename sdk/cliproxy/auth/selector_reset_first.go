package auth

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// ResetFirstSelector prefers the available credential whose weekly quota window
// resets soonest, so quota that is about to expire is used before quota that
// still has days left.
//
// Reset times come from the passive quota snapshot (Quota.Signals) that executors
// record from upstream response headers. A credential without a usable future
// reset time is picked first: one request records its snapshot, after which it
// takes its place in the reset order. Ties keep a stable order by credential ID.
type ResetFirstSelector struct {
	// now is overridable in tests.
	now func() time.Time
}

// weeklyResetSignalKeys lists, per provider, the snapshot keys that carry the
// weekly window reset time, in priority order.
var weeklyResetSignalKeys = map[string][]string{
	"claude": {
		"Anthropic-Ratelimit-Unified-7d-Reset",
		"Anthropic-Ratelimit-Unified-7d_oi-Reset",
	},
	"codex": {
		"X-Codex-Secondary-Reset-At",
		"X-Codex-Primary-Reset-At",
	},
}

// weeklyResetAfterSignalKeys lists relative reset signals (seconds after the
// observation time) used when no absolute reset time is present.
var weeklyResetAfterSignalKeys = map[string][]string{
	"codex": {
		"X-Codex-Secondary-Reset-After-Seconds",
		"X-Codex-Primary-Reset-After-Seconds",
	},
}

// Pick selects the available credential with the earliest known weekly reset.
func (s *ResetFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	if s != nil && s.now != nil {
		now = s.now()
	}
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	if len(available) == 1 {
		return available[0], nil
	}

	ordered := make([]*Auth, len(available))
	copy(ordered, available)
	resets := make(map[string]time.Time, len(ordered))
	for _, auth := range ordered {
		if reset, ok := weeklyResetAt(auth, now); ok {
			resets[auth.ID] = reset
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, okI := resets[ordered[i].ID]
		rj, okJ := resets[ordered[j].ID]
		if okI != okJ {
			// Unknown reset first, so the credential gets observed.
			return !okI
		}
		if okI && !ri.Equal(rj) {
			return ri.Before(rj)
		}
		return ordered[i].ID < ordered[j].ID
	})
	return ordered[0], nil
}

// weeklyResetAt returns the future weekly reset time recorded for the credential.
func weeklyResetAt(auth *Auth, now time.Time) (time.Time, bool) {
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return time.Time{}, false
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	signals := auth.Quota.Signals
	for _, key := range weeklyResetSignalKeys[provider] {
		if reset, ok := parseResetSignal(signals[key]); ok && reset.After(now) {
			return reset, true
		}
	}
	if auth.Quota.ObservedAt.IsZero() {
		return time.Time{}, false
	}
	for _, key := range weeklyResetAfterSignalKeys[provider] {
		seconds, errParse := strconv.ParseFloat(strings.TrimSpace(signals[key]), 64)
		if errParse != nil || seconds <= 0 {
			continue
		}
		reset := auth.Quota.ObservedAt.Add(time.Duration(seconds * float64(time.Second)))
		if reset.After(now) {
			return reset, true
		}
	}
	return time.Time{}, false
}

// parseResetSignal accepts unix seconds or an RFC 3339 timestamp.
func parseResetSignal(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if seconds, errParse := strconv.ParseFloat(raw, 64); errParse == nil && seconds > 0 {
		whole := int64(seconds)
		return time.Unix(whole, int64((seconds-float64(whole))*1e9)), true
	}
	if parsed, errParse := time.Parse(time.RFC3339, raw); errParse == nil {
		return parsed, true
	}
	return time.Time{}, false
}
