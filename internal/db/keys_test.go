package db

import (
	"errors"
	"testing"
	"time"
)

// TestKeyRoundTrip covers the whole life of a key: created, listed back with
// every field intact, revoked, and refused a second revocation.
func TestKeyRoundTrip(t *testing.T) {
	var s = newTestStore(t, 0)

	var want = Key{
		Label:      "wilson-lab",
		KeyHash:    "abc123",
		CIDRs:      []string{"203.0.113.0/24", "198.51.100.7/32"},
		RatePerSec: 0.5,
		Burst:      10,
		DailyCap:   5000,
		Notes:      "corpus crawl through winter term",
		Created:    time.Now().Truncate(time.Microsecond),
		Expires:    time.Now().Add(90 * 24 * time.Hour).Truncate(time.Microsecond),
	}
	var id, err = s.CreateKey(want)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if id == 0 {
		t.Fatal("CreateKey returned id 0")
	}

	keys, err := s.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	var got = keys[0]
	if got.ID != id || got.Label != want.Label || got.KeyHash != want.KeyHash ||
		got.RatePerSec != want.RatePerSec || got.Burst != want.Burst ||
		got.DailyCap != want.DailyCap || got.Notes != want.Notes {
		t.Errorf("key did not round-trip: got %+v, want %+v", got, want)
	}
	if len(got.CIDRs) != 2 || got.CIDRs[0] != want.CIDRs[0] || got.CIDRs[1] != want.CIDRs[1] {
		t.Errorf("CIDRs = %v, want %v", got.CIDRs, want.CIDRs)
	}
	if !got.Created.Equal(want.Created) || !got.Expires.Equal(want.Expires) {
		t.Errorf("times did not round-trip: got %v/%v, want %v/%v",
			got.Created, got.Expires, want.Created, want.Expires)
	}
	if !got.Revoked.IsZero() {
		t.Errorf("fresh key already revoked at %v", got.Revoked)
	}
	if !got.Active(time.Now()) {
		t.Error("fresh unexpired key is not Active")
	}

	if err = s.RevokeKey(id); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	keys, err = s.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys after revoke: %v", err)
	}
	if keys[0].Revoked.IsZero() {
		t.Error("revoked key has no Revoked time")
	}
	if keys[0].Active(time.Now()) {
		t.Error("revoked key is still Active")
	}

	if err = s.RevokeKey(id); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("second RevokeKey = %v, want ErrNoSuchKey", err)
	}
	if err = s.RevokeKey(9999); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("RevokeKey of unknown id = %v, want ErrNoSuchKey", err)
	}
}

// TestKeyUsage checks that per-key aggregates come out of the raw event log:
// only events naming a key count, split by served vs rate-limited.
func TestKeyUsage(t *testing.T) {
	var s = newTestStore(t, 0)

	var base = time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	s.LogEvent(Event{Timestamp: base, Outcome: OutcomeProxied, Reason: ReasonBypassKey, KeyID: 7})
	s.LogEvent(Event{Timestamp: base.Add(time.Minute), Outcome: OutcomeProxied, Reason: ReasonBypassKey, KeyID: 7})
	s.LogEvent(Event{Timestamp: base.Add(2 * time.Minute), Outcome: OutcomeRateLimited, Reason: ReasonBypassRate, KeyID: 7})
	s.LogEvent(Event{Timestamp: base, Outcome: OutcomeProxied, Reason: ReasonValidToken}) // keyless; must not count

	var deadline = time.Now().Add(2 * time.Second)
	for countEvents(t, s) < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 4 events written before timeout", countEvents(t, s))
		}
		time.Sleep(10 * time.Millisecond)
	}

	var usage, err = s.KeyUsage()
	if err != nil {
		t.Fatalf("KeyUsage: %v", err)
	}
	if len(usage) != 1 {
		t.Fatalf("usage covers %d keys, want 1: %+v", len(usage), usage)
	}
	var u = usage[7]
	if u.Requests != 2 || u.RateLimited != 1 {
		t.Errorf("usage = %d served / %d limited, want 2 / 1", u.Requests, u.RateLimited)
	}
	if !u.LastSeen.Equal(base.Add(2 * time.Minute)) {
		t.Errorf("LastSeen = %v, want %v", u.LastSeen, base.Add(2*time.Minute))
	}
}

// TestKeysUnavailableOnNoop pins the sentinel every key method returns when
// logging is disabled, since the CLI and server both branch on it.
func TestKeysUnavailableOnNoop(t *testing.T) {
	var s = NewNoopStore()
	if _, err := s.CreateKey(Key{}); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("CreateKey = %v, want ErrKeysUnavailable", err)
	}
	if _, err := s.ListKeys(); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("ListKeys = %v, want ErrKeysUnavailable", err)
	}
	if err := s.RevokeKey(1); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("RevokeKey = %v, want ErrKeysUnavailable", err)
	}
	if _, err := s.KeyUsage(); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("KeyUsage = %v, want ErrKeysUnavailable", err)
	}
}
