package zcode

import (
	"errors"
	"testing"
	"time"
)

func TestLimiterHoldsPermitThroughStreamAndReleaseIsIdempotent(t *testing.T) {
	l := NewLimiter()
	now := time.Unix(100, 0)
	l.now = func() time.Time { return now }
	release, err := l.Acquire("a", 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if _, err = l.Acquire("a", 1, time.Second); err == nil {
		t.Fatal("active stream permit expired")
	}
	other, err := l.Acquire("b", 1, time.Second)
	if err != nil {
		t.Fatal("accounts share budget", err)
	}
	other()
	release()
	release()
	release, err = l.Acquire("a", 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	release()
	_, err = l.Acquire("a", 1, time.Second)
	var busy *BusyError
	if !errors.As(err, &busy) || busy.After != time.Second {
		t.Fatalf("missing start-rate limit: %v", err)
	}
	now = now.Add(time.Second)
	release, err = l.Acquire("a", 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
