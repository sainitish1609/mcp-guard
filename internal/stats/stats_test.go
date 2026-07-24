package stats

import (
	"strings"
	"testing"
)

func TestSummaryReportsCountsAndCost(t *testing.T) {
	s := New()
	if !s.Empty() {
		t.Fatal("fresh stats should be empty")
	}
	s.AddRedaction("aws-access-key", 2)
	s.AddRedaction("high-entropy", 1)
	s.WritesBlocked.Add(1)
	s.InjectionsFound.Add(3)
	s.AddSaved(1000, 4000)

	if s.Empty() {
		t.Fatal("stats should no longer be empty")
	}
	out := s.Summary(0.003)
	for _, want := range []string{
		"secrets redacted       3",
		"aws-access-key",
		"writes blocked         1",
		"injections neutralized 3",
		"tokens saved           1000",
		"est. cost saved",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestSummaryOmitsDollarWhenNoPrice(t *testing.T) {
	s := New()
	s.AddSaved(500, 100)
	if strings.Contains(s.Summary(0), "cost saved") {
		t.Fatal("cost line should be omitted when price is 0")
	}
}
