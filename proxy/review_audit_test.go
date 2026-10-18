package proxy

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

func TestReviewDomainKeywordMatch(t *testing.T) {
	cache := &sync.Map{}
	if got := domainMatchScore("www.google.com", "*google*", cache); got <= 0 {
		t.Fatalf("keyword rule must match, got %d", got)
	}
	if got := domainMatchScore("example.com", "*google*", cache); got != -1 {
		t.Fatalf("keyword rule must not match unrelated host, got %d", got)
	}
	keyword := domainMatchScore("www.google.com", "*google*", cache)
	if exact := domainMatchScore("www.google.com", "www.google.com", cache); exact <= keyword {
		t.Fatalf("exact match %d must outrank keyword %d", exact, keyword)
	}
	if suffix := domainMatchScore("a.google.com", "google.com", cache); suffix >= keyword {
		t.Fatalf("suffix match %d must not outrank keyword %d", suffix, keyword)
	}
}

func TestReviewSaveRulesConfigUnderLock(t *testing.T) {
	dir := t.TempDir()
	rm := NewRuleManager(filepath.Join(dir, "settings.json"), filepath.Join(dir, "rules.json"))
	if err := rm.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	rm.SetSubscriptionStore(subscription.NewStore(filepath.Join(dir, "subs.json"), nil))

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := rm.AddSiteGroup(SiteGroup{Name: "review", Domains: []string{"example.com"}, Enabled: true}); err != nil {
			t.Errorf("AddSiteGroup: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("AddSiteGroup deadlocked: saveRulesConfig -> activeSubscriptionID -> GetSubscriptionStore takes rm.mu.RLock while the caller holds the write lock")
	}
}
