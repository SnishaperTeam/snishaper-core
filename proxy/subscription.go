package proxy

import (
	"fmt"
	"path/filepath"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// subscriptionStorePath resolves the on-disk location of the subscription store.
// It lives next to the rules file so a portable install keeps everything together.
func (rm *RuleManager) subscriptionStorePath() string {
	return filepath.Join(filepath.Dir(rm.rulesPath), "subscriptions.json")
}

// SetSubscriptionStore attaches the subscription store and applies the active
// subscription's rules.
func (rm *RuleManager) SetSubscriptionStore(store *subscription.Store) {
	rm.mu.Lock()
	rm.subscriptions = store
	rm.mu.Unlock()
	rm.ApplyActiveSubscriptionRules()
}

// GetSubscriptionStore returns the attached store, if any.
func (rm *RuleManager) GetSubscriptionStore() *subscription.Store {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.subscriptions
}

// ApplyActiveSubscriptionRules rebuilds the runtime rule set from the active
// subscription. The built-in default subscription restores the shipped rules.
// Pooled WireGuard tunnels are dropped here: a stale tunnel would keep its
// device, IP stack and UDP socket alive after the node set changed.
func (rm *RuleManager) ApplyActiveSubscriptionRules() {
	store := rm.GetSubscriptionStore()
	if store == nil {
		return
	}

	subscription.ReleaseWireguardDialers()

	active := store.ActiveEntry()
	if active == nil {
		return
	}

	if active.Builtin {
		rm.mu.Lock()
		rm.siteGroups = rm.builtinSiteGroups
		rm.mu.Unlock()
		rm.buildRules()
		rm.logf("[Subscription] active subscription is default rules, restored %d site groups", len(rm.builtinSiteGroups))
		return
	}

	converted := make([]SiteGroup, 0, len(active.SiteGroups))
	for _, sg := range active.SiteGroups {
		converted = append(converted, SiteGroup{
			ID:         sg.ID,
			Name:       sg.Name,
			Mode:       sg.Mode,
			DNSMode:    sg.DNSMode,
			SniFake:    sg.SniFake,
			Domains:    sg.Domains,
			ECHEnabled: false,
			UseCFPool:  false,
			Website:    sg.Website,
			Enabled:    true,
		})
	}

	rm.mu.Lock()
	rm.siteGroups = converted
	rm.mu.Unlock()
	rm.buildRules()
	rm.logf("[Subscription] applied %d site groups from subscription %q", len(converted), active.Name)
}

// activeSubscriptionID returns the active subscription id, or "" when no store
// is attached. It reads rm.subscriptions directly because its only caller
// (saveRulesConfig) already holds the RuleManager write lock; going through
// GetSubscriptionStore would RLock the same mutex and deadlock.
func (rm *RuleManager) activeSubscriptionID() string {
	if rm.subscriptions == nil {
		return ""
	}
	return rm.subscriptions.ActiveID()
}

// snapshotBuiltinSiteGroups stores the shipped rules so the default
// subscription can restore them at any time.
func (rm *RuleManager) snapshotBuiltinSiteGroups() {
	rm.mu.Lock()
	rm.builtinSiteGroups = make([]SiteGroup, len(rm.siteGroups))
	copy(rm.builtinSiteGroups, rm.siteGroups)
	rm.mu.Unlock()
}

// ListSubscriptions returns every known subscription.
func (rm *RuleManager) ListSubscriptions() []*subscription.Entry {
	store := rm.GetSubscriptionStore()
	if store == nil {
		return nil
	}
	return store.List()
}

// ActivateSubscription switches the active subscription and reloads rules.
func (rm *RuleManager) ActivateSubscription(id string) error {
	store := rm.GetSubscriptionStore()
	if store == nil {
		return fmt.Errorf("subscription store is not initialized")
	}
	if err := store.SetActive(id); err != nil {
		return err
	}
	rm.ApplyActiveSubscriptionRules()
	return nil
}

// AddSubscription registers a new subscription from a Clash URL.
func (rm *RuleManager) AddSubscription(name, url string) (*subscription.Entry, error) {
	store := rm.GetSubscriptionStore()
	if store == nil {
		return nil, fmt.Errorf("subscription store is not initialized")
	}
	return store.Add(name, url)
}

// UpdateSubscription re-downloads a subscription and refreshes rules if active.
func (rm *RuleManager) UpdateSubscription(id string) (*subscription.Entry, error) {
	store := rm.GetSubscriptionStore()
	if store == nil {
		return nil, fmt.Errorf("subscription store is not initialized")
	}
	entry, err := store.Update(id)
	if err != nil {
		return entry, err
	}
	if store.ActiveID() == id {
		rm.ApplyActiveSubscriptionRules()
	}
	return entry, nil
}

// DeleteSubscription removes a subscription, restoring defaults when needed.
func (rm *RuleManager) DeleteSubscription(id string) error {
	store := rm.GetSubscriptionStore()
	if store == nil {
		return fmt.Errorf("subscription store is not initialized")
	}
	wasActive := store.ActiveID() == id
	if err := store.Delete(id); err != nil {
		return err
	}
	if wasActive {
		rm.ApplyActiveSubscriptionRules()
	}
	return nil
}

// SelectSubscriptionNode records the chosen node for a subscription group.
func (rm *RuleManager) SelectSubscriptionNode(subscriptionID, group, node string) error {
	store := rm.GetSubscriptionStore()
	if store == nil {
		return fmt.Errorf("subscription store is not initialized")
	}
	return store.SelectNode(subscriptionID, group, node)
}
