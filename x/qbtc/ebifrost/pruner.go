package ebifrost

import "time"

// startPruneTimer starts a timer to periodically prune expired items from the caches
func (eb *EnshrinedBifrost) startPruneTimer() {
	interval := eb.cfg.CacheItemTTL / 10 // Check every 1/10th of the TTL
	if interval < time.Second {
		interval = time.Second // Minimum interval of 1 second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				eb.logger.Debug("Pruning expired cache items", "ttl", eb.cfg.CacheItemTTL.String())

			case <-eb.stopCh:
				return
			}
		}
	}()
}
