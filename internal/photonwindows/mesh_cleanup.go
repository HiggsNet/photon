package photonwindows

import "errors"

// retire owns slow platform cleanup after the event owner has detached its
// live state. Cleanup never mutates peers, plans, or packet authorization.
// Device acquire/Close still serialize through meshDevice's existing mutex.
func (m *meshRuntime) retire(cleanup func() error) {
	m.cleanupWG.Go(func() {
		if err := cleanup(); err != nil {
			m.cleanupMu.Lock()
			m.cleanupErr = errors.Join(m.cleanupErr, err)
			m.cleanupMu.Unlock()
			m.logger.Warn("leaf_cleanup_failed", "error", err)
		}
	})
}

func (m *meshRuntime) retireDevice(device ownedPacketDevice) {
	m.retire(device.Close)
}
