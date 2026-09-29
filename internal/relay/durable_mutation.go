package relay

import "time"

func (s *Store) commitDurableLocked(before durableState) error {
	if err := s.persistLocked(); err != nil {
		_ = s.restoreDurableStateLocked(before)
		return err
	}
	return nil
}

func (s *Store) pruneQueuedCommandsForSessionLocked(deviceID, agentSessionID string, now time.Time) []string {
	queue := s.queues[deviceID]
	if len(queue) == 0 {
		return nil
	}
	kept := queue[:0]
	var removed []string
	for _, item := range queue {
		envelope, err := decodeCommandEnvelope(item.command.Payload)
		if err != nil || envelope.SessionID != agentSessionID || envelope.ExpiresAt <= now.Unix() {
			removed = append(removed, item.command.RequestID)
			delete(s.requests, item.command.RequestID)
			continue
		}
		item.leasedTill = time.Time{}
		kept = append(kept, item)
	}
	if len(kept) == 0 {
		delete(s.queues, deviceID)
	} else {
		s.queues[deviceID] = kept
	}
	return removed
}

func (s *Store) removeDurableDeviceLocked(deviceID string) []string {
	delete(s.pairings, deviceID)
	delete(s.queues, deviceID)
	s.pairingGeneration[deviceID]++

	var removed []string
	for requestID, owner := range s.requests {
		if owner != deviceID {
			continue
		}
		removed = append(removed, requestID)
		delete(s.requests, requestID)
		delete(s.results, requestID)
	}
	if len(removed) > 0 {
		kept := s.resultOrder[:0]
		for _, requestID := range s.resultOrder {
			if owner, ok := s.requests[requestID]; ok && owner != deviceID {
				kept = append(kept, requestID)
			}
		}
		s.resultOrder = kept
	}
	for key := range s.controllerNonces {
		if key.deviceID == deviceID {
			delete(s.controllerNonces, key)
		}
	}
	for key := range s.deviceNonces {
		if key.deviceID == deviceID {
			delete(s.deviceNonces, key)
		}
	}
	for key := range s.commandNonces {
		if key.deviceID == deviceID {
			delete(s.commandNonces, key)
		}
	}
	return removed
}
