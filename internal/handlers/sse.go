package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HandleSSE streams real-time updates to the client via Server-Sent Events.
func (h *Handler) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.SSEBroker.Subscribe()
	defer h.SSEBroker.Unsubscribe(ch)

	// Send current cached stats immediately so the client doesn't wait for next tick
	h.ProxmoxCache.Mutex.RLock()
	initial := h.ProxmoxCache.Stats
	h.ProxmoxCache.Mutex.RUnlock()
	if data, err := json.Marshal(initial); err == nil {
		fmt.Fprintf(w, "event: proxmox_stats\ndata: %s\n\n", data)
		flusher.Flush()
	}

	for {
		select {
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: proxmox_stats\ndata: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
