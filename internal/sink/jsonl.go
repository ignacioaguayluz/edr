// Package sink contains output adapters for events and alerts.
package sink

import (
	"encoding/json"
	"io"
	"sync"
)

// Record is one line of agent output. Type is "event" or "alert".
type Record struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// JSONL writes records as JSON Lines. It is safe for concurrent use.
type JSONL struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONL returns a JSON Lines sink writing to w.
func NewJSONL(w io.Writer) *JSONL {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONL{enc: enc}
}

// Write encodes one record followed by a newline.
func (s *JSONL) Write(recordType string, data any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(Record{Type: recordType, Data: data})
}
