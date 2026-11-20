// Package detection evaluates telemetry events against declarative rules
// and produces alerts. It has no IO or kernel dependencies besides rule
// loading from the filesystem.
package detection

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"edr/internal/telemetry"
)

// Severity ranks how serious an alert is.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Action is the response a rule requests when it matches.
type Action string

const (
	ActionAlert Action = "alert" // default: report only
	ActionKill  Action = "kill"  // terminate the offending process
)

// Condition tests one event field. Exactly one operator must be set.
type Condition struct {
	Field      string   `yaml:"field"`
	Equals     *string  `yaml:"equals"`
	Contains   *string  `yaml:"contains"`
	StartsWith *string  `yaml:"startswith"`
	EndsWith   *string  `yaml:"endswith"`
	In         []string `yaml:"in"`
}

// Rule is a detection: all conditions must match (AND) an event of Kind.
// An empty Kind matches every kind.
type Rule struct {
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Description string         `yaml:"description"`
	Severity    Severity       `yaml:"severity"`
	Kind        telemetry.Kind `yaml:"kind"`
	Action      Action         `yaml:"action"`
	Match       []Condition    `yaml:"match"`
}

// ResponseOutcome records what the response layer did for an alert.
type ResponseOutcome struct {
	Action Action `json:"action"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Alert is emitted when a rule matches an event.
type Alert struct {
	Time     time.Time        `json:"time"`
	RuleID   string           `json:"rule_id"`
	Title    string           `json:"title"`
	Severity Severity         `json:"severity"`
	Action   Action           `json:"action"`
	Event    telemetry.Event  `json:"event"`
	Response *ResponseOutcome `json:"response,omitempty"`
}

func (c Condition) operatorCount() int {
	n := 0
	for _, set := range []bool{c.Equals != nil, c.Contains != nil, c.StartsWith != nil, c.EndsWith != nil, c.In != nil} {
		if set {
			n++
		}
	}
	return n
}

func (c Condition) matches(ev telemetry.Event) bool {
	v, ok := ev.Field(c.Field)
	if !ok {
		return false
	}
	switch {
	case c.Equals != nil:
		return v == *c.Equals
	case c.Contains != nil:
		return strings.Contains(v, *c.Contains)
	case c.StartsWith != nil:
		return strings.HasPrefix(v, *c.StartsWith)
	case c.EndsWith != nil:
		return strings.HasSuffix(v, *c.EndsWith)
	case c.In != nil:
		return slices.Contains(c.In, v)
	}
	return false
}

func (r Rule) matches(ev telemetry.Event) bool {
	if r.Kind != "" && r.Kind != ev.Kind {
		return false
	}
	for _, c := range r.Match {
		if !c.matches(ev) {
			return false
		}
	}
	return true
}

var (
	validSeverities = []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	validKinds      = []telemetry.Kind{"", telemetry.KindProcessExec, telemetry.KindProcessExit, telemetry.KindFileOpen, telemetry.KindNetConnect}
	validActions    = []Action{"", ActionAlert, ActionKill}
)

// Validate reports the first structural problem in r.
func (r Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule has no id")
	}
	if !slices.Contains(validSeverities, r.Severity) {
		return fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
	}
	if !slices.Contains(validKinds, r.Kind) {
		return fmt.Errorf("rule %s: invalid kind %q", r.ID, r.Kind)
	}
	if !slices.Contains(validActions, r.Action) {
		return fmt.Errorf("rule %s: invalid action %q", r.ID, r.Action)
	}
	if len(r.Match) == 0 {
		return fmt.Errorf("rule %s: no match conditions", r.ID)
	}
	for i, c := range r.Match {
		if !telemetry.KnownFields[c.Field] {
			return fmt.Errorf("rule %s: condition %d: unknown field %q", r.ID, i, c.Field)
		}
		if n := c.operatorCount(); n != 1 {
			return fmt.Errorf("rule %s: condition %d: want exactly one operator, got %d", r.ID, i, n)
		}
	}
	return nil
}
