package detection

import "edr/internal/telemetry"

// Engine evaluates events against a fixed rule set. It is immutable after
// construction and safe for concurrent use.
type Engine struct {
	rules []Rule
}

// NewEngine builds an engine. Rules are expected to be validated already
// (LoadDir does this); an empty Action is normalized to ActionAlert.
func NewEngine(rules []Rule) *Engine {
	rs := make([]Rule, len(rules))
	for i, r := range rules {
		if r.Action == "" {
			r.Action = ActionAlert
		}
		rs[i] = r
	}
	return &Engine{rules: rs}
}

// Evaluate returns one alert per matching rule, in rule order.
func (e *Engine) Evaluate(ev telemetry.Event) []Alert {
	var alerts []Alert
	for _, r := range e.rules {
		if r.matches(ev) {
			alerts = append(alerts, Alert{
				Time: ev.Time, RuleID: r.ID, Title: r.Title,
				Severity: r.Severity, Action: r.Action, Event: ev,
			})
		}
	}
	return alerts
}

// Len returns the number of loaded rules.
func (e *Engine) Len() int { return len(e.rules) }
