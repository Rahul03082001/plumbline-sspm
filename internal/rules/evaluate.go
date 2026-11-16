package rules

import (
	"strings"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// Evaluate runs one rule against one asset using three-valued logic:
//
//   - any referenced field unknown        -> Unknown (never Pass, never Fail)
//   - otherwise, all conditions true      -> Fail
//   - otherwise                           -> Pass
//
// The evidence records the values used, or why the result is unknown.
func Evaluate(r model.Rule, a model.Asset) (model.Result, model.Evidence) {
	if a.CarriedForward {
		// We didn't see this asset this scan (its listing was incomplete), so
		// we know nothing about it now. Its history decides how it's shown.
		return model.Unknown, model.Evidence{Reason: model.ReasonCollectionIncomplete}
	}

	values := map[string]any{}
	var unknownFields []string
	allTrue := true
	fields := model.Fields[r.AssetKind]

	for _, c := range r.FailWhen {
		val, known := lookup(a.Attributes, c.Field, fields[c.Field])
		if !known {
			unknownFields = appendOnce(unknownFields, c.Field)
			continue
		}
		values[c.Field] = val
		if !holds(c, val) {
			allTrue = false
		}
	}

	if len(unknownFields) > 0 {
		// Report the reason recorded by the connector for the first unknown
		// field (e.g. permission_denied + the endpoint), or "missing".
		why, ok := a.Unknown[unknownFields[0]]
		if !ok {
			why = model.UnknownReason{Reason: model.ReasonMissing}
		}
		ev := model.Evidence{Reason: why.Reason, Endpoint: why.Endpoint, UnknownFields: unknownFields}
		if len(values) > 0 {
			ev.Values = values
		}
		return model.Unknown, ev
	}
	if allTrue {
		return model.Fail, model.Evidence{Values: values}
	}
	return model.Pass, model.Evidence{Values: values}
}

// lookup reads a field through the typed helpers, so `any` never leaks into
// rule logic. The returned value is a bool or a string.
func lookup(attrs model.Attributes, field string, ft model.FieldType) (any, bool) {
	switch ft {
	case model.FieldBool:
		return model.GetBool(attrs, field)
	case model.FieldString:
		return model.GetString(attrs, field)
	}
	return nil, false
}

// holds reports whether one condition is true for a known value. Validation
// at startup guarantees the value types match, so the comparisons are safe.
func holds(c model.Condition, val any) bool {
	switch c.Op {
	case model.OpEq:
		return val == c.Value
	case model.OpNeq:
		return val != c.Value
	case model.OpIn:
		for _, v := range c.Value.([]any) {
			if val == v {
				return true
			}
		}
		return false
	case model.OpContains:
		s, _ := val.(string)
		sub, _ := c.Value.(string)
		return strings.Contains(s, sub)
	}
	return false
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// EvaluateAll produces a CheckResult for EVERY applicable (rule, asset) pair
// of one scan. History fields (last_definitive, first_failed) are filled in
// later by the scan publisher, which knows the previous scan.
func EvaluateAll(ruleset []model.Rule, provider, connectionID, scanID string, assets []model.Asset) []model.CheckResult {
	var out []model.CheckResult
	for _, a := range assets {
		for _, r := range ruleset {
			if !r.AppliesTo(provider, a.Kind) {
				continue
			}
			res, ev := Evaluate(r, a)
			out = append(out, model.CheckResult{
				ID:          model.NewID(),
				ScanID:      scanID,
				RuleID:      r.ID,
				AssetID:     a.ID,
				Fingerprint: model.Fingerprint(connectionID, r.ID, a.Kind, a.ExternalID),
				Result:      res,
				Severity:    r.Severity,
				Evidence:    ev,
			})
		}
	}
	return out
}
