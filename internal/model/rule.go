package model

// Op is a rule condition operator.
type Op string

const (
	OpEq       Op = "eq"       // field == value
	OpNeq      Op = "neq"      // field != value
	OpIn       Op = "in"       // field is one of value (a list)
	OpContains Op = "contains" // string field contains value as a substring
)

// Condition is one line of a rule's fail_when list.
type Condition struct {
	Field string `yaml:"field" json:"field"`
	Op    Op     `yaml:"op" json:"op"`
	Value any    `yaml:"value" json:"value"`
}

// Rule is one posture check, loaded from YAML. The struct tags (`yaml:"..."`)
// tell the YAML and JSON libraries which key maps to which field.
type Rule struct {
	ID          string      `yaml:"id" json:"id"`
	Title       string      `yaml:"title" json:"title"`
	Severity    Severity    `yaml:"severity" json:"severity"`
	Providers   []string    `yaml:"providers" json:"providers"`
	AssetKind   AssetKind   `yaml:"asset_kind" json:"asset_kind"`
	FailWhen    []Condition `yaml:"fail_when" json:"fail_when"`
	Remediation string      `yaml:"remediation" json:"remediation"`
}

// AppliesTo reports whether the rule should be evaluated for this asset.
func (r Rule) AppliesTo(provider string, kind AssetKind) bool {
	if r.AssetKind != kind {
		return false
	}
	for _, p := range r.Providers {
		if p == provider {
			return true
		}
	}
	return false
}
