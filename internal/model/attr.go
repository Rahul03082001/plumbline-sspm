package model

import (
	"encoding/json"
	"fmt"
)

// Attributes is the loosely-typed bag of normalized values on an Asset.
// map[string]any is Go's "any JSON object". The helpers below are the ONLY
// place that looks inside it, so the rule engine never deals with `any`.
type Attributes map[string]any

// unknownKey is a reserved key used when an asset is stored in the database:
// it carries the reasons for unknown attributes alongside the known values.
// Rule fields may never start with "_", so it can't clash with a real field.
const unknownKey = "_unknown"

// GetBool returns (value, known). known is false when the key is missing,
// null, or not a bool. All three mean "we don't know", never "false".
func GetBool(attrs Attributes, key string) (value bool, known bool) {
	v, ok := attrs[key]
	if !ok || v == nil {
		return false, false
	}
	b, ok := v.(bool) // type assertion: "is v a bool?" ok=false if not
	return b, ok
}

// GetString returns (value, known) with the same rules as GetBool.
func GetString(attrs Attributes, key string) (value string, known bool) {
	v, ok := attrs[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// FieldType is the declared type of a normalized attribute.
type FieldType string

const (
	FieldBool   FieldType = "bool"
	FieldString FieldType = "string"
)

// Fields is the normalized schema: which attributes exist on each asset kind
// and their types. Rules are validated against it at startup, so a typo in a
// rule file is a startup error, not a silent "unknown" forever.
var Fields = map[AssetKind]map[string]FieldType{
	KindOrg: {
		"two_factor_required":             FieldBool,
		"default_repo_permission":         FieldString,
		"members_can_create_public_repos": FieldBool,
	},
	KindUser: {
		"login":                   FieldString,
		"is_admin":                FieldBool,
		"mfa_enabled":             FieldBool,
		"is_outside_collaborator": FieldBool,
	},
	KindRepo: {
		"visibility":               FieldString,
		"default_branch":           FieldString,
		"default_branch_protected": FieldBool,
		"secret_scanning":          FieldBool,
	},
	KindWebhook: {
		"url_scheme":   FieldString,
		"insecure_ssl": FieldBool,
		"has_secret":   FieldBool,
	},
}

// EncodeAttributes produces the JSON stored in assets.attributes: the known
// values, plus the unknown reasons under the reserved "_unknown" key.
func EncodeAttributes(attrs Attributes, unknown map[string]UnknownReason) (string, error) {
	out := make(map[string]any, len(attrs)+1)
	for k, v := range attrs {
		out[k] = v
	}
	if len(unknown) > 0 {
		out[unknownKey] = unknown
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("encode attributes: %w", err)
	}
	return string(b), nil
}

// DecodeAttributes is the inverse of EncodeAttributes.
func DecodeAttributes(s string) (Attributes, map[string]UnknownReason, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, nil, fmt.Errorf("decode attributes: %w", err)
	}
	attrs := Attributes{}
	var unknown map[string]UnknownReason
	for k, v := range raw {
		if k == unknownKey {
			if err := json.Unmarshal(v, &unknown); err != nil {
				return nil, nil, fmt.Errorf("decode unknown reasons: %w", err)
			}
			continue
		}
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			return nil, nil, fmt.Errorf("decode attribute %q: %w", k, err)
		}
		attrs[k] = val
	}
	return attrs, unknown, nil
}
