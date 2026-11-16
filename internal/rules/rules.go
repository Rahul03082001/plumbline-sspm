// Package rules loads posture rules from YAML, validates them against the
// normalized schema, and evaluates them with three-valued logic.
package rules

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

//go:embed rules/*.yaml
var builtinFS embed.FS

// knownProviders lists providers a rule may target.
var knownProviders = map[string]bool{"github": true}

var idPattern = regexp.MustCompile(`^SL-[A-Z]+-[0-9]{3}$`)

// LoadBuiltin loads the rules compiled into the binary.
func LoadBuiltin() ([]model.Rule, error) {
	return Load(builtinFS, "rules/*.yaml")
}

// Load reads every YAML file matching pattern in fsys, validates each rule,
// and returns them sorted by ID. Any invalid rule is an error: we would rather
// refuse to start than run with a rule that can never fire.
func Load(fsys fs.FS, pattern string) ([]model.Rule, error) {
	files, err := fs.Glob(fsys, pattern)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no rule files match %q", pattern)
	}
	var all []model.Rule
	seen := map[string]bool{}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		rs, err := parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, r := range rs {
			if err := Validate(r); err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", f, r.ID, err)
			}
			if seen[r.ID] {
				return nil, fmt.Errorf("%s: duplicate rule id %q", f, r.ID)
			}
			seen[r.ID] = true
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}

func parse(data []byte) ([]model.Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelled key like "fail_whn" is an error, not ignored
	var rs []model.Rule
	if err := dec.Decode(&rs); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return rs, nil
}

// Validate checks one rule against the normalized schema in model.Fields.
func Validate(r model.Rule) error {
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("id must look like SL-XXX-000")
	}
	if strings.TrimSpace(r.Title) == "" || strings.TrimSpace(r.Remediation) == "" {
		return errors.New("title and remediation are required")
	}
	if r.Severity.Weight() == 0 {
		return fmt.Errorf("unknown severity %q", r.Severity)
	}
	if len(r.Providers) == 0 {
		return errors.New("at least one provider is required")
	}
	for _, p := range r.Providers {
		if !knownProviders[p] {
			return fmt.Errorf("unknown provider %q", p)
		}
	}
	fields, ok := model.Fields[r.AssetKind]
	if !ok {
		return fmt.Errorf("unknown asset_kind %q", r.AssetKind)
	}
	if len(r.FailWhen) == 0 {
		return errors.New("fail_when needs at least one condition")
	}
	for i, c := range r.FailWhen {
		ft, ok := fields[c.Field]
		if !ok {
			return fmt.Errorf("condition %d: unknown field %q for kind %q", i, c.Field, r.AssetKind)
		}
		if err := validateCondition(c, ft); err != nil {
			return fmt.Errorf("condition %d (%s): %w", i, c.Field, err)
		}
	}
	return nil
}

func validateCondition(c model.Condition, ft model.FieldType) error {
	switch c.Op {
	case model.OpEq, model.OpNeq:
		return checkType(c.Value, ft)
	case model.OpIn:
		list, ok := c.Value.([]any)
		if !ok || len(list) == 0 {
			return errors.New(`"in" needs a non-empty list`)
		}
		for _, v := range list {
			if err := checkType(v, ft); err != nil {
				return err
			}
		}
		return nil
	case model.OpContains:
		if ft != model.FieldString {
			return errors.New(`"contains" only works on string fields`)
		}
		return checkType(c.Value, ft)
	}
	return fmt.Errorf("unknown operator %q", c.Op)
}

func checkType(v any, ft model.FieldType) error {
	switch ft {
	case model.FieldBool:
		if _, ok := v.(bool); ok {
			return nil
		}
	case model.FieldString:
		if _, ok := v.(string); ok {
			return nil
		}
	}
	return fmt.Errorf("value %v (%T) does not match field type %s", v, v, ft)
}
