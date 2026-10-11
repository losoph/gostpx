package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

var (
	// ErrConfigReadOnly is returned when attempting to write config while ui.config_writable is false.
	ErrConfigReadOnly = errors.New("configuration is read-only (ui.config_writable = false)")
)

// FormatValueForKey formats a Go value into a valid TOML value string for a given key.
func FormatValueForKey(key string, val any) (string, error) {
	switch key {
	case "proxy.port":
		switch v := val.(type) {
		case int:
			return strconv.Itoa(v), nil
		case int64:
			return strconv.FormatInt(v, 10), nil
		case string:
			n, err := strconv.Atoi(v)
			if err != nil {
				return "", fmt.Errorf("invalid port %q: %w", v, err)
			}
			return strconv.Itoa(n), nil
		}
	case "autostart", "autoconnect", "ui.config_writable":
		switch v := val.(type) {
		case bool:
			return strconv.FormatBool(v), nil
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return "", fmt.Errorf("invalid bool %q: %w", v, err)
			}
			return strconv.FormatBool(b), nil
		}
	default:
		switch v := val.(type) {
		case string:
			return fmt.Sprintf("%q", v), nil
		case int:
			return strconv.Itoa(v), nil
		case int64:
			return strconv.FormatInt(v, 10), nil
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64), nil
		case bool:
			return strconv.FormatBool(v), nil
		}
	}
	return "", fmt.Errorf("unsupported value %v (%T) for key %s", val, val, key)
}

type replacement struct {
	keyPath string
	offset  uint32
	length  uint32
}

// UpdateBytes modifies specific keys in the TOML document without disturbing
// comments, indentation, whitespace, or other keys. It uses go-toml/v2/unstable AST
// to replace only the exact byte range of each value.
func UpdateBytes(doc []byte, updates map[string]any) ([]byte, error) {
	if len(updates) == 0 {
		return doc, nil
	}

	bomLength := 0
	if bytes.HasPrefix(doc, []byte("\xef\xbb\xbf")) {
		bomLength = 3
	}

	parseData := doc[bomLength:]
	p := unstable.Parser{KeepComments: true}
	p.Reset(parseData)

	var currentTable []string
	var replacements []replacement
	foundKeys := make(map[string]bool)

	// Keep track of section positions in case we need to append missing keys
	tableEnds := make(map[string]int)
	lastExprEnd := bomLength

	for p.NextExpression() {
		node := p.Expression()
		nodeEnd := bomLength + int(node.Raw.Offset+node.Raw.Length)
		if nodeEnd > lastExprEnd {
			lastExprEnd = nodeEnd
		}

		if node.Kind == unstable.Table {
			currentTable = nil
			for it := node.Children(); it.Next(); {
				currentTable = append(currentTable, string(it.Node().Data))
			}
			tblName := strings.Join(currentTable, ".")
			tableEnds[tblName] = nodeEnd
		} else if node.Kind == unstable.KeyValue {
			valNode := node.Child()
			if valNode != nil {
				var keySegments []string
				if len(currentTable) > 0 {
					keySegments = append(keySegments, currentTable...)
				}
				for k := valNode.Next(); k != nil; k = k.Next() {
					keySegments = append(keySegments, string(k.Data))
				}
				fullKey := strings.Join(keySegments, ".")
				if _, ok := updates[fullKey]; ok {
					replacements = append(replacements, replacement{
						keyPath: fullKey,
						offset:  valNode.Raw.Offset + uint32(bomLength),
						length:  valNode.Raw.Length,
					})
					foundKeys[fullKey] = true
				}
			}
			tblName := strings.Join(currentTable, ".")
			tableEnds[tblName] = nodeEnd
		}
	}

	if err := p.Error(); err != nil {
		return nil, fmt.Errorf("parse toml ast: %w", err)
	}

	// Sort replacements by offset in DESCENDING order to avoid offset drift
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].offset > replacements[j].offset
	})

	result := make([]byte, len(doc))
	copy(result, doc)

	for _, r := range replacements {
		newValStr, err := FormatValueForKey(r.keyPath, updates[r.keyPath])
		if err != nil {
			return nil, err
		}
		newBytes := []byte(newValStr)
		start := int(r.offset)
		end := start + int(r.length)
		result = append(result[:start], append(newBytes, result[end:]...)...)

		delta := len(newBytes) - int(r.length)
		if delta != 0 {
			for t, pos := range tableEnds {
				if pos >= end {
					tableEnds[t] = pos + delta
				}
			}
		}
	}

	// For any key that was not found, sort deterministically and append cleanly to its table or root
	var missingKeys []string
	for key := range updates {
		if !foundKeys[key] {
			missingKeys = append(missingKeys, key)
		}
	}
	sort.Strings(missingKeys)

	for _, key := range missingKeys {
		val := updates[key]
		newValStr, err := FormatValueForKey(key, val)
		if err != nil {
			return nil, err
		}

		parts := strings.Split(key, ".")
		if len(parts) == 1 {
			// Top-level key: must appear before any table header
			line := fmt.Sprintf("%s = %s\n", parts[0], newValStr)
			firstTableIdx := -1
			lines := bytes.SplitAfter(result, []byte("\n"))
			pos := 0
			for _, l := range lines {
				trimmed := bytes.TrimSpace(l)
				if bytes.HasPrefix(trimmed, []byte("[")) {
					firstTableIdx = pos
					break
				}
				pos += len(l)
			}
			if firstTableIdx >= 0 {
				insertion := []byte(line)
				result = append(result[:firstTableIdx], append(insertion, result[firstTableIdx:]...)...)
				insertLen := len(insertion)
				for t, endPos := range tableEnds {
					if endPos >= firstTableIdx {
						tableEnds[t] = endPos + insertLen
					}
				}
			} else {
				result = append(result, []byte("\n"+line)...)
			}
		} else {
			section := strings.Join(parts[:len(parts)-1], ".")
			fieldName := parts[len(parts)-1]
			line := fmt.Sprintf("%s = %s\n", fieldName, newValStr)

			if endPos, ok := tableEnds[section]; ok && endPos <= len(result) {
				// Advance past the end of the line
				for endPos < len(result) && result[endPos] != '\n' {
					endPos++
				}
				if endPos < len(result) && result[endPos] == '\n' {
					endPos++
				}
				insertion := []byte(line)
				result = append(result[:endPos], append(insertion, result[endPos:]...)...)
				insertLen := len(insertion)
				newEnd := endPos + insertLen
				for t, pos := range tableEnds {
					if t == section {
						tableEnds[t] = newEnd
					} else if pos >= endPos {
						tableEnds[t] = pos + insertLen
					}
				}
			} else {
				// Add new section at bottom
				secHeader := fmt.Sprintf("\n[%s]\n%s", section, line)
				result = append(result, []byte(secHeader)...)
				tableEnds[section] = len(result)
			}
		}
	}

	// Verify the result is valid TOML syntax before returning
	var genericMap map[string]any
	testData := bytes.TrimPrefix(result, []byte("\xef\xbb\xbf"))
	if err := toml.Unmarshal(testData, &genericMap); err != nil {
		return nil, fmt.Errorf("result is invalid TOML: %w", err)
	}

	// If it matches gostpx Config schema, verify semantic validation rules
	if cfg, err := Parse(result); err == nil {
		issues := Validate(cfg, result)
		for _, issue := range issues {
			if !issue.IsWarning {
				return nil, fmt.Errorf("result validation failed: %s", issue)
			}
		}
	}

	return result, nil
}

// UpdateFile reads the config file at path, checks ui.config_writable, performs
// surgical in-place updates preserving all comments and structure, and writes back atomically.
func UpdateFile(path string, updates map[string]any) error {
	doc, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	// Check ui.config_writable
	cfg, _, err := Load(path)
	if err == nil && cfg != nil {
		// If config_writable is false, refuse to write
		if !cfg.UI.ConfigWritable {
			return ErrConfigReadOnly
		}
	}

	newDoc, err := UpdateBytes(doc, updates)
	if err != nil {
		return fmt.Errorf("update toml: %w", err)
	}

	var perm os.FileMode = 0600
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		perm = fi.Mode().Perm()
	}

	// Backup before write (ADR-007)
	bakPath := path + ".bak"
	if err := os.WriteFile(bakPath, doc, perm); err != nil {
		return fmt.Errorf("backup config: %w", err)
	}

	// Write temp file and atomically rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, newDoc, perm); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp config: %w", err)
	}

	return nil
}
