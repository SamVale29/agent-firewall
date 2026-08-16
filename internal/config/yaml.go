package config

import (
	"fmt"
	"strconv"
	"strings"
)

// This parser intentionally supports the small, readable YAML vocabulary used
// by Agent Firewall policies. Keeping it dependency-free makes the CLI easy to
// bootstrap; unsupported YAML features fail with a useful line number instead
// of being silently misinterpreted.
type yamlLine struct {
	number int
	indent int
	text   string
}

func parseYAML(data []byte) (map[string]any, error) {
	lines, err := prepareYAMLLines(string(data))
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	value, next, err := parseYAMLBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next != len(lines) {
		return nil, fmt.Errorf("line %d: unexpected content", lines[next].number)
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("line %d: the document must start with a mapping", lines[0].number)
	}
	return result, nil
}

func prepareYAMLLines(input string) ([]yamlLine, error) {
	var result []yamlLine
	for number, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		if strings.Contains(raw, "\t") {
			return nil, fmt.Errorf("line %d: tabs are not supported for indentation", number+1)
		}
		withoutComment := stripYAMLComment(raw)
		if strings.TrimSpace(withoutComment) == "" {
			continue
		}
		trimmed := strings.TrimLeft(withoutComment, " ")
		if trimmed == "---" || trimmed == "..." {
			continue
		}
		result = append(result, yamlLine{
			number: number + 1,
			indent: len(withoutComment) - len(trimmed),
			text:   strings.TrimSpace(withoutComment),
		})
	}
	return result, nil
}

func stripYAMLComment(value string) string {
	var quote rune
	for i, r := range value {
		if quote != 0 {
			if r == quote && (quote != '"' || i == 0 || value[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
			return value[:i]
		}
	}
	return value
}

func parseYAMLBlock(lines []yamlLine, index, indent int) (any, int, error) {
	if index >= len(lines) || lines[index].indent != indent {
		return nil, index, fmt.Errorf("line %d: invalid indentation", lines[index].number)
	}
	if strings.HasPrefix(lines[index].text, "-") {
		return parseYAMLList(lines, index, indent)
	}
	return parseYAMLMap(lines, index, indent)
}

func parseYAMLMap(lines []yamlLine, index, indent int) (map[string]any, int, error) {
	result := map[string]any{}
	for index < len(lines) && lines[index].indent == indent {
		line := lines[index]
		if strings.HasPrefix(line.text, "-") {
			break
		}
		key, rest, ok := splitYAMLKey(line.text)
		if !ok || key == "" {
			return nil, index, fmt.Errorf("line %d: expected key: value", line.number)
		}
		if _, exists := result[key]; exists {
			return nil, index, fmt.Errorf("line %d: duplicate key %q", line.number, key)
		}
		index++
		if strings.TrimSpace(rest) != "" {
			value, err := parseYAMLScalar(strings.TrimSpace(rest))
			if err != nil {
				return nil, index, fmt.Errorf("line %d: %w", line.number, err)
			}
			result[key] = value
			continue
		}
		if index < len(lines) && lines[index].indent > indent {
			value, next, err := parseYAMLBlock(lines, index, lines[index].indent)
			if err != nil {
				return nil, index, err
			}
			result[key] = value
			index = next
		} else {
			result[key] = map[string]any{}
		}
	}
	return result, index, nil
}

func parseYAMLList(lines []yamlLine, index, indent int) ([]any, int, error) {
	result := []any{}
	for index < len(lines) && lines[index].indent == indent && strings.HasPrefix(lines[index].text, "-") {
		line := lines[index]
		rest := strings.TrimSpace(strings.TrimPrefix(line.text, "-"))
		index++
		if rest == "" {
			if index >= len(lines) || lines[index].indent <= indent {
				return nil, index, fmt.Errorf("line %d: list item must have a value", line.number)
			}
			value, next, err := parseYAMLBlock(lines, index, lines[index].indent)
			if err != nil {
				return nil, index, err
			}
			result = append(result, value)
			index = next
			continue
		}
		// Mapping list items are supported for future policy extensions.
		if key, valueText, ok := splitYAMLKey(rest); ok {
			item := map[string]any{}
			if strings.TrimSpace(valueText) == "" {
				item[key] = map[string]any{}
			} else {
				value, err := parseYAMLScalar(strings.TrimSpace(valueText))
				if err != nil {
					return nil, index, fmt.Errorf("line %d: %w", line.number, err)
				}
				item[key] = value
			}
			result = append(result, item)
			continue
		}
		value, err := parseYAMLScalar(rest)
		if err != nil {
			return nil, index, fmt.Errorf("line %d: %w", line.number, err)
		}
		result = append(result, value)
	}
	return result, index, nil
}

func splitYAMLKey(value string) (string, string, bool) {
	var quote rune
	for i, r := range value {
		if quote != 0 {
			if r == quote && (quote != '"' || i == 0 || value[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == ':' {
			if i+1 == len(value) || value[i+1] == ' ' || value[i+1] == '\t' {
				return strings.TrimSpace(value[:i]), value[i+1:], true
			}
		}
	}
	return "", "", false
}

func parseYAMLScalar(value string) (any, error) {
	if value == "" {
		return "", nil
	}
	if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
		(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
		if strings.HasPrefix(value, "'") {
			return strings.ReplaceAll(value[1:len(value)-1], "''", "'"), nil
		}
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return nil, fmt.Errorf("invalid quoted scalar %q", value)
		}
		return unquoted, nil
	}
	if value == "null" || value == "~" {
		return nil, nil
	}
	if value == "true" || value == "false" {
		return value == "true", nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		inside := strings.TrimSpace(value[1 : len(value)-1])
		if inside == "" {
			return []any{}, nil
		}
		parts, err := splitInlineList(inside)
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(parts))
		for _, part := range parts {
			item, err := parseYAMLScalar(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	}
	if integer, err := strconv.Atoi(value); err == nil {
		return integer, nil
	}
	return value, nil
}

func splitInlineList(value string) ([]string, error) {
	var parts []string
	start := 0
	var quote rune
	for i, r := range value {
		if quote != 0 {
			if r == quote && (quote != '"' || i == 0 || value[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case ',':
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in inline list")
	}
	parts = append(parts, value[start:])
	return parts, nil
}
