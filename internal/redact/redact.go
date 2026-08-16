// Package redact removes obvious credentials from local audit and diagnostic text.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

var sensitiveName = regexp.MustCompile(`(?i)(token|secret|password|private[_-]?key|api[_-]?key|access[_-]?key|credential)`)
var sensitiveAssignment = regexp.MustCompile(`(?i)([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY|API[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL)[A-Z0-9_-]*\s*[=:]\s*)([^\s,;]+)`)
var sensitiveArgument = regexp.MustCompile(`(?i)(--?(?:token|secret|password|passwd|private[-_]?key|api[-_]?key|access[-_]?key|credential|auth[-_]?token)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
var sensitiveHeader = regexp.MustCompile(`(?i)((?:authorization|x-api-key|x-auth-token)\s*:\s*)(?:[^\s,;]+(?:\s+[^\s,;]+)?)`)
var pemBlock = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`)

// NameLooksSensitive identifies names whose values must not enter logs.
func NameLooksSensitive(name string) bool { return sensitiveName.MatchString(name) }

// Value returns a safe representation for an environment variable.
func Value(name, value string) string {
	if NameLooksSensitive(name) {
		return "[REDACTED]"
	}
	return value
}

// Text redacts obvious assignments and PEM blocks without attempting to be a
// complete secret scanner.
func Text(value string) string {
	value = pemBlock.ReplaceAllString(value, "[REDACTED PEM BLOCK]")
	value = sensitiveAssignment.ReplaceAllString(value, `${1}[REDACTED]`)
	value = sensitiveArgument.ReplaceAllString(value, `${1}[REDACTED]`)
	return sensitiveHeader.ReplaceAllString(value, `${1}[REDACTED]`)
}

// EnvironmentNames returns a stable, sorted list of removed variable names.
func EnvironmentNames(names []string) []string {
	result := append([]string(nil), names...)
	for index := range result {
		result[index] = strings.TrimSpace(result[index])
	}
	sort.Strings(result)
	return result
}
