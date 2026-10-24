package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel string

const (
	LogLevelINFO  LogLevel = "INFO"
	LogLevelWARN  LogLevel = "WARN"
	LogLevelERROR LogLevel = "ERROR"
	LogLevelDEBUG LogLevel = "DEBUG"
)

// Logger provides structured logging functionality
type Logger struct {
	prefix string
}

// NewLogger creates a new logger with a prefix
func NewLogger(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

// formatMessage formats a log message with timestamp, level, prefix, and message
func (l *Logger) formatMessage(level LogLevel, message string, args ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	formattedMessage := fmt.Sprintf(message, args...)
	return fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, level, l.prefix, formattedMessage)
}

// Info logs an informational message
func (l *Logger) Info(message string, args ...interface{}) {
	log.Println(l.formatMessage(LogLevelINFO, message, args...))
}

// Warn logs a warning message
func (l *Logger) Warn(message string, args ...interface{}) {
	log.Println(l.formatMessage(LogLevelWARN, message, args...))
}

// Error logs an error message
func (l *Logger) Error(message string, args ...interface{}) {
	log.Println(l.formatMessage(LogLevelERROR, message, args...))
}

// Debug logs a debug message
func (l *Logger) Debug(message string, args ...interface{}) {
	log.Println(l.formatMessage(LogLevelDEBUG, message, args...))
}

// LogRequest logs incoming HTTP request details
func (l *Logger) LogRequest(method, path, userUUID string) {
	l.Info("Request received: method=%s path=%s userUUID=%s", method, path, userUUID)
}

// LogResponse logs HTTP response details
func (l *Logger) LogResponse(statusCode int, message string) {
	l.Info("Response sent: status=%d message=%s", statusCode, message)
}

// LogError logs an error with context and stack trace (RULES.md §6.3)
func (l *Logger) LogError(operation string, err error) {
	// Get caller info for stack trace
	_, file, line, ok := runtime.Caller(1)
	callerInfo := "unknown"
	if ok {
		callerInfo = fmt.Sprintf("%s:%d", file, line)
	}

	// Structured JSON logging (RULES.md §12.2)
	logEntry := map[string]interface{}{
		"timestamp": time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
		"level":     "ERROR",
		"module":    l.prefix,
		"operation": operation,
		"error":     err.Error(),
		"caller":    callerInfo,
	}

	if jsonBytes, err := json.Marshal(logEntry); err == nil {
		log.Println(string(jsonBytes))
	} else {
		// Fallback to text format
		l.Error("Operation failed: operation=%s error=%v caller=%s", operation, err, callerInfo)
	}
}

// LogOperation logs the start/end of an operation
func (l *Logger) LogOperation(operation string, details ...string) {
	detailStr := ""
	if len(details) > 0 {
		detailStr = fmt.Sprintf(" details=[%s]", fmt.Sprint(details))
	}
	l.Debug("Operation: %s%s", operation, detailStr)
}
