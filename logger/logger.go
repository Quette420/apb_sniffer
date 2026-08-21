package logger

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Level int

const (
	Error Level = iota
	Info
	Debug
	Trace
)

type Logger struct {
	level Level
}

func New(level string) *Logger {
	switch strings.ToLower(level) {
	case "error":
		return &Logger{level: Error}

	case "info":
		return &Logger{level: Info}

	case "debug":
		return &Logger{level: Debug}

	case "trace":
		return &Logger{level: Trace}

	default:
		fmt.Fprintf(
			os.Stderr,
			"unknown log level %q, using info\n",
			level,
		)

		return &Logger{level: Info}
	}
}

func (l *Logger) Error(format string, args ...any) {
	l.log(Error, "ERROR", format, args...)
}

func (l *Logger) Info(format string, args ...any) {
	l.log(Info, "INFO", format, args...)
}

func (l *Logger) Debug(format string, args ...any) {
	l.log(Debug, "DEBUG", format, args...)
}

func (l *Logger) Trace(format string, args ...any) {
	l.log(Trace, "TRACE", format, args...)
}

func (l *Logger) log(
	level Level,
	name string,
	format string,
	args ...any,
) {
	if level > l.level {
		return
	}

	timestamp := time.Now().Format("15:04:05.000")

	fmt.Fprintf(
		os.Stdout,
		"[%s] %-5s %s\n",
		timestamp,
		name,
		fmt.Sprintf(format, args...),
	)
}
