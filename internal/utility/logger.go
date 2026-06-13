package utility

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// EnsureLogger returns a no-op logger if the given logger is nil.
func EnsureLogger(logger *zap.Logger) *zap.Logger {
	if logger == nil {
		return zap.NewNop()
	}
	return logger
}

// NewLogger initializes the global logger.
// format is an optional parameter: "console" (default) or "json".
func NewLogger(level zap.AtomicLevel, format ...string) *zap.Logger {

	// Determine log format
	logFormat := "console"
	if len(format) > 0 && format[0] != "" {
		logFormat = format[0]
	}

	// Create custom encoder configuration
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    encodeLevel,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	var writeSyncer zapcore.WriteSyncer

	if logFormat == "json" {
		// JSON encoder for production/containerized environments
		encoder = zapcore.NewJSONEncoder(encoderConfig)
		writeSyncer = zapcore.AddSync(os.Stdout)
	} else {
		// Console encoder with optional color output
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
		if supportsColor() {
			writeSyncer = &ColorWriteSyncer{Writer: os.Stdout, color: true}
		} else {
			writeSyncer = zapcore.AddSync(os.Stdout)
		}
	}

	core := zapcore.NewCore(
		encoder,
		writeSyncer,
		level,
	)

	return zap.New(core, zap.AddCaller())
}

// encodeLevel adds color for different log levels
func encodeLevel(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	switch level {
	case zapcore.DebugLevel:
		enc.AppendString("[DEBUG]")
	case zapcore.InfoLevel:
		enc.AppendString("[INFO]")
	case zapcore.WarnLevel:
		enc.AppendString("[WARN]")
	case zapcore.ErrorLevel:
		enc.AppendString("[ERROR]")
	case zapcore.DPanicLevel:
		enc.AppendString("[DPANIC]")
	case zapcore.PanicLevel:
		enc.AppendString("[PANIC]")
	case zapcore.FatalLevel:
		enc.AppendString("[FATAL]")
	default:
		enc.AppendString("[" + level.CapitalString() + "]")
	}
}

// ColorWriteSyncer color write syncer
type ColorWriteSyncer struct {
	Writer *os.File
	color  bool
}

// Write writes data and adds color
func (w *ColorWriteSyncer) Write(p []byte) (n int, err error) {
	// If it is a log output and color is supported, add color to the entire line
	if w.color && len(p) > 0 {
		line := string(p)
		coloredLine := colorizeLine(line)
		return w.Writer.Write([]byte(coloredLine))
	}

	return w.Writer.Write(p)
}

// Sync syncs written data
func (w *ColorWriteSyncer) Sync() error {
	return w.Writer.Sync()
}

// colorizeLine adds color to the entire log line
func colorizeLine(line string) string {
	var color string

	if strings.Contains(line, "[DEBUG]") {
		color = "\033[36m" // Cyan
	} else if strings.Contains(line, "[INFO]") {
		color = "\033[32m" // Green
	} else if strings.Contains(line, "[WARN]") {
		color = "\033[33m" // Yellow
	} else if strings.Contains(line, "[ERROR]") || strings.Contains(line, "[FATAL]") || strings.Contains(line, "[PANIC]") || strings.Contains(line, "[DPANIC]") {
		color = "\033[31m" // Red
	} else {
		return line
	}

	return fmt.Sprintf("%s%s\033[0m", color, line)
}

// supportsColor detects if the terminal supports color
func supportsColor() bool {
	// Check NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check TERM environment variable
	term := os.Getenv("TERM")
	if strings.Contains(term, "color") || strings.Contains(term, "256") {
		return true
	}

	// Common color-supporting terminals
	colorTerms := []string{"xterm", "screen", "tmux", "vt100"}
	for _, t := range colorTerms {
		if strings.Contains(term, t) {
			return true
		}
	}

	// Check if outputting to a terminal
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		return true
	}

	return false
}
