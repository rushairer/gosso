package utility

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ──────────────────────────────────────────────
// EnsureLogger
// ──────────────────────────────────────────────

func TestEnsureLogger_Nil(t *testing.T) {
	logger := EnsureLogger(nil)
	assert.NotNil(t, logger)
}

func TestEnsureLogger_NonNil(t *testing.T) {
	original := zap.NewNop()
	logger := EnsureLogger(original)
	assert.Same(t, original, logger)
}

// ──────────────────────────────────────────────
// NewLogger
// ──────────────────────────────────────────────

func TestNewLogger(t *testing.T) {
	level := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	logger := NewLogger(level)
	assert.NotNil(t, logger)
	// Verify the logger can log without panicking
	logger.Info("test message")
}

func TestNewLogger_DebugLevel(t *testing.T) {
	level := zap.NewAtomicLevelAt(zapcore.DebugLevel)
	logger := NewLogger(level)
	assert.NotNil(t, logger)
	logger.Debug("debug test")
}

// ──────────────────────────────────────────────
// encodeLevel
// ──────────────────────────────────────────────

// testEnc is a minimal PrimitiveArrayEncoder stub for testing encodeLevel.
type testEnc struct{ vals []string }

func (e *testEnc) AppendString(s string)                      { e.vals = append(e.vals, s) }
func (e *testEnc) AppendBool(bool)                            {}
func (e *testEnc) AppendByteString([]byte)                    {}
func (e *testEnc) AppendComplex128(complex128)                {}
func (e *testEnc) AppendComplex64(complex64)                  {}
func (e *testEnc) AppendFloat64(float64)                      {}
func (e *testEnc) AppendFloat32(float32)                      {}
func (e *testEnc) AppendInt(int)                              {}
func (e *testEnc) AppendInt64(int64)                          {}
func (e *testEnc) AppendInt32(int32)                          {}
func (e *testEnc) AppendInt16(int16)                          {}
func (e *testEnc) AppendInt8(int8)                            {}
func (e *testEnc) AppendUint(uint)                            {}
func (e *testEnc) AppendUint64(uint64)                        {}
func (e *testEnc) AppendUint32(uint32)                        {}
func (e *testEnc) AppendUint16(uint16)                        {}
func (e *testEnc) AppendUint8(uint8)                          {}
func (e *testEnc) AppendUintptr(uintptr)                      {}
func (e *testEnc) AppendDuration(time.Duration)               {}
func (e *testEnc) AppendTime(time.Time)                       {}
func (e *testEnc) AppendArray(zapcore.ArrayMarshaler) error   { return nil }
func (e *testEnc) AppendObject(zapcore.ObjectMarshaler) error { return nil }
func (e *testEnc) AppendReflect(reflect.Value) error          { return nil }

func TestEncodeLevel(t *testing.T) {
	tests := []struct {
		level    zapcore.Level
		expected string
	}{
		{zapcore.DebugLevel, "[DEBUG]"},
		{zapcore.InfoLevel, "[INFO]"},
		{zapcore.WarnLevel, "[WARN]"},
		{zapcore.ErrorLevel, "[ERROR]"},
		{zapcore.DPanicLevel, "[DPANIC]"},
		{zapcore.PanicLevel, "[PANIC]"},
		{zapcore.FatalLevel, "[FATAL]"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			enc := &testEnc{}
			encodeLevel(tt.level, enc)
			require.Len(t, enc.vals, 1)
			assert.Equal(t, tt.expected, enc.vals[0])
		})
	}
}

// ──────────────────────────────────────────────
// colorizeLine
// ──────────────────────────────────────────────

func TestColorizeLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAnsi bool
	}{
		{"debug", "[DEBUG] msg", true},
		{"info", "[INFO] msg", true},
		{"warn", "[WARN] msg", true},
		{"error", "[ERROR] msg", true},
		{"fatal", "[FATAL] msg", true},
		{"panic", "[PANIC] msg", true},
		{"dpanic", "[DPANIC] msg", true},
		{"plain", "some plain text", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := colorizeLine(tt.input)
			if tt.wantAnsi {
				assert.Contains(t, result, "\033[")
				assert.True(t, len(result) > len(tt.input))
			} else {
				assert.Equal(t, tt.input, result)
			}
		})
	}
}

// ──────────────────────────────────────────────
// supportsColor
// ──────────────────────────────────────────────

func TestSupportsColor_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	assert.False(t, supportsColor())
}

func TestSupportsColor_TermColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	assert.True(t, supportsColor())
}

// ──────────────────────────────────────────────
// ColorWriteSyncer
// ──────────────────────────────────────────────

func TestColorWriteSyncer_Write(t *testing.T) {
	// Use os.Pipe to get a writable, non-terminal file
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()

	syncer := &ColorWriteSyncer{Writer: w}
	data := []byte("[INFO] test message\n")
	n, err := syncer.Write(data)

	assert.NoError(t, err)
	// When writing to a pipe (not a terminal), supportsColor() may return false,
	// so the byte count should equal the input length.
	assert.Greater(t, n, 0)

	// Read from the pipe to verify something was written
	_ = w.Close()
	buf := make([]byte, 512)
	readN, _ := r.Read(buf)
	assert.Greater(t, readN, 0)
	assert.Contains(t, string(buf[:readN]), "[INFO] test message")
}

func TestColorWriteSyncer_WriteEmpty(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()

	syncer := &ColorWriteSyncer{Writer: w}
	n, err := syncer.Write([]byte{})

	assert.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestColorWriteSyncer_Sync(t *testing.T) {
	// os.Pipe returns a file that doesn't support sync well,
	// but Sync() should delegate without panicking.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()

	syncer := &ColorWriteSyncer{Writer: w}
	// Sync on a pipe may return an error, but it should not panic.
	_ = syncer.Sync()
}
