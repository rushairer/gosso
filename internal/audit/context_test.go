package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetMetadata_AndExtract(t *testing.T) {
	ctx := SetMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0", "req-123")

	assert.Equal(t, "192.168.1.1", IPFromContext(ctx))
	assert.Equal(t, "Mozilla/5.0", UserAgentFromContext(ctx))
	assert.Equal(t, "req-123", RequestIDFromContext(ctx))
}

func TestContextExtractors_EmptyContext(t *testing.T) {
	ctx := context.Background()

	assert.Equal(t, "", IPFromContext(ctx))
	assert.Equal(t, "", UserAgentFromContext(ctx))
	assert.Equal(t, "", RequestIDFromContext(ctx))
}

func TestSetMetadata_Overwrite(t *testing.T) {
	ctx := SetMetadata(context.Background(), "ip1", "ua1", "rid1")
	ctx = SetMetadata(ctx, "ip2", "ua2", "rid2")

	assert.Equal(t, "ip2", IPFromContext(ctx))
	assert.Equal(t, "ua2", UserAgentFromContext(ctx))
	assert.Equal(t, "rid2", RequestIDFromContext(ctx))
}

func TestSetMetadata_PartialValues(t *testing.T) {
	ctx := SetMetadata(context.Background(), "", "", "")

	assert.Equal(t, "", IPFromContext(ctx))
	assert.Equal(t, "", UserAgentFromContext(ctx))
	assert.Equal(t, "", RequestIDFromContext(ctx))
}
