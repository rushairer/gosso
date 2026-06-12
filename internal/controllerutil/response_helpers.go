package controllerutil

import "github.com/gin-gonic/gin"

// SetNoCacheHeaders sets HTTP headers to prevent caching of responses containing tokens.
func SetNoCacheHeaders(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
}
