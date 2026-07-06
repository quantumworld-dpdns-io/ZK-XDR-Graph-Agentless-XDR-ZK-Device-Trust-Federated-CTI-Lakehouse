package handlers

import (
	"net/http"
	"time"

	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/config"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/pkg/response"
)

type HealthHandler struct {
	cfg *config.Config
}

func NewHealthHandler(cfg *config.Config) *HealthHandler {
	return &HealthHandler{cfg: cfg}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"service":   "zk-xdr-graph-api",
		"version":   "0.1.0",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(startTime).String(),
	})
}

var startTime = time.Now()
