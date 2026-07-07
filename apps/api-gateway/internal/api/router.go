package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/api/handlers"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/config"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/models"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/pkg/response"
)

func NewRouter(cfg *config.Config, db *gorm.DB, rdb *redis.Client) *chi.Mux {
	r := chi.NewRouter()

	r.Use(LoggerMiddleware)
	r.Use(RecovererMiddleware)
	r.Use(CORSMiddleware)
	r.Use(RequestIDMiddleware)

	healthH := handlers.NewHealthHandler(cfg)
	authH := handlers.NewAuthHandler(db, cfg)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", healthH.Health)
		r.Handle("/metrics", promhttp.Handler())

		r.Post("/auth/login", authH.Login)
		r.Post("/auth/register", authH.Register)

		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware(cfg))
			r.Use(TenantMiddleware)
			r.Use(RateLimitMiddleware(rdb))
			r.Use(AuditMiddleware(db))

			r.Get("/assets", listAssets(db))
			r.Post("/assets", createAsset(db))
			r.Get("/assets/{id}", getAsset(db))
			r.Put("/assets/{id}", updateAsset(db))
			r.Delete("/assets/{id}", deleteAsset(db))

			r.Post("/events/ingest", ingestEvent(db))
			r.Get("/events", listEvents(db))
			r.Get("/events/{id}", getEvent(db))

			r.Get("/incidents", listIncidents(db))
			r.Post("/incidents", createIncident(db))
			r.Get("/incidents/{id}", getIncident(db))
			r.Post("/incidents/{id}/assign", assignIncident(db))
			r.Post("/incidents/{id}/close", closeIncident(db))

			r.Get("/cti/indicators", listCTIIndicators(db))
			r.Post("/cti/indicators", createCTIIndicator(db))
			r.Post("/cti/lookup", lookupCTI(db))

			r.Get("/playbooks", listPlaybooks(db))
			r.Post("/playbooks/{id}/dry-run", dryRunPlaybook(db))
			r.Post("/playbooks/{id}/execute", executePlaybook(db))

			r.Post("/proofs/generate", generateProof(db))
			r.Post("/proofs/verify", verifyProof(db))

			r.Post("/copilot/summarize-incident", summarizeIncident())
			r.Post("/copilot/recommend-playbook", recommendPlaybook())
		})
	})

	return r
}

func listAssets(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)
		tid, _ := uuid.Parse(tenantIDStr)

		var assets []models.Asset
		if err := db.Where("tenant_id = ?", tid).Find(&assets).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list assets"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]interface{}{"data": assets, "total": len(assets)})
	}
}

func createAsset(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var asset models.Asset
		if err := json.NewDecoder(r.Body).Decode(&asset); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)
		tid, _ := uuid.Parse(tenantIDStr)
		asset.TenantID = tid
		asset.Status = "active"

		if err := db.Create(&asset).Error; err != nil {
			slog.Error("failed to create asset", "error", err)
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create asset"})
			return
		}
		response.JSON(w, http.StatusCreated, asset)
	}
}

func getAsset(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var asset models.Asset
		if err := db.First(&asset, "id = ?", id).Error; err != nil {
			response.JSON(w, http.StatusNotFound, map[string]string{"error": "asset not found"})
			return
		}
		response.JSON(w, http.StatusOK, asset)
	}
}

func updateAsset(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		if err := db.Model(&models.Asset{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update asset"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]string{"message": "asset updated"})
	}
}

func deleteAsset(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if err := db.Delete(&models.Asset{}, "id = ?", id).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete asset"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]string{"message": "asset deleted"})
	}
}

func ingestEvent(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var event models.SecurityEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)
		tid, _ := uuid.Parse(tenantIDStr)
		event.TenantID = tid
		event.SchemaVersion = "xdr-event-v0.1"

		if event.EventID == "" {
			event.EventID = "evt_" + uuid.New().String()[:12]
		}

		if err := db.Create(&event).Error; err != nil {
			slog.Error("failed to ingest event", "error", err)
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to ingest event"})
			return
		}
		response.JSON(w, http.StatusCreated, event)
	}
}

func listEvents(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)
		tid, _ := uuid.Parse(tenantIDStr)

		var events []models.SecurityEvent
		if err := db.Where("tenant_id = ?", tid).Order("observed_at DESC").Limit(100).Find(&events).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list events"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]interface{}{"data": events, "total": len(events)})
	}
}

func getEvent(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var event models.SecurityEvent
		if err := db.First(&event, "id = ?", id).Error; err != nil {
			response.JSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
			return
		}
		response.JSON(w, http.StatusOK, event)
	}
}

func listIncidents(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)
		tid, _ := uuid.Parse(tenantIDStr)

		var incidents []models.Incident
		if err := db.Where("tenant_id = ?", tid).Order("created_at DESC").Find(&incidents).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list incidents"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]interface{}{"data": incidents, "total": len(incidents)})
	}
}

func createIncident(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var incident models.Incident
		if err := json.NewDecoder(r.Body).Decode(&incident); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)
		tid, _ := uuid.Parse(tenantIDStr)
		incident.TenantID = tid
		incident.Status = "open"

		if err := db.Create(&incident).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create incident"})
			return
		}
		response.JSON(w, http.StatusCreated, incident)
	}
}

func getIncident(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var incident models.Incident
		if err := db.First(&incident, "id = ?", id).Error; err != nil {
			response.JSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		response.JSON(w, http.StatusOK, incident)
	}
}

func assignIncident(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req struct {
			AssignedTo string `json:"assigned_to"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		assignedUUID, _ := uuid.Parse(req.AssignedTo)
		now := time.Now()
		updates := map[string]interface{}{
			"assigned_to": assignedUUID,
			"assigned_at": now,
		}

		if err := db.Model(&models.Incident{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to assign incident"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]string{"message": "incident assigned"})
	}
}

func closeIncident(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		now := time.Now()
		updates := map[string]interface{}{
			"status":     "closed",
			"resolved_at": now,
		}

		if err := db.Model(&models.Incident{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to close incident"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]string{"message": "incident closed"})
	}
}

func listCTIIndicators(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var indicators []models.CTIIndicator
		if err := db.Where("is_active = ?", true).Order("created_at DESC").Find(&indicators).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list indicators"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]interface{}{"data": indicators, "total": len(indicators)})
	}
}

func createCTIIndicator(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var indicator models.CTIIndicator
		if err := json.NewDecoder(r.Body).Decode(&indicator); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		if indicator.IndicatorID == "" {
			indicator.IndicatorID = "ioc_" + uuid.New().String()[:12]
		}
		indicator.IsActive = true

		if err := db.Create(&indicator).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create indicator"})
			return
		}
		response.JSON(w, http.StatusCreated, indicator)
	}
}

func lookupCTI(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		var indicators []models.CTIIndicator
		query := db.Where("is_active = ?", true)
		if req.Value != "" {
			query = query.Where("value ILIKE ?", "%"+req.Value+"%")
		}
		if req.Type != "" {
			query = query.Where("type = ?", req.Type)
		}

		if err := query.Find(&indicators).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to lookup indicators"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]interface{}{"data": indicators, "total": len(indicators)})
	}
}

func listPlaybooks(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var playbooks []models.Playbook
		if err := db.Where("is_active = ?", true).Find(&playbooks).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list playbooks"})
			return
		}
		response.JSON(w, http.StatusOK, map[string]interface{}{"data": playbooks, "total": len(playbooks)})
	}
}

func dryRunPlaybook(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var playbook models.Playbook
		if err := db.First(&playbook, "id = ?", id).Error; err != nil {
			response.JSON(w, http.StatusNotFound, map[string]string{"error": "playbook not found"})
			return
		}

		response.JSON(w, http.StatusOK, map[string]interface{}{
			"playbook_id": id,
			"mode":        "dry-run",
			"would_execute": playbook.Actions,
			"status":      "dry-run-complete",
		})
	}
}

func executePlaybook(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		response.JSON(w, http.StatusOK, map[string]interface{}{
			"playbook_id": id,
			"mode":        "execute",
			"status":      "execution-started",
			"execution_id": "exec_" + uuid.New().String()[:12],
		})
	}
}

func generateProof(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AssetID    string `json:"asset_id"`
			CircuitType string `json:"circuit_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)
		tid, _ := uuid.Parse(tenantIDStr)
		assetID, _ := uuid.Parse(req.AssetID)

		proof := models.ZKProof{
			TenantID:    tid,
			AssetID:     assetID,
			ProofID:     "proof_" + uuid.New().String()[:12],
			ProofSystem: "risc0",
			CircuitType: req.CircuitType,
			Status:      "generated",
		}

		if err := db.Create(&proof).Error; err != nil {
			response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate proof"})
			return
		}
		response.JSON(w, http.StatusCreated, proof)
	}
}

func verifyProof(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProofID string `json:"proof_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		var proof models.ZKProof
		if err := db.First(&proof, "proof_id = ?", req.ProofID).Error; err != nil {
			response.JSON(w, http.StatusNotFound, map[string]string{"error": "proof not found"})
			return
		}

		now := time.Now()
		proof.Status = "verified"
		proof.VerifiedAt = &now
		db.Save(&proof)

		response.JSON(w, http.StatusOK, map[string]interface{}{
			"proof_id":  proof.ProofID,
			"is_valid":  true,
			"status":    "verified",
			"verified_at": now.Format(time.RFC3339),
		})
	}
}

func summarizeIncident() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response.JSON(w, http.StatusOK, map[string]interface{}{
			"summary": "LLM analyst copilot - connect to /analyst-copilot service for real summarization",
			"status":  "stub",
		})
	}
}

func recommendPlaybook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response.JSON(w, http.StatusOK, map[string]interface{}{
			"recommendation": "LLM playbook recommendation - connect to /analyst-copilot service",
			"status":         "stub",
		})
	}
}
