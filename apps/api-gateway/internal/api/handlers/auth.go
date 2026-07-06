package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/config"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/models"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/pkg/response"
)

type AuthHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewAuthHandler(db *gorm.DB, cfg *config.Config) *AuthHandler {
	return &AuthHandler{db: db, cfg: cfg}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		response.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		response.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	tenantID := ""
	if user.TenantID != nil {
		tenantID = user.TenantID.String()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       user.ID.String(),
		"email":     user.Email,
		"role":      user.Role,
		"tenant_id": tenantID,
		"exp":       time.Now().Add(time.Duration(h.cfg.JWTExpiryHours) * time.Hour).Unix(),
		"iss":       h.cfg.JWTIssuer,
	})

	tokenString, err := token.SignedString([]byte(h.cfg.JWTSecret))
	if err != nil {
		response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"token": tokenString,
		"user": map[string]interface{}{
			"id":    user.ID.String(),
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
		return
	}

	user := models.User{
		ID:           uuid.New(),
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Role:         "analyst",
	}

	if err := h.db.Create(&user).Error; err != nil {
		response.JSON(w, http.StatusConflict, map[string]string{"error": "email already exists"})
		return
	}

	response.JSON(w, http.StatusCreated, map[string]interface{}{
		"id":    user.ID.String(),
		"email": user.Email,
		"role":  user.Role,
	})
}
