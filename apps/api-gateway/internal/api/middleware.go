package api

import (
	"context"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/config"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/models"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway/internal/pkg/response"
)

type contextKey string

const (
	UserIDKey    contextKey = "user_id"
	TenantIDKey  contextKey = "tenant_id"
	RoleKey      contextKey = "role"
	RequestIDKey contextKey = "request_id"
)

type wrapWriter struct {
	http.ResponseWriter
	code int
}

func (w *wrapWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &wrapWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.code,
			"duration", time.Since(start).String(),
			"ip", r.RemoteAddr,
		)
	})
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "300")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = time.Now().Format("20060102150405") + "-" + randString(8)
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), RequestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func AuthMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				response.JSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authorization header"})
				return
			}
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				response.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization format"})
				return
			}
			token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(cfg.JWTSecret), nil
			})
			if err != nil || !token.Valid {
				response.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
				return
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				response.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token claims"})
				return
			}
			ctx := context.WithValue(r.Context(), UserIDKey, claims["sub"])
			ctx = context.WithValue(ctx, TenantIDKey, claims["tenant_id"])
			ctx = context.WithValue(ctx, RoleKey, claims["role"])
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := r.Context().Value(TenantIDKey).(string)
		if !ok || tenantID == "" {
			response.JSON(w, http.StatusForbidden, map[string]string{"error": "tenant context required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RateLimitMiddleware(rdb *redis.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			key := "ratelimit:" + ip
			ctx := context.Background()
			count, err := rdb.Incr(ctx, key).Result()
			if err != nil {
				slog.Error("rate limit error", "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if count == 1 {
				rdb.Expire(ctx, key, time.Minute)
			}
			if count > 100 {
				w.Header().Set("Retry-After", "60")
				response.JSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func AuditMiddleware(db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &wrapWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rw, r)

			go func() {
				userIDStr, _ := r.Context().Value(UserIDKey).(string)
				tenantIDStr, _ := r.Context().Value(TenantIDKey).(string)

				entry := models.AuditLog{
					Action:     r.Method + " " + r.URL.Path,
					Resource:   r.URL.Path,
					RequestIP:  r.RemoteAddr,
					UserAgent:  r.UserAgent(),
					StatusCode: rw.code,
				}

				if uid, err := uuid.Parse(userIDStr); err == nil {
					entry.UserID = &uid
				}
				if tid, err := uuid.Parse(tenantIDStr); err == nil {
					entry.TenantID = &tid
				}

				db.Create(&entry)
			}()
		})
	}
}

func RecovererMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "error", rec)
				response.JSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
