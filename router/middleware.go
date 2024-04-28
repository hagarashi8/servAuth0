package router

import (
	"context"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func LogMiddleware(log *log.Logger) (func(http.Handler) http.Handler) {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lrw := NewLoggingResponseWriter(w)
			h.ServeHTTP(lrw, r)
			code := lrw.statusCode
			log.Printf("%s %s %d\n", r.Method, r.URL.Path, code)
		})
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func ATNeeded(bl *mongo.Collection, log *log.Logger, secret string) func (h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			at := r.Header.Get("Authorization")
			if at == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Необходим токен доступа для авторизации"))
				return
			}
			if len(at) < 8 {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Неверный Access Токен"))
				return
			}
			if at[:6] != "Bearer" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Неверный метод авторизации"))
				return
			}
			t, err := jwt.ParseWithClaims(at[7:], &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
				return []byte(secret), nil
			})
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Неверный Access Токен"))
				return
			}
			if !t.Valid {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Неверный Access Токен"))
				return
			}
			id, err := primitive.ObjectIDFromHex(t.Claims.(*jwt.RegisteredClaims).ID)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Неверный Access Токен"))
				return
			}
			req := bson.D{{Key: "_id", Value: id}}
			blres := bl.FindOne(r.Context(), req)
			if blres.Err() != mongo.ErrNoDocuments {
				if blres.Err() == nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Access Токен заблокирован"))
				} else {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Ошибка сервера"))
				}
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), "Access", t))
			h.ServeHTTP(w,r)
		})
	}
}
