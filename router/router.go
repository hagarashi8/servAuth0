package router

import (
	"log"
	"net/http"

	"go.mongodb.org/mongo-driver/mongo"
)

func SetupMux(log *log.Logger, rts *mongo.Collection, bl *mongo.Collection, secret string) http.Handler {
	bsecret := []byte(secret)
	logMW := LogMiddleware(log)
	atNeededMW := ATNeeded(bl, log, secret)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token",GetTokensHandler(log, rts, bsecret))
	mux.Handle("GET /refresh", atNeededMW(RefreshHandler(rts, bl, bsecret)))
	return logMW(mux)
}

