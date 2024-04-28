package router

import (
	"context"
	"encoding/json"
	"jj/tokens"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func GetTokensHandler(log *log.Logger, rts *mongo.Collection, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// Проверяем был ли передан GUID
		if !q.Has("guid") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		guid := q.Get("guid")
		// Генерируем токены
		refresh := tokens.GenerateRefreshToken(guid)
		rth, err := tokens.BcryptRefreshToken(refresh)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			return
		}
		insres, err := rts.InsertOne(context.Background(), tokens.NewFromNow(r.Context(), *rth, guid, rts))
		log.Println(*rth)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			return
		}
		access, err := tokens.GenerateAccessToken(guid, insres.InsertedID.(primitive.ObjectID), secret)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			return
		}
		res := tokens.TokenPair{
			AccessToken: access,
			RefreshToken:  refresh,
		}
		br, err := json.Marshal(&res)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(br)
	}
}

func RefreshHandler(rts *mongo.Collection, bl *mongo.Collection, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Этот хандлер не запускается без ATNeeded, так что это гарантировано работает правлиьно
		access := r.Context().Value("Access").(*jwt.Token) 
		jwtid, _ := primitive.ObjectIDFromHex(access.Claims.(*jwt.RegisteredClaims).ID)
		q := r.URL.Query()
		if !q.Has("rt") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Необходим Refresh Token"))
			return
		}
		rt := q.Get("rt")
		rtrec, err := findRTRecord(rts, r.Context(), access)
		err = bcrypt.CompareHashAndPassword([]byte(rtrec.Token), []byte(rt))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Неправильный RT"))
			return
		}
		exptime, _ := access.Claims.GetExpirationTime()
		if exptime.Time.After(time.Now()) {
			_, err := bl.InsertOne(r.Context(), tokens.BlocklistRecord{
				ID: jwtid,
				ExpireOn: exptime.Time,
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Ошибка сервера"))
				return
			}
		}
		newRefresh := tokens.GenerateRefreshToken(rtrec.GUID)
		insres, err := rts.InsertOne(r.Context(), tokens.NewFromNow(r.Context(), newRefresh, rtrec.GUID, rts))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Ошибка сервера"))
			return
		}
		newAccess, err := tokens.GenerateAccessToken(rtrec.GUID, insres.InsertedID.(primitive.ObjectID), secret)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Ошибка сервера"))
			return
		}
		tp := tokens.TokenPair{
			RefreshToken: newRefresh,
			AccessToken: newAccess,
		}
		btp, err := json.Marshal(&tp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Ошибка сервера"))
			return
		}
		rts.DeleteOne(r.Context(), bson.D{{Key: "_id", Value: rtrec.ID}})
		w.WriteHeader(http.StatusOK)
		w.Write(btp)
	}
}

func findRTRecord(rts *mongo.Collection, ctx context.Context, access *jwt.Token) (rtrec *tokens.RefreshTokenRecord, err error) {
	id, _ := primitive.ObjectIDFromHex(access.Claims.(*jwt.RegisteredClaims).ID)
	found := rts.FindOne(ctx, bson.D{{Key: "_id", Value: id}})
	if found.Err() != nil {
		err = found.Err()
		return
	}
	rtrec = new(tokens.RefreshTokenRecord)
	err = found.Decode(&rtrec)
	if err != nil {
		rtrec = nil
		return
	}
	return
}

func GenerateRefreshToken(s string) {
	panic("unimplemented")
}

