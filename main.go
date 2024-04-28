package main

import (
	"context"
	"jj/router"
	"log"
	"net/http"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	constr := os.Getenv("MONGO_URI")
	user := os.Getenv("MONGO_USER")
	password := os.Getenv("MONGO_PASSWORD")
	db := os.Getenv("MONGO_DATABASE")
	secret := os.Getenv("JWT_SECRET")
	logger := log.New(os.Stdout, "auth ", log.Default().Flags())
	logger.Println("Логгер создан")
	rts, bl, err := InitMongo(constr, user, password, db)
	if err != nil {
		logger.Fatalln(err.Error())
	}
	logger.Println("Подключение успешно")
	mux := router.SetupMux(logger, rts, bl, secret)
	logger.Println("Mux создан")
	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		logger.Fatalln(err.Error())
	}
}

func InitMongo(constr string, user string, password string, db string) (rts *mongo.Collection, bl *mongo.Collection, err error) {
	credential := options.Credential{
		AuthMechanism: "SCRAM-SHA-256",
		AuthSource:    db,
		Username:      user,
		Password:      password,
	}

	m, err := mongo.Connect(context.Background(), options.Client().ApplyURI(constr).SetAuth(credential))
	if err != nil {
		return
	}

	rts = m.Database(db).Collection("RT")
	bl = m.Database(db).Collection("Blocklist")
	return
}
