package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

const Month = time.Hour * 24 * 30

// Создаёт запись Refresh токена
func NewFromNow(ctx context.Context, token string, guid string, rts *mongo.Collection) (tokrec RefreshTokenRecord) {
	tokrec.ID = primitive.NewObjectID()
	tokrec.ExpireOn = time.Now().Add(Month) 
	tokrec.Token = token
	tokrec.GUID = guid
	return
}

type RefreshTokenRecord struct {
	ID primitive.ObjectID `bson:"_id"`
	Token string `bson:"token"`
	ExpireOn time.Time `bson:"expire_on"`
	GUID string `bson:"guid"`
}

type TokenPair struct {
	AccessToken string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// Запись из коллекции инвалидированных токенов
type BlocklistRecord struct {
	ID primitive.ObjectID `bson:"_id"`
	// Когда токен истечёт, можно будет удалить токен. 
	// Если будет необходимость, можно будет сделать сервис переодической отчистки
	ExpireOn time.Time `bson:"expire_on"` 
}

func GenerateAccessToken(guid string, rtid primitive.ObjectID, secret []byte) (access string, err error) {
	// Устанавливаем время жизни Access токена
	exptime := time.Now().Add(time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
		Subject: guid,
		ExpiresAt: jwt.NewNumericDate(exptime),
		ID: rtid.Hex(),
	})
	access, err = token.SignedString(secret)
	return
}

func GenerateRefreshToken(guid string) (refresh string){
	s := sha256.New()
	randmax := big.NewInt(9999)
	rng, _ := rand.Int(rand.Reader, randmax)
	// Используем время и GUID для создания ключа
	tgbytes := append([]byte(time.Now().Format(time.RFC3339)), []byte(guid)...)
	// добавляем случайное число для уменьшения шанса создания одинаковых ключей
	s.Write(append(tgbytes, rng.Bytes()...))
	sum := s.Sum([]byte{})
	refresh = base64.RawStdEncoding.EncodeToString(sum)
	return
}

func BcryptRefreshToken(token string) (crypted *string, err error) {
	cryptedb, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	crypted = new(string)
	*crypted = string(cryptedb)
	return
}
