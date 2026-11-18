package mongo

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	oauth2 "github.com/djedjethai/go-oauth2-openid"
	"github.com/djedjethai/go-oauth2-openid/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TokenConfig token configuration parameters
type TokenConfig struct {
	BasicCName  string
	storeConfig *StoreConfig
}

// NewDefaultTokenConfig create a default token configuration
func NewDefaultTokenConfig(strConfig *StoreConfig) *TokenConfig {
	return &TokenConfig{
		BasicCName:  "oauth2_basic",
		storeConfig: strConfig,
	}
}

// NewTokenStore create a token store instance based on mongodb
func NewTokenStore(cfg *Config, scfgs ...*StoreConfig) (store *TokenStore) {
	clientOptions := options.Client().ApplyURI(cfg.URL)

	// Configure MongoDB TLS
	if cfg.MongoTLSConfig != nil {
		clientOptions.SetTLSConfig(cfg.MongoTLSConfig)
	}

	ctx := context.TODO()
	ctxPing := context.TODO()

	if len(scfgs) > 0 && scfgs[0].connectionTimeout > 0 {
		newCtx, cancel := context.WithTimeout(context.Background(), time.Duration(scfgs[0].connectionTimeout)*time.Second)
		ctx = newCtx
		defer cancel()
		clientOptions.SetConnectTimeout(time.Duration(scfgs[0].connectionTimeout) * time.Second)
	}

	if len(scfgs) > 0 && scfgs[0].requestTimeout > 0 {
		newCtx, cancel := context.WithTimeout(context.Background(), time.Duration(scfgs[0].requestTimeout)*time.Second)
		ctxPing = newCtx
		defer cancel()
		clientOptions.SetConnectTimeout(time.Duration(scfgs[0].requestTimeout) * time.Second)
	}

	if !cfg.IsReplicaSet {
		clientOptions.SetAuth(options.Credential{
			Username: cfg.Username,
			Password: cfg.Password,
		})
	}

	c, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("ClientStore failed to connect mongo: ", err)
	} else {
		log.Println("Connection to mongoDB successful")
	}

	err = c.Ping(ctxPing, nil)
	if err != nil {
		log.Fatal("MongoDB ping failed:", err)
	}

	log.Println("Ping db successfull")

	return NewTokenStoreWithSession(c, cfg, scfgs...)
}

// NewTokenStoreWithSession create a token store instance based on mongodb
func NewTokenStoreWithSession(client *mongo.Client, cfg *Config, scfgs ...*StoreConfig) (store *TokenStore) {
	strCfgs := NewDefaultStoreConfig(cfg.DB, cfg.Service, cfg.IsReplicaSet)

	ts := &TokenStore{
		client: client,
		tcfg:   NewDefaultTokenConfig(strCfgs),
	}

	if len(scfgs) > 0 {
		if scfgs[0].connectionTimeout > 0 {
			ts.tcfg.storeConfig.connectionTimeout = scfgs[0].connectionTimeout
		}
		if scfgs[0].requestTimeout > 0 {
			ts.tcfg.storeConfig.requestTimeout = scfgs[0].requestTimeout
		}
	}

	_, err := ts.client.Database(ts.tcfg.storeConfig.db).Collection(ts.tcfg.BasicCName).Indexes().CreateOne(context.TODO(), mongo.IndexModel{
		Keys: bson.D{{"ExpiredAt", 1}}})
	if err != nil {
		log.Fatalln("Error creating index: ", ts.tcfg.BasicCName, " - ", err)
	}

	store = ts
	return
}

// TokenStore MongoDB storage for OAuth 2.0
type TokenStore struct {
	tcfg   *TokenConfig
	client *mongo.Client
	// txnHandler *transactionHandler
}

func (ts *TokenStore) getClient() *mongo.Client {
	return ts.client
}

// Close close the mongo session
func (ts *TokenStore) Close() {
	if err := ts.client.Disconnect(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func (ts *TokenStore) c(name string) *mongo.Collection {
	return ts.client.Database(ts.tcfg.storeConfig.db).Collection(name)
}

// Create create and store the new token information
func (ts *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) (err error) {

	jv, err := json.Marshal(info)
	if err != nil {
		return
	}

	ctxReq, cancel := ts.tcfg.storeConfig.setRequestContext()
	defer cancel()
	if ctxReq != nil {
		ctx = ctxReq
	}

	// svcName is the serviceName for servers or userEmail for user
	svcName := info.GetUserID()
	if svcName == "" {
		svcName = info.GetClientID()
	}

	aexp := info.GetAccessCreateAt().Add(info.GetAccessExpiresIn())
	rexp := aexp
	if refresh := info.GetRefresh(); refresh != "" {
		rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
		if aexp.Second() > rexp.Second() {
			aexp = rexp
		}
	}

	userEmail := info.GetUserEmail()
	userPassword := info.GetUserPassword()
	userPath := info.GetUserPath()

	// Create the basicData document
	code := info.GetCode()
	if code == "" {
		log.Println("create code entry in database, missing code")
		err = errors.New("create code entry in database, missing code")
		return
	}
	basicData := basicData{
		ID:           code,
		Service:      svcName, // svcName is the userID or clientID
		UserEmail:    userEmail,
		UserPassword: userPassword,
		UserPath:     userPath,
		Data:         jv,
		ExpiredAt:    info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()),
	}

	_, err = ts.c(ts.tcfg.BasicCName).InsertOne(ctx, basicData)
	if err != nil {
		log.Println("Error CreateToken with code: ", err)
	}

	return
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(ctx context.Context, code string) (err error) {
	ctxReq, cancel := ts.tcfg.storeConfig.setRequestContext()
	defer cancel()
	if ctxReq != nil {
		ctx = ctxReq
	}

	_, err = ts.c(ts.tcfg.BasicCName).DeleteOne(ctx, bson.D{{Key: "_id", Value: code}})
	if err != nil {
		log.Println("Error RemoveByCode: ", err)
	}
	return
}

// RemoveByService use the service name to delete the basic, access, refresh
func (ts *TokenStore) RemoveByService(ctx context.Context, svcName string) (err error) {
	ctxReq, cancel := ts.tcfg.storeConfig.setRequestContext()
	defer cancel()

	if ctxReq != nil {
		ctx = ctxReq
	}

	var bd basicData
	err = ts.c(ts.tcfg.BasicCName).FindOne(ctx, bson.D{{Key: "Service", Value: svcName}}).Decode(&bd)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return
		}
		return
	}

	_, err = ts.c(ts.tcfg.BasicCName).DeleteOne(ctx, bson.D{{Key: "_id", Value: bd.ID}})
	if err != nil {
		log.Println("Error RemoveByCode: ", err)
	}

	return
}

func (ts *TokenStore) getData(basicID string) (ti oauth2.TokenInfo, err error) {
	ctx := context.Background()
	ctxReq, cancel := ts.tcfg.storeConfig.setRequestContext()
	defer cancel()
	if ctxReq != nil {
		ctx = ctxReq
	}

	var bd basicData
	err = ts.c(ts.tcfg.BasicCName).FindOne(ctx, bson.D{{Key: "_id", Value: basicID}}).Decode(&bd)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	var tm models.Token
	err = json.Unmarshal(bd.Data, &tm)
	if err != nil {
		return
	}

	ti = &tm

	return
}

func (ts *TokenStore) getBasicID(cname, token string) (basicID string, err error) {
	ctx := context.Background()
	ctxReq, cancel := ts.tcfg.storeConfig.setRequestContext()
	defer cancel()
	if ctxReq != nil {
		ctx = ctxReq
	}

	var td tokenData
	err = ts.c(cname).FindOne(ctx, bson.D{{Key: "_id", Value: token}}).Decode(&td)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return
		}
		return
	}
	basicID = td.BasicID
	return
}

// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(ctx context.Context, code string) (ti oauth2.TokenInfo, err error) {
	ti, err = ts.getData(code)
	return
}

type basicData struct {
	ID           string    `bson:"_id"`
	Service      string    `bson:"Service"` // serverName for server or userID
	UserEmail    string    `bson:"UserEmail"`
	UserPassword string    `bson:"UserPassword"`
	UserPath     string    `bson:"UserPath"`
	Data         []byte    `bson:"Data"`
	ExpiredAt    time.Time `bson:"ExpiredAt"`
}

type tokenData struct {
	ID        string    `bson:"_id"`
	BasicID   string    `bson:"BasicID"`
	ExpiredAt time.Time `bson:"ExpiredAt"`
}
