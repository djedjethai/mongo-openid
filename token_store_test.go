package mongo

import (
	"context"
	"github.com/djedjethai/go-oauth2-openid/models"
	. "github.com/smartystreets/goconvey/convey"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
	"time"
)

func clearTokenEntries(ts *TokenStore, collection string) error {
	c := ts.getClient()

	_, err := c.Database(ts.tcfg.storeConfig.db).Collection(collection).DeleteMany(context.TODO(), bson.D{})
	if err != nil {
		return err
	}
	return nil
}

func countTokenEntries(ts *TokenStore, collection string) (int, error) {
	c := ts.getClient()

	count, err := c.Database(ts.tcfg.storeConfig.db).Collection(collection).CountDocuments(context.TODO(), bson.D{})
	if err != nil {
		return -1, err
	}
	return int(count), nil
}

// shut the the down the database, test should fail within a second
func TestTokenStoreWithTimeout(t *testing.T) {
	Convey("Test mongodb token store", t, func() {

		storeConfig := NewStoreConfig(1, 5)

		var store *TokenStore
		if !isReplicaSet {
			store = NewTokenStore(NewConfigNonReplicaSet(url, dbName, username, password, service), storeConfig)
		} else {
			store = NewTokenStore(NewConfigReplicaSet(url, dbName), storeConfig)
		}

		Convey("Test authorization code store", func() {
			info := &models.Token{
				ClientID:      "1",
				UserID:        "1_1",
				RedirectURI:   "http://localhost/",
				Scope:         "all",
				Code:          "11_11_11",
				CodeCreateAt:  time.Now(),
				CodeExpiresIn: time.Second * 5,
			}
			err := store.Create(context.TODO(), info)
			So(err, ShouldBeNil)

			cinfo, err := store.GetByCode(context.TODO(), info.Code)
			So(err, ShouldBeNil)
			So(cinfo.GetUserID(), ShouldEqual, info.UserID)

			err = store.RemoveByCode(context.TODO(), cinfo.GetCode())
			So(err, ShouldBeNil)

			cinfo, err = store.GetByCode(context.TODO(), info.Code)
			So(err, ShouldBeNil)
			So(cinfo, ShouldBeNil)
		})

		Convey("Test access token store", func() {
			info := &models.Token{
				ClientID:        "1",
				UserID:          "1_1",
				RedirectURI:     "http://localhost/",
				Scope:           "all",
				Access:          "1_1_1",
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 5,
			}
			err := store.Create(context.TODO(), info)
			So(err, ShouldBeNil)

			ainfo, err := store.GetByAccess(context.TODO(), info.GetAccess())
			So(err, ShouldBeNil)
			So(ainfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByAccess(context.TODO(), info.GetAccess())
			So(err, ShouldBeNil)

			ainfo, err = store.GetByAccess(context.TODO(), info.GetAccess())
			So(err.Error(), ShouldEqual, "mongo: no documents in result")
			So(ainfo, ShouldBeNil)

			// cleanup, clear all basicTokens
			// NOTE that in this case the basicToken remains in the db
			err = clearTokenEntries(store, store.tcfg.BasicCName)
			So(err, ShouldBeNil)

		})

		Convey("Test refresh token store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(context.TODO(), info)
			So(err, ShouldBeNil)

			rinfo, err := store.GetByRefresh(context.TODO(), info.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByRefresh(context.TODO(), info.GetRefresh())
			So(err, ShouldBeNil)

			rinfo, err = store.GetByRefresh(context.TODO(), info.GetRefresh())
			So(err.Error(), ShouldEqual, "mongo: no documents in result")
			So(rinfo, ShouldBeNil)

			// cleanup
			err = store.RemoveAllTokensByAccess(context.TODO(), info.GetAccess())
			So(err, ShouldBeNil)
		})
	})
}

func TestTokenStore(t *testing.T) {
	Convey("Test mongodb token store", t, func() {
		var store *TokenStore
		if !isReplicaSet {
			store = NewTokenStore(NewConfigNonReplicaSet(url, dbName, username, password, service))
		} else {
			store = NewTokenStore(NewConfigReplicaSet(url, dbName))
		}

		// by code
		Convey("Test authorization code store", func() {
			info := &models.Token{
				ClientID:      "1",
				UserID:        "1_1",
				RedirectURI:   "http://localhost/",
				Scope:         "all",
				Code:          "11_11_11",
				CodeCreateAt:  time.Now(),
				CodeExpiresIn: time.Second * 5,
			}
			err := store.Create(context.TODO(), info)
			So(err, ShouldBeNil)

			cinfo, err := store.GetByCode(context.TODO(), info.Code)
			So(err, ShouldBeNil)
			So(cinfo.GetUserID(), ShouldEqual, info.UserID)

			err = store.RemoveByCode(context.TODO(), info.Code)
			So(err, ShouldBeNil)

			cinfo, err = store.GetByCode(context.TODO(), info.Code)
			So(err, ShouldBeNil)
			So(cinfo, ShouldBeNil)
		})

		// by access
		Convey("Test access token store", func() {
			info := &models.Token{
				ClientID:        "1",
				UserID:          "1_1",
				RedirectURI:     "http://localhost/",
				Scope:           "all",
				Access:          "1_1_1",
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 5,
			}
			err := store.Create(context.TODO(), info)
			So(err, ShouldBeNil)

			ainfo, err := store.GetByAccess(context.TODO(), info.GetAccess())
			So(err, ShouldBeNil)
			So(ainfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByAccess(context.TODO(), info.GetAccess())
			So(err, ShouldBeNil)

			ainfo, err = store.GetByAccess(context.TODO(), info.GetAccess())
			So(err.Error(), ShouldEqual, "mongo: no documents in result")
			So(ainfo, ShouldBeNil)

			// cleanup, clear all basicTokens
			// NOTE that in this case the basicToken remains in the db
			err = clearTokenEntries(store, store.tcfg.BasicCName)
			So(err, ShouldBeNil)

		})

		// by refresh
		Convey("Test refresh token store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(context.TODO(), info)
			So(err, ShouldBeNil)

			rinfo, err := store.GetByRefresh(context.TODO(), info.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByRefresh(context.TODO(), info.GetRefresh())
			So(err, ShouldBeNil)

			rinfo, err = store.GetByRefresh(context.TODO(), info.GetRefresh())
			So(err.Error(), ShouldEqual, "mongo: no documents in result")
			So(rinfo, ShouldBeNil)

			// cleanup
			err = store.RemoveAllTokensByAccess(context.TODO(), info.GetAccess())
			So(err, ShouldBeNil)

		})

	})
}

// // TODO RemoveAllTokensByAccess
// // TODO RemoveAllTokensByRefresh
func TestTokenStoreDeleteTokens(t *testing.T) {
	Convey("Test mongodb token store delete tokens", t, func() {
		var store *TokenStore
		if !isReplicaSet {
			store = NewTokenStore(NewConfigNonReplicaSet(url, dbName, username, password, service))
		} else {
			store = NewTokenStore(NewConfigReplicaSet(url, dbName))
		}

		// by refresh
		Convey("Test the code's refresh token is deleted as well", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(context.TODO(), info)
			So(err, ShouldBeNil)

			rinfo, err := store.GetByRefresh(context.TODO(), info.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveAllTokensByRefresh(context.TODO(), info.GetRefresh())
			So(err, ShouldBeNil)

			rinfo, err = store.GetByRefresh(context.TODO(), info.GetRefresh())
			So(err.Error(), ShouldEqual, "mongo: no documents in result")
			So(rinfo, ShouldBeNil)

			// cleanup
			err = store.RemoveByAccess(context.TODO(), info.GetAccess())
			So(err, ShouldBeNil)
		})

		// multiplicate entries
		Convey("Test set two auth for a single user", func() {
			// make sure the db is empty
			err := clearTokenEntries(store, store.tcfg.BasicCName)
			So(err, ShouldBeNil)

			err = clearTokenEntries(store, store.tcfg.AccessCName)
			So(err, ShouldBeNil)

			err = clearTokenEntries(store, store.tcfg.RefreshCName)
			So(err, ShouldBeNil)

			info1 := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err = store.Create(context.TODO(), info1)
			So(err, ShouldBeNil)

			// user did not signed out and sign in again
			info2 := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_3_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_3_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err = store.Create(context.TODO(), info2)
			So(err, ShouldBeNil)

			rinfo, err := store.GetByAccess(context.TODO(), info1.GetAccess())
			So(err, ShouldBeNil)
			So(rinfo.GetUserID(), ShouldEqual, info1.GetUserID())

			rinfo, err = store.GetByRefresh(context.TODO(), info2.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo.GetUserID(), ShouldEqual, info2.GetUserID())

			err = store.RemoveAllTokensByRefresh(context.TODO(), info2.GetRefresh())
			So(err, ShouldBeNil)

			err = store.RemoveAllTokensByAccess(context.TODO(), info1.GetAccess())
			So(err, ShouldBeNil)

			// make sure all tokens has been removed
			tot, err := countTokenEntries(store, store.tcfg.BasicCName)
			So(tot, ShouldEqual, 0)
			So(err, ShouldBeNil)

			tot, err = countTokenEntries(store, store.tcfg.AccessCName)
			So(tot, ShouldEqual, 0)
			So(err, ShouldBeNil)

			tot, err = countTokenEntries(store, store.tcfg.RefreshCName)
			So(tot, ShouldEqual, 0)
			So(err, ShouldBeNil)

		})

	})
}
