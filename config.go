package mongo

import (
	"crypto/tls"
)

// Config mongodb configuration parameters
type Config struct {
	URL            string
	DB             string
	Username       string
	Password       string
	Service        string
	IsReplicaSet   bool
	MongoTLSConfig *tls.Config
}

// NewConfigNonReplicaSet create mongodb configuration for a non-replicaSet
func NewConfigNonReplicaSet(url, db, username, password, service string, mongoTLSConfig *tls.Config) *Config {
	config := &Config{
		URL:          url,
		DB:           db,
		Username:     username,
		Password:     password,
		Service:      service,
		IsReplicaSet: false,
	}

	if mongoTLSConfig != nil {
		config.MongoTLSConfig = mongoTLSConfig
	}

	return config
}

// NewConfigReplicaSet create mongodb configuration for a ReplicaSet
func NewConfigReplicaSet(url, db string, mongoTLSConfig *tls.Config) *Config {
	config := &Config{
		URL:          url,
		DB:           db,
		IsReplicaSet: true,
	}

	if mongoTLSConfig != nil {
		config.MongoTLSConfig = mongoTLSConfig
	}

	return config
}
