[![Build Status](https://travis-ci.org/OpenBazaar/zcash-light.svg?branch=master)](https://travis-ci.org/OpenBazaar/zcash-light)
[![Coverage Status](https://coveralls.io/repos/github/OpenBazaar/zcash-light/badge.svg?branch=master)](https://coveralls.io/github/OpenBazaar/zcash-light?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/OpenBazaar/zcash-light)](https://goreportcard.com/report/github.com/OpenBazaar/zcash-light)

# zcash-light

Lightweight Zcash API-wallet library in Go. It connects to an Insight API endpoint to fetch and send transactions.

Library Usage:

```go
// Create a new config
config := zcash.Config{}

// Select network
config.Params = &chaincfg.TestNet3Params

// Select wallet datastore
sqliteDatastore, _ := db.Create(config.RepoPath)
config.DB = sqliteDatastore

// Create the wallet
wallet, _ := zcash.NewWallet(config)

// Start it!
go wallet.Start()
```

The wallet implements the interface from github.com/OpenBazaar/wallet-interface
