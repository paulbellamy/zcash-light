package zcash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/net/proxy"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	btc "github.com/btcsuite/btcutil"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	b39 "github.com/tyler-smith/go-bip39"
)

func init() {
	newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
		return &FakeInsightClient{
			getTransactions:   func(addrs []btc.Address) ([]client.Transaction, error) { return nil, nil },
			transactionNotify: func() <-chan client.Transaction { return nil },
		}, nil
	}
}

func testConfig(t *testing.T) Config {
	return Config{
		Mnemonic: "",
		Params:   &chaincfg.TestNet3Params,
		DB:       &FakeDatastore{},
		Proxy:    nil,
	}
}

func TestWalletMnemonicDeterminesMasterKey(t *testing.T) {
	// Generate a key, and initialize the wallet with it.
	config1 := testConfig(t)
	config1.Mnemonic = ""
	w1, err := NewWallet(config1)
	if err != nil {
		t.Fatal(err)
	}

	config2 := testConfig(t)
	config2.Mnemonic = "submit daughter wrist uniform slide truck doll couch news word cool tissue obvious panel skull firm hospital wreck bind correct develop pistol short replace"
	w2, err := NewWallet(config2)
	if err != nil {
		t.Fatal(err)
	}

	if w1.MasterPrivateKey().String() == w2.MasterPrivateKey().String() {
		t.Errorf("Mnemonic did not change master private key")
	}

	if w1.MasterPublicKey().String() == w2.MasterPublicKey().String() {
		t.Errorf("Mnemonic did not change master public key")
	}
}

func TestWalletParams(t *testing.T) {
	config := testConfig(t)
	config.Params = &chaincfg.Params{Name: chaincfg.TestNet3Params.Name}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}
	if w.Params() != config.Params {
		t.Errorf(
			"Params() did not return chain cfg params.\nExpected: %v\n     Got: %v",
			config.Params,
			w.Params(),
		)
	}
}

func TestWalletIsDust(t *testing.T) {
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, amount := range []int64{0, 1e2 - 1, 400} {
		t.Run(fmt.Sprint(amount), func(t *testing.T) {
			if !w.IsDust(amount) {
				t.Errorf("Expected IsDust to be true")
			}
		})
	}
	for _, amount := range []int64{(1e3) + 1, 1e4} {
		t.Run(fmt.Sprint(amount), func(t *testing.T) {
			if w.IsDust(amount) {
				t.Errorf("Expected IsDust to be false")
			}
		})
	}
}

func TestWalletCurrencyCodeMainNet(t *testing.T) {
	config := testConfig(t)
	config.Params = &chaincfg.MainNetParams
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	expected := "zec"
	if w.CurrencyCode() != expected {
		t.Errorf(
			"CurrencyCode() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			w.CurrencyCode(),
		)
	}
}

func TestWalletCurrencyCodeTestnet(t *testing.T) {
	expected := "tzec"
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if w.CurrencyCode() != expected {
		t.Errorf(
			"CurrencyCode() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			w.CurrencyCode(),
		)
	}
}

func TestWalletCurrentAddress(t *testing.T) {
	// Generate a key, and initialize the wallet with it.
	config := testConfig(t)
	config.Params = &chaincfg.MainNetParams
	config.Mnemonic = "" // TODO: Set this
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	// Derive the first unused key's address
	_, external, _ := keys.Bip44Derivation(mPrivKey, wallet.Zcash)
	externalChild, _ := external.Child(0)
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	address := w.CurrentAddress(wallet.EXTERNAL)

	if !strings.HasPrefix(fmt.Sprint(address), "t1") || len(fmt.Sprint(address)) != 35 {
		t.Errorf("generated address was not a zcash t-address: %v", address)
	}

	pubkey, _ := externalChild.ECPubKey()
	hash, err := NewAddressPubKeyHash(btc.Hash160(pubkey.SerializeCompressed()), config.Params)
	if err != nil {
		t.Fatal(err)
	}
	expected := hash.EncodeAddress()
	if fmt.Sprint(address) != fmt.Sprint(expected) {
		t.Errorf(
			"CurrentAddress() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			address,
		)
	}
}

func TestWalletNewAddress(t *testing.T) {
	// Generate a key, and initialize the wallet with it.
	config := testConfig(t)
	// markKeyAsUsed, should modify the output of getLastKeyIndex
	unused := 0
	config.DB.(*FakeDatastore).keys = &FakeKeys{
		markKeyAsUsed: func(scriptAddress []byte) error {
			unused++
			return nil
		},
	}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	// Generate some addresses
	addresses := make([]btc.Address, 10)
	for i := 0; i < 10; i++ {
		addresses[i] = w.NewAddress(wallet.EXTERNAL)
	}

	// all addresses should be unique
	addrMap := map[string]struct{}{}
	for _, a := range addresses {
		addrMap[fmt.Sprint(a)] = struct{}{}
	}
	if len(addrMap) != len(addresses) {
		t.Errorf("Found duplicate addresses from NewAddress: %v", addresses)
	}
}

func TestWalletScriptToAddress(t *testing.T) {
	config := testConfig(t)
	config.Params = &chaincfg.MainNetParams
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Test this better
	for _, tc := range []struct {
		name    string
		script  []byte
		address string
		err     error
	}{
		{
			name:    "empty script",
			script:  nil,
			address: "",
			err:     fmt.Errorf("unknown script type"),
		},
		{
			name:    "basic script",
			script:  []byte{0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87},
			address: "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
			err:     nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := w.ScriptToAddress([]byte(tc.script))
			switch {
			case tc.err == nil && err != nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err == nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err != nil && tc.err.Error() != err.Error():
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			}
			if tc.address != "" || address != nil {
				if fmt.Sprint(address) != tc.address {
					t.Errorf("\nExpected: %v\n     Got: %v", tc.address, address)
				}
			}
		})
	}
}

func TestWalletAddressToScript(t *testing.T) {
	config := testConfig(t)
	config.Params = &chaincfg.MainNetParams
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	btcAddr, err := btc.NewAddressPubKeyHash(make([]byte, 20, 20), config.Params)
	if err != nil {
		t.Fatal(err)
	}

	basicAddr, err := w.DecodeAddress("t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		script  []byte
		address btc.Address
		err     error
	}{
		{
			name:    "nil address",
			address: nil,
			script:  nil,
			err:     fmt.Errorf("unable to generate payment script for unsupported address type <nil>"),
		},
		{
			name:    "unsupported address type",
			address: btcAddr,
			script:  nil,
			err:     fmt.Errorf("unable to generate payment script for unsupported address type *btcutil.AddressPubKeyHash"),
		},
		{
			name:    "basic script",
			address: basicAddr,
			script:  []byte{0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87},
			err:     nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script, err := w.AddressToScript(tc.address)
			switch {
			case tc.err == nil && err != nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err == nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err != nil && tc.err.Error() != err.Error():
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			}
			if string(tc.script) != string(script) {
				t.Errorf("\nExpected: %q\n     Got: %q", string(tc.script), string(script))
			}
			if len(script) > 0 {
				gotAddress, err := w.ScriptToAddress(script)
				if err != nil {
					t.Errorf("Unable to check answer: %v", err)
				}
				if fmt.Sprint(gotAddress) != fmt.Sprint(tc.address) {
					t.Errorf("Generated script was not to address %v, was to %v", tc.address, gotAddress)
				}
			}
		})
	}
}

func TestWalletDecodeAddress(t *testing.T) {
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Test this better
	for _, tc := range []struct {
		name    string
		address string
		err     error
	}{
		{
			name:    "empty address",
			address: "",
			err:     fmt.Errorf("decoded address is of unknown format"),
		},
		{
			name:    "basic address",
			address: "tmG2NhraCEiMeaajMjLraFjKVeGP8RWZXz6",
			err:     nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := w.DecodeAddress(tc.address)
			switch {
			case tc.err == nil && err != nil:
				t.Errorf("\nUnexpected error: %v\n             Got: %v", tc.err, err)
			case tc.err != nil && err == nil:
				t.Errorf("\nUnexpected error: %v\n             Got: %v", tc.err, err)
			case tc.err != nil && err != nil && tc.err.Error() != err.Error():
				t.Errorf("\nUnexpected error: %v\n             Got: %v", tc.err, err)
			}

			// re-encoding it should equal the original input
			if address != nil {
				output := address.EncodeAddress()
				if tc.address != output {
					t.Errorf("\nExpected: %v\n     Got: %v", tc.address, address)
				}
			}
		})
	}
}

// TODO: test it ignores watch-only
// TODO: test unconfirmed
func TestWalletBalance(t *testing.T) {
	config := testConfig(t)
	hash1, _ := chainhash.NewHashFromStr("a")
	hash2, _ := chainhash.NewHashFromStr("b")
	config.DB.Utxos().Put(wallet.Utxo{
		Op:       wire.OutPoint{Hash: *hash1},
		AtHeight: 4, // Confirmed
		Value:    1,
	})
	config.DB.Utxos().Put(wallet.Utxo{
		Op:       wire.OutPoint{Hash: *hash2},
		AtHeight: 0, // Unconfirmed
		Value:    2,
	})
	config.DB.Stxos().Put(wallet.Stxo{SpendHeight: 4, SpendTxid: *hash1})
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Close()

	confirmed, unconfirmed := w.Balance()

	expectedConfirmed, expectedUnconfirmed := int64(1), int64(2)
	if confirmed != expectedConfirmed {
		t.Errorf("Confirmed\nExpected: %v\n     Got: %v", expectedConfirmed, confirmed)
	}
	if unconfirmed != expectedUnconfirmed {
		t.Errorf("Unconfirmed\nExpected: %v\n     Got: %v", expectedUnconfirmed, unconfirmed)
	}
}

// TODO: Test ongoing transactions
// TODO: Test race condition of transactions coming in after initial load
func TestWalletTransactionsInitialLoad(t *testing.T) {
	txnChan := make(chan client.Transaction)
	newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
		return &FakeInsightClient{
			getBestBlock: func() (*client.Block, error) { return nil, nil },
			getTransactions: func(addrs []btc.Address) ([]client.Transaction, error) {
				// TODO: Put some txns here
				return []client.Transaction{{Txid: "a"}}, nil
			},
			getRawTransaction: func(txid string) ([]byte, error) { return nil, nil },
			transactionNotify: func() <-chan client.Transaction { return txnChan },
		}, nil
	}
	config := testConfig(t)
	expectedTxns := []wallet.Txn{{Txid: "a"}}
	config.DB.Txns().Put(nil, expectedTxns[0].Txid, 0, 0, time.Time{}, false)
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Close()

	txns, err := w.Transactions()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(txns, expectedTxns) {
		t.Errorf("\nExpected: %v\n     Got: %v", expectedTxns, txns)
	}
}

// TODO: Test initial load of transactions
// TODO: Test ongoing transactions
// TODO: Test race condition of transactions coming in after initial load
func TestWalletChainTip(t *testing.T) {
	var expectedHeight uint32 = 1234
	expectedHash, _ := chainhash.NewHashFromStr("a")
	newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
		return &FakeInsightClient{
			getBestBlock: func() (*client.Block, error) {
				return &client.Block{Hash: expectedHash.String(), Height: int(expectedHeight)}, nil
			},
			getTransactions: func(addrs []btc.Address) ([]client.Transaction, error) {
				// TODO: Put some txns here
				return []client.Transaction{{Txid: "a"}}, nil
			},
			getRawTransaction: func(txid string) ([]byte, error) { return nil, nil },
		}, nil
	}
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Close()

	// Initial blocks are loaded
	blockHeight, blockHash := w.ChainTip()
	if blockHeight != expectedHeight {
		t.Errorf("\nExpected: %v\n     Got: %v", expectedHeight, blockHeight)
	}
	if blockHash.String() != expectedHash.String() {
		t.Errorf("\nExpected: %v\n     Got: %v", expectedHash, blockHash)
	}
}

func TestWalletGetConfirmations(t *testing.T) {
	txHash, _ := chainhash.NewHashFromStr("a")
	blockHash, _ := chainhash.NewHashFromStr("b")
	for _, tc := range []struct {
		name             string
		height, confirms uint32
		err              error
		txns             []client.Transaction
		block            *client.Block
	}{
		{
			name:     "not found",
			height:   0,
			confirms: 0,
			err:      fmt.Errorf("not found"),
			txns:     nil,
			block:    &client.Block{Hash: blockHash.String(), Height: 1234},
		},
		{
			name:     "unconfirmed",
			height:   0,
			confirms: 0,
			txns:     []client.Transaction{{Txid: txHash.String(), BlockHeight: 0}},
			block:    &client.Block{Hash: blockHash.String(), Height: 1234},
		},
		{
			name:     "just confirmed",
			height:   1234,
			confirms: 1,
			txns:     []client.Transaction{{Txid: txHash.String(), BlockHeight: 1234}},
			block:    &client.Block{Hash: blockHash.String(), Height: 1234},
		},
		{
			name:     "confirmed",
			height:   1234,
			confirms: 6,
			txns:     []client.Transaction{{Txid: txHash.String(), BlockHeight: 1234}},
			block:    &client.Block{Hash: blockHash.String(), Height: 1234 + 5},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
				return &FakeInsightClient{
					getBestBlock:      func() (*client.Block, error) { return tc.block, nil },
					getTransactions:   func(addrs []btc.Address) ([]client.Transaction, error) { return tc.txns, nil },
					getRawTransaction: func(txid string) ([]byte, error) { return nil, nil },
				}, nil
			}

			config := testConfig(t)
			// Put the txn to the db
			for _, txn := range tc.txns {
				config.DB.Txns().Put(nil, txn.Txid, 1, txn.BlockHeight, time.Now(), false)
			}

			w, err := NewWallet(config)
			if err != nil {
				t.Fatal(err)
			}
			w.Start()
			defer w.Close()

			// Initial blocks are loaded
			confirms, atHeight, err := w.GetConfirmations(*txHash)
			if fmt.Sprint(tc.err) != fmt.Sprint(err) {
				t.Errorf("\nExpected error: %v\n     Got error: %v", tc.err, err)
			}
			if atHeight != uint32(tc.height) {
				t.Errorf("\nExpected: %v\n     Got: %v", tc.height, atHeight)
			}
			if confirms != uint32(tc.confirms) {
				t.Errorf("\nExpected: %v\n     Got: %v", tc.confirms, confirms)
			}
		})
	}
}

// TODO: Test external insight api error
// TODO: Calculate making change
// TODO: Test unconfirmed utxos are not spent
func TestWalletSpend(t *testing.T) {
	blockHash, _ := chainhash.NewHashFromStr("a")
	var sentTx []byte
	sentTxHash, _ := chainhash.NewHashFromStr("b")
	newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
		return &FakeInsightClient{
			getBestBlock: func() (*client.Block, error) {
				return &client.Block{Hash: blockHash.String(), Height: 1234}, nil
			},
			getTransactions:   func(addrs []btc.Address) ([]client.Transaction, error) { return nil, nil },
			getRawTransaction: func(txid string) ([]byte, error) { return nil, nil },
			broadcast: func(tx []byte) (string, error) {
				sentTx = tx
				return sentTxHash.String(), nil
			},
			estimateFee: func(nbBlocks int) (int, error) { return 1, nil },
		}, nil
	}

	config := testConfig(t)
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Close()

	changeAddress := w.CurrentAddress(wallet.INTERNAL)
	address := w.NewAddress(wallet.EXTERNAL)
	var expectedAmount int64 = 100000
	inputHash, _ := chainhash.NewHashFromStr("c")
	scriptPubkey, err := w.AddressToScript(address)
	if err != nil {
		t.Fatal(err)
	}
	utxo1 := wallet.Utxo{
		Op:           wire.OutPoint{Hash: *inputHash, Index: 0},
		AtHeight:     12,
		Value:        expectedAmount * 3,
		ScriptPubkey: scriptPubkey,
	}
	var expectedChange int64 = utxo1.Value - expectedAmount
	config.DB.Utxos().Put(utxo1)
	config.DB.Utxos().Put(wallet.Utxo{
		Op:           wire.OutPoint{Hash: *inputHash, Index: 1},
		AtHeight:     1000,
		Value:        expectedAmount - 10,
		ScriptPubkey: scriptPubkey,
	})
	txHash, err := w.Spend(expectedAmount, address, wallet.NORMAL)
	if err != nil {
		t.Fatal(err)
	}
	if txHash == nil || txHash.String() != sentTxHash.String() {
		t.Errorf("Expected tx hash %q, got: %q", sentTxHash, txHash)
	}

	// Check the sent txn is valid
	var txn Transaction
	if _, err := txn.ReadFrom(bytes.NewReader(sentTx)); err != nil {
		t.Fatal(err)
	}
	// Check there are inputs
	if len(txn.Inputs) != 1 {
		t.Errorf("Expected 1 inputs, got: %d", len(txn.Inputs))
	} else {
		// Check the input is the expected utxo
		if !txn.Inputs[0].PreviousOutPoint.Hash.IsEqual(&utxo1.Op.Hash) {
			t.Errorf("Expected input txid %q, got input txid: %q", utxo1.Op.Hash.String(), txn.Inputs[0].PreviousOutPoint.Hash.String())
		}
		if txn.Inputs[0].PreviousOutPoint.Index != utxo1.Op.Index {
			t.Errorf("Expected input vout %d, got input vout: %d", utxo1.Op.Index, txn.Inputs[0].PreviousOutPoint.Index)
		}

		// Check the input signature hashes
		expectedPubKeyHash := scriptPubkey[3:23]
		// Check that the signature pubkey we're trying to use hashes to the expected
		disasm, err := txscript.DisasmString(txn.Inputs[0].SignatureScript)
		if err != nil {
			t.Errorf("Invalid signature: %v", err)
		}
		parts := strings.Split(disasm, " ")
		if len(parts) != 2 {
			t.Errorf("Invalid signature: had %d parts", len(parts))
		}
		pkData, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Errorf("Invalid signature: %v", err)
		}
		hash := sha256.Sum256(pkData)
		ripe := ripemd160.New()
		ripe.Write(hash[:])
		got := ripe.Sum(nil)
		if string(expectedPubKeyHash) != string(got) {
			t.Errorf(
				"\nExpected pubkeyhash: %q\n     Got pubkeyhash: %q",
				hex.EncodeToString(expectedPubKeyHash),
				hex.EncodeToString(got),
			)
		}

	}

	if len(txn.Outputs) != 2 {
		t.Errorf("Expected 2 outputs, got: %d", len(txn.Outputs))
	} else {
		// Check main output
		{
			// Check the target is the expected address
			addr, err := w.ScriptToAddress(txn.Outputs[0].ScriptPubKey)
			if err != nil {
				t.Errorf("error converting output script to address: %v", err)
			} else if fmt.Sprint(addr) != fmt.Sprint(address) {
				t.Errorf("Expected output address %v, got %v", address, addr)
			}

			// Check the sum of the output values
			value := txn.Outputs[0].Value
			if value != expectedAmount {
				t.Errorf("Expected amount %d, got outputs: %d", expectedAmount, value)
			}

			// Check the output signature
			/*
				signingKey, err := w.MasterPrivateKey().ECPubKey()
				if err != nil {
					t.Fatal(err)
				}
				txCopy := txn.shallowCopy()
				for i := range txCopy.Inputs {
					// Eugh, because we replace the ScriptSig from the script to the
					// signature, we need an unsigned copy of the txn to verify it. This
					// feels really wrong and needs a refactor... :/
					unsignedScript, err := w.AddressToScript(address)
					if err != nil {
						t.Fatal(err)
					}
					txCopy.Inputs[i].ScriptSig.Hex = hex.EncodeToString(unsignedScript)
				}
				if err := verifySignature(txCopy, signingKey, 0, txn.Inputs[0].ScriptSig.Hex); err != nil {
					t.Error(err)
				}
			*/
		}

		// Check the change output
		{
			// Check the target is our own
			addr, err := w.ScriptToAddress(txn.Outputs[1].ScriptPubKey)
			if err != nil {
				t.Errorf("error converting output script to address: %v", err)
			} else if fmt.Sprint(addr) != fmt.Sprint(changeAddress) {
				t.Errorf("Expected output address %v, got %v", changeAddress, addr)
			}

			// Check the sum of the output values is our expected amount
			value := txn.Outputs[1].Value
			if value != expectedChange {
				t.Errorf("Expected change %d, got change: %d", expectedChange, value)
			}
		}
	}
}

func TestWalletSpendRejectsDustAmounts(t *testing.T) {
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Close()
	address := w.CurrentAddress(wallet.EXTERNAL)
	txHash, err := w.Spend(1, address, wallet.NORMAL)
	expectedError := wallet.ErrorDustAmount
	if err == nil || err != expectedError {
		t.Errorf("Expected error %q, got: %q", expectedError, err)
	}
	if txHash != nil {
		t.Errorf("Expected null tx hash, got: %q", txHash)
	}
}

func TestWalletSpendRejectsInsufficientFunds(t *testing.T) {
	var expectedHeight uint32 = 5
	expectedHash, _ := chainhash.NewHashFromStr("a")
	newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
		return &FakeInsightClient{
			getBestBlock: func() (*client.Block, error) {
				return &client.Block{Hash: expectedHash.String(), Height: int(expectedHeight)}, nil
			},
			getTransactions: func(addrs []btc.Address) ([]client.Transaction, error) { return nil, nil },
			estimateFee:     func(nbBlocks int) (int, error) { return 1, nil },
		}, nil
	}
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Close()

	// Wallet is empty
	address := w.CurrentAddress(wallet.EXTERNAL)
	txHash, err := w.Spend(123400000, address, wallet.NORMAL)
	expectedError := wallet.ErrorInsuffientFunds
	if err == nil || err != expectedError {
		t.Errorf("Expected error %q, got: %q", expectedError, err)
	}
	if txHash != nil {
		t.Errorf("Expected null tx hash, got: %q", txHash)
	}
}
