package zcash

import (
	"testing"
	"time"

	"github.com/OpenBazaar/multiwallet/keys"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	b39 "github.com/tyler-smith/go-bip39"
)

func TestTxStoreIngestAddsTxnsToDB(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}

	txn := &Transaction{
		Version: 1,
		Inputs:  []Input{{}},
		Outputs: []Output{
			{Value: 123400000, ScriptPubKey: nil},
		},
	}
	config.DB.Stxos().Put(wallet.Stxo{SpendTxid: txn.TxHash()})
	if _, err := txStore.Ingest(txn, nil, 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Errorf("Expected 1 txn, got: %d", len(txns))
	}
}

func TestTxStoreIngestIgnoresDuplicates(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}

	txn := &Transaction{
		Version: 1,
		Inputs:  []Input{{}},
		Outputs: []Output{{}},
	}
	config.DB.Stxos().Put(wallet.Stxo{SpendTxid: txn.TxHash()})
	for i := 0; i < 2; i++ {
		if _, err := txStore.Ingest(txn, nil, 1, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Errorf("Expected 1 txn, got: %d", len(txns))
	}
}

func TestTxStoreIngestIgnoresUnconfirmedDoubleSpends(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address, err := KeyToAddress(keys[0], config.Params)
	if err != nil {
		t.Fatal(err)
	}
	script, err := PayToAddrScript(address)
	if err != nil {
		t.Fatal(err)
	}

	receivedTxid, _ := chainhash.NewHashFromStr("a")
	existingTxn := &Transaction{
		Version: 1,
		Inputs: []Input{
			{PreviousOutPoint: wire.OutPoint{Hash: *receivedTxid, Index: 0}},
		},
		Outputs: []Output{
			{Value: 123400000, ScriptPubKey: script},
		},
	}
	config.DB.Stxos().Put(wallet.Stxo{SpendTxid: existingTxn.TxHash()})
	if _, err := txStore.Ingest(existingTxn, nil, 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Check our existing txn was added
	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Errorf("Expected 1 txn, got: %d", len(txns))
	}

	txn := &Transaction{
		Version: 1,
		Inputs: []Input{
			{PreviousOutPoint: wire.OutPoint{Hash: *receivedTxid, Index: 0}},
		},
		Outputs: []Output{
			{Value: 123400000, ScriptPubKey: script},
		},
	}
	config.DB.Stxos().Put(wallet.Stxo{SpendTxid: txn.TxHash()})
	if _, err := txStore.Ingest(txn, nil, 11, time.Now()); err != nil {
		t.Fatal(err)
	}

	txns, err = config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Errorf("Expected 1 txn, got: %d", len(txns))
	}
}

func TestTxStoreIngestMarksExistingDoubleSpendsAsDead(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address, err := KeyToAddress(keys[0], config.Params)
	if err != nil {
		t.Fatal(err)
	}
	script, err := PayToAddrScript(address)
	if err != nil {
		t.Fatal(err)
	}
	config.DB.WatchedScripts().Put(script)
	txStore.PopulateAdrs()

	receivedTxid, _ := chainhash.NewHashFromStr("a")
	// Eugh, we need 2 different types here (only one is serializable).
	existingTxn := &Transaction{
		Version: 1,
		Inputs: []Input{
			{PreviousOutPoint: wire.OutPoint{Hash: *receivedTxid, Index: 0}},
		},
		Outputs: []Output{
			{Value: 123400000, ScriptPubKey: script},
		},
	}
	raw, err := existingTxn.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txStore.Ingest(existingTxn, raw, 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Check our existing txn was added
	utxos, err := config.DB.Utxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 {
		t.Errorf("Expected old utxo to have been added")
	}

	txn := &Transaction{
		Version: 1,
		Inputs: []Input{
			{PreviousOutPoint: wire.OutPoint{Hash: *receivedTxid, Index: 0}},
		},
		Outputs: []Output{
			// Doesn't matter as long as it is relevant, and different from the existing
			{Value: 123400001, ScriptPubKey: script},
		},
	}
	raw, err = txn.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txStore.Ingest(txn, raw, 9, time.Now()); err != nil {
		t.Fatal(err)
	}

	utxos, err = config.DB.Utxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 {
		t.Fatalf("Expected 1 utxo to be found, got: %v\n", utxos)
	}
	if outpointsEqual(utxos[0].Op, wire.OutPoint{Hash: existingTxn.TxHash(), Index: 0}) {
		t.Errorf("Expected old utxo to have been removed")
	}
}

func TestTxStoreIngestRejectsInvalidTxns(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}

	expectedErr := ErrTxVersionTooLow.Error()
	txn := &Transaction{Version: 0, Inputs: []Input{{}}, Outputs: []Output{{}}}
	if _, err := txStore.Ingest(txn, nil, 1, time.Now()); err == nil {
		t.Errorf("Did not reject invalid txn")
	} else if err.Error() != expectedErr {
		t.Errorf("Expected %q error, got: %q", expectedErr, err.Error())
	}
}

func TestTxStoreIngestUpdatesUtxos(t *testing.T) {
	var usedKeys int
	config := testConfig(t)
	config.DB.(*FakeDatastore).keys = &FakeKeys{
		markKeyAsUsed: func(scriptAddress []byte) error {
			usedKeys++
			return nil
		},
	}
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address, err := KeyToAddress(keys[0], config.Params)
	if err != nil {
		t.Fatal(err)
	}
	script, err := PayToAddrScript(address)
	if err != nil {
		t.Fatal(err)
	}
	config.DB.WatchedScripts().Put(script)
	txStore.PopulateAdrs()

	txn := &Transaction{
		Version: 1,
		Inputs: []Input{
			{},
		},
		Outputs: []Output{
			{Value: 123400000, ScriptPubKey: script},
		},
	}
	if _, err := txStore.Ingest(txn, nil, 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	utxos, err := config.DB.Utxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 {
		t.Errorf("Expected 1 utxo, got: %d", len(utxos))
	}
}

func TestTxStoreIngestOnlyStoresRelevantTxns(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	// random testnet address
	address, err := DecodeAddress("tmD8E94EC75EbRGWYWAEMU48Gmm1bJmkp3m", config.Params)
	script, err := PayToAddrScript(address)
	if err != nil {
		t.Fatal(err)
	}
	// Don't call PopulateAdrs here, so txstore doesn't know about this address

	txn := &Transaction{
		Version: 1,
		Inputs:  []Input{{}},
		Outputs: []Output{
			{Value: 123400000, ScriptPubKey: script},
		},
	}
	if _, err := txStore.Ingest(txn, nil, 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 0 {
		t.Errorf("Expected txn not to be stored, but got: %v", txns)
	}
}

func TestTxStoreIngestAddsStxos(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address, err := KeyToAddress(keys[0], config.Params)
	if err != nil {
		t.Fatal(err)
	}

	// Set up a previous txn where we received some utxos
	outScript, err := PayToAddrScript(address)
	if err != nil {
		t.Fatal(err)
	}
	prevHash, _ := chainhash.NewHashFromStr("a")
	sequence := uint32(898) // position in the block outputs
	receivedUtxo := wallet.Utxo{
		Op:           wire.OutPoint{*prevHash, sequence},
		AtHeight:     1,
		Value:        1.2345 * 1e8,
		ScriptPubkey: outScript,
		WatchOnly:    false,
	}
	config.DB.Utxos().Put(receivedUtxo)

	burnKey, err := keyManager.GetFreshKey(wallet.EXTERNAL)
	if err != nil {
		t.Fatal(err)
	}
	burnAddress, err := KeyToAddress(burnKey, config.Params)
	if err != nil {
		t.Fatal(err)
	}
	burnScript, err := PayToAddrScript(burnAddress)
	if err != nil {
		t.Fatal(err)
	}
	// Don't call PopulateAdrs here, so txstore doesn't know about this address

	// Ingest the initial stxo-containing txn
	txn := &Transaction{
		Version: 1,
		Inputs: []Input{
			{PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: sequence}},
		},
		Outputs: []Output{
			// Burn some money
			{Value: 110000000, ScriptPubKey: burnScript},
			// Return the change
			{Value: 123450000 - 110000000, ScriptPubKey: outScript},
		},
	}
	if _, err := txStore.Ingest(txn, nil, 5, time.Now()); err != nil {
		t.Fatal(err)
	}

	stxos, err := config.DB.Stxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(stxos) != 1 {
		t.Fatalf("Expected 1 stxo, got: %v", stxos)
	}
	if stxos[0].SpendHeight != 5 {
		t.Errorf("Expected stxo height to be updated, got: %d", stxos[0].SpendHeight)
	}

	utxos, err := config.DB.Utxos().GetAll()
	if err != nil {
		t.Error(err)
	}
	for _, u := range utxos {
		if u.Op.String() == receivedUtxo.Op.String() {
			t.Errorf("Expected matching utxo to have been removed")
			break
		}
	}

	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Fatalf("Expected 1 txn, got: %d", len(txns))
	}
	if txns[0].Value != -110000000 {
		t.Errorf("Expected txn value %d, got: %d", int64(-110000000), txns[0].Value)
	}
}

func TestTxStoreIngestUpdatesStxosHeight(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, wallet.Zcash, KeyToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address, err := KeyToAddress(keys[0], config.Params)
	if err != nil {
		t.Fatal(err)
	}

	// Set up a previous txn where we received some utxos
	outScript, err := PayToAddrScript(address)
	if err != nil {
		t.Fatal(err)
	}
	config.DB.WatchedScripts().Put(outScript)
	txStore.PopulateAdrs()

	burnKey, err := keyManager.GetFreshKey(wallet.EXTERNAL)
	if err != nil {
		t.Fatal(err)
	}
	burnAddress, err := KeyToAddress(burnKey, config.Params)
	if err != nil {
		t.Fatal(err)
	}
	burnScript, err := PayToAddrScript(burnAddress)
	if err != nil {
		t.Fatal(err)
	}
	// Don't call PopulateAdrs here, so txstore doesn't know about this address

	// Ingest the new stxo-containing txn
	prevHash, _ := chainhash.NewHashFromStr("a")
	sequence := uint32(898) // position in the block outputs
	txn := &Transaction{
		Version: 1,
		Inputs: []Input{
			{PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: sequence}},
		},
		Outputs: []Output{
			// Burn some money
			{Value: 110000000, ScriptPubKey: burnScript},
			// Return the change
			{Value: 123450000 - 110000000, ScriptPubKey: outScript},
		},
	}
	existingStxo := wallet.Stxo{
		SpendHeight: 0,
		SpendTxid:   txn.TxHash(),
		Utxo: wallet.Utxo{
			Op:           wire.OutPoint{*prevHash, sequence},
			AtHeight:     1,
			Value:        123450000,
			ScriptPubkey: outScript,
			WatchOnly:    true,
		},
	}
	if err := config.DB.Stxos().Put(existingStxo); err != nil {
		t.Fatal(err)
	}

	if _, err := txStore.Ingest(txn, nil, 5, time.Now()); err != nil {
		t.Fatal(err)
	}

	stxos, err := config.DB.Stxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(stxos) != 1 {
		t.Fatalf("Expected 1 stxo, got: %v", stxos)
	}
	if stxos[0].SpendHeight != 5 {
		t.Errorf("Expected stxo height to be updated, got: %d", stxos[0].SpendHeight)
	}
}
