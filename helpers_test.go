package zcash

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
)

type FakeDatastore struct {
	utxos          wallet.Utxos
	stxos          wallet.Stxos
	txns           wallet.Txns
	keys           wallet.Keys
	watchedScripts wallet.WatchedScripts
}

func (f *FakeDatastore) Utxos() wallet.Utxos {
	if f.utxos == nil {
		f.utxos = &FakeUtxos{}
	}
	return f.utxos
}

func (f *FakeDatastore) Stxos() wallet.Stxos {
	if f.stxos == nil {
		f.stxos = &FakeStxos{}
	}
	return f.stxos
}

func (f *FakeDatastore) Txns() wallet.Txns {
	if f.txns == nil {
		f.txns = &FakeTxns{}
	}
	return f.txns
}

func (f *FakeDatastore) Keys() wallet.Keys {
	if f.keys == nil {
		f.keys = &FakeKeys{}
	}
	return f.keys
}

func (f *FakeDatastore) WatchedScripts() wallet.WatchedScripts {
	if f.watchedScripts == nil {
		f.watchedScripts = &FakeWatchedScripts{}
	}
	return f.watchedScripts
}

type keyStoreEntry struct {
	scriptAddress []byte
	path          wallet.KeyPath
	used          bool
	key           *btcec.PrivateKey
}

type FakeKeys struct {
	sync.Once
	keys          map[string]*keyStoreEntry
	markKeyAsUsed func(scriptAddress []byte) error
}

func (m *FakeKeys) init() {
	if m.keys == nil {
		m.keys = make(map[string]*keyStoreEntry)
	}
}

func (m *FakeKeys) Put(scriptAddress []byte, keyPath wallet.KeyPath) error {
	m.Do(m.init)
	m.keys[hex.EncodeToString(scriptAddress)] = &keyStoreEntry{scriptAddress, keyPath, false, nil}
	return nil
}

func (m *FakeKeys) ImportKey(scriptAddress []byte, key *btcec.PrivateKey) error {
	m.Do(m.init)
	keyPath := wallet.KeyPath{Purpose: wallet.EXTERNAL, Index: -1}
	m.keys[hex.EncodeToString(scriptAddress)] = &keyStoreEntry{scriptAddress, keyPath, false, key}
	return nil
}

func (m *FakeKeys) MarkKeyAsUsed(scriptAddress []byte) error {
	m.Do(m.init)
	if m.markKeyAsUsed != nil {
		return m.markKeyAsUsed(scriptAddress)
	}
	k, err := m.getEntry(scriptAddress)
	if err != nil {
		return err
	}
	k.used = true
	return nil
}

func (m *FakeKeys) GetLastKeyIndex(purpose wallet.KeyPurpose) (int, bool, error) {
	m.Do(m.init)
	i := -1
	used := false
	for _, key := range m.keys {
		if key.path.Purpose == purpose && key.path.Index > i {
			i = key.path.Index
			used = key.used
		}
	}
	if i == -1 {
		return i, used, errors.New("no saved keys")
	}
	return i, used, nil
}

func (m *FakeKeys) GetPathForKey(scriptAddress []byte) (wallet.KeyPath, error) {
	m.Do(m.init)
	k, err := m.getEntry(scriptAddress)
	if err != nil {
		return wallet.KeyPath{}, err
	}
	return k.path, nil
}

func (m *FakeKeys) GetKey(scriptAddress []byte) (*btcec.PrivateKey, error) {
	m.Do(m.init)
	k, err := m.getEntry(scriptAddress)
	if err != nil {
		return nil, err
	}
	return k.key, nil
}

func (m *FakeKeys) getEntry(scriptAddress []byte) (*keyStoreEntry, error) {
	if k, ok := m.keys[hex.EncodeToString(scriptAddress)]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}

func (m *FakeKeys) GetImported() ([]*btcec.PrivateKey, error) {
	m.Do(m.init)
	var keys []*btcec.PrivateKey
	for _, k := range m.keys {
		if k.path.Index == -1 {
			keys = append(keys, k.key)
		}
	}
	return keys, nil
}

func (m *FakeKeys) GetUnused(purpose wallet.KeyPurpose) ([]int, error) {
	m.Do(m.init)
	var i []int
	for _, key := range m.keys {
		if !key.used && key.path.Purpose == purpose {
			i = append(i, key.path.Index)
		}
	}
	sort.Ints(i)
	return i, nil
}

func (m *FakeKeys) GetAll() ([]wallet.KeyPath, error) {
	m.Do(m.init)
	var kp []wallet.KeyPath
	for _, key := range m.keys {
		kp = append(kp, key.path)
	}
	return kp, nil
}

func (m *FakeKeys) GetLookaheadWindows() map[wallet.KeyPurpose]int {
	m.Do(m.init)
	internalLastUsed := -1
	externalLastUsed := -1
	for _, key := range m.keys {
		if key.path.Purpose == wallet.INTERNAL && key.used && key.path.Index > internalLastUsed {
			internalLastUsed = key.path.Index
		}
		if key.path.Purpose == wallet.EXTERNAL && key.used && key.path.Index > externalLastUsed {
			externalLastUsed = key.path.Index
		}
	}
	internalUnused := 0
	externalUnused := 0
	for _, key := range m.keys {
		if key.path.Purpose == wallet.INTERNAL && !key.used && key.path.Index > internalLastUsed {
			internalUnused++
		}
		if key.path.Purpose == wallet.EXTERNAL && !key.used && key.path.Index > externalLastUsed {
			externalUnused++
		}
	}
	mp := make(map[wallet.KeyPurpose]int)
	mp[wallet.INTERNAL] = internalUnused
	mp[wallet.EXTERNAL] = externalUnused
	return mp
}

type FakeUtxos struct {
	sync.Once
	utxos map[string]wallet.Utxo
}

func (f *FakeUtxos) init() {
	if f.utxos == nil {
		f.utxos = make(map[string]wallet.Utxo)
	}
}

// Put a utxo to the database
func (f *FakeUtxos) Put(utxo wallet.Utxo) error {
	f.Do(f.init)
	f.utxos[utxo.Op.String()] = utxo
	return nil
}

// Fetch all utxos from the db
func (f *FakeUtxos) GetAll() (a []wallet.Utxo, err error) {
	f.Do(f.init)
	for _, u := range f.utxos {
		a = append(a, u)
	}
	return a, nil
}

// Make a utxo unspendable
func (f *FakeUtxos) SetWatchOnly(utxo wallet.Utxo) error {
	f.Do(f.init)
	if u, ok := f.utxos[utxo.Op.String()]; ok {
		u.WatchOnly = true
		f.utxos[utxo.Op.String()] = u
		return nil
	}
	return fmt.Errorf("not found")
}

// Delete a utxo from the db
func (f *FakeUtxos) Delete(utxo wallet.Utxo) error {
	f.Do(f.init)
	delete(f.utxos, utxo.Op.String())
	return nil
}

type FakeStxos struct {
	sync.Once
	stxos map[string]wallet.Stxo
}

func (f *FakeStxos) init() {
	if f.stxos == nil {
		f.stxos = make(map[string]wallet.Stxo)
	}
}

// Put a stxo to the database
func (f *FakeStxos) Put(stxo wallet.Stxo) error {
	f.Do(f.init)
	f.stxos[stxo.Utxo.Op.String()] = stxo
	return nil
}

// Fetch all stxos from the db
func (f *FakeStxos) GetAll() (a []wallet.Stxo, err error) {
	f.Do(f.init)
	for _, s := range f.stxos {
		a = append(a, s)
	}
	return a, nil
}

// Delete a stxo from the db
func (f *FakeStxos) Delete(stxo wallet.Stxo) error {
	f.Do(f.init)
	delete(f.stxos, stxo.Utxo.Op.String())
	return nil
}

type FakeTxns struct {
	sync.Once
	txns map[string]wallet.Txn
}

func (f *FakeTxns) init() {
	if f.txns == nil {
		f.txns = make(map[string]wallet.Txn)
	}
}

// Put a new transaction to the database
func (f *FakeTxns) Put(txn []byte, txid string, value, height int, timestamp time.Time, watchOnly bool) error {
	f.Do(f.init)
	f.txns[txid] = wallet.Txn{
		Txid:      txid,
		Value:     int64(value),
		Height:    int32(height),
		Timestamp: timestamp,
		WatchOnly: watchOnly,
		Bytes:     txn,
	}
	return nil
}

// Fetch a raw tx and it's metadata given a hash
func (f *FakeTxns) Get(txid chainhash.Hash) (wallet.Txn, error) {
	f.Do(f.init)
	if t, ok := f.txns[txid.String()]; ok {
		return t, nil
	}
	return wallet.Txn{}, fmt.Errorf("not found")
}

// Fetch all transactions from the db
func (f *FakeTxns) GetAll(includeWatchOnly bool) (a []wallet.Txn, err error) {
	f.Do(f.init)
	for _, t := range f.txns {
		if !includeWatchOnly && t.WatchOnly {
			continue
		}
		a = append(a, t)
	}
	return a, nil
}

// Update the height of a transaction
func (f *FakeTxns) UpdateHeight(txid chainhash.Hash, height int) error {
	f.Do(f.init)
	if t, ok := f.txns[txid.String()]; ok {
		t.Height = int32(height)
		f.txns[txid.String()] = t
		return nil
	}
	return fmt.Errorf("not found")
}

// Delete a transactions from the db
func (f *FakeTxns) Delete(txid *chainhash.Hash) error {
	f.Do(f.init)
	delete(f.txns, txid.String())
	return nil
}

type FakeWatchedScripts struct {
	sync.Once
	sync.Mutex
	scripts map[string][]byte
}

func (f *FakeWatchedScripts) init() {
	if f.scripts == nil {
		f.scripts = make(map[string][]byte)
	}
}

func (f *FakeWatchedScripts) Put(scriptPubKey []byte) error {
	f.Do(f.init)
	f.scripts[hex.EncodeToString(scriptPubKey)] = scriptPubKey
	return nil
}

func (f *FakeWatchedScripts) GetAll() ([][]byte, error) {
	f.Do(f.init)
	var found [][]byte
	for _, s := range f.scripts {
		found = append(found, s)
	}
	return found, nil
}

func (f *FakeWatchedScripts) Delete(scriptPubKey []byte) error {
	f.Do(f.init)
	delete(f.scripts, hex.EncodeToString(scriptPubKey))
	return nil
}

type FakeInsightClient struct {
	getInfo           func() (*client.Info, error)
	getLatestBlock    func() (*client.Block, error)
	getBlocksBefore   func(time.Time, int) (*client.BlockList, error)
	getTransactions   func(addrs []btcutil.Address) ([]client.Transaction, error)
	getRawTransaction func(txid string) ([]byte, error)
	blockNotify       func() <-chan client.Block
	transactionNotify func() <-chan client.Transaction
	broadcast         func(tx []byte) (string, error)
	estimateFee       func(nbBlocks int) (int, error)
	listenAddress     func(addr btcutil.Address)
	close             func()
}

func (f *FakeInsightClient) GetInfo() (*client.Info, error) {
	if f.getInfo == nil {
		return &client.Info{
			ProtocolVersion: OverwinterProtocolVersion - 1,
		}, nil
	}
	return f.getInfo()
}

func (f *FakeInsightClient) GetLatestBlock() (*client.Block, error) {
	if f.getLatestBlock == nil {
		panic("not implemented")
	}
	return f.getLatestBlock()
}

func (f *FakeInsightClient) GetBlocksBefore(t time.Time, limit int) (*client.BlockList, error) {
	if f.getBlocksBefore == nil {
		panic("not implemented")
	}
	return f.getBlocksBefore(t, limit)
}

func (f *FakeInsightClient) GetTransactions(addrs []btcutil.Address) ([]client.Transaction, error) {
	if f.getTransactions == nil {
		panic("not implemented")
	}
	return f.getTransactions(addrs)
}

func (f *FakeInsightClient) GetRawTransaction(txid string) ([]byte, error) {
	if f.getRawTransaction == nil {
		panic("not implemented")
	}
	return f.getRawTransaction(txid)
}

func (f *FakeInsightClient) BlockNotify() <-chan client.Block {
	if f.blockNotify == nil {
		return nil
	}
	return f.blockNotify()
}

func (f *FakeInsightClient) TransactionNotify() <-chan client.Transaction {
	if f.transactionNotify == nil {
		return nil
	}
	return f.transactionNotify()
}

func (f *FakeInsightClient) Broadcast(tx []byte) (string, error) {
	if f.broadcast == nil {
		panic("not implemented")
	}
	return f.broadcast(tx)
}

func (f *FakeInsightClient) ListenAddress(addr btcutil.Address) {
	if f.listenAddress != nil {
		f.listenAddress(addr)
	}
}

func (f *FakeInsightClient) EstimateFee(nbBlocks int) (int, error) {
	if f.estimateFee == nil {
		panic("not implemented")
	}
	return f.estimateFee(nbBlocks)
}

func (f *FakeInsightClient) Close() {
	if f.close != nil {
		f.close()
	}
}
