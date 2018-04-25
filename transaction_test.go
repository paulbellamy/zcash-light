package zcash

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/d4l3k/messagediff"
)

func byteSlice32(t *testing.T) (b [32]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func byteSlice64(t *testing.T) (b [64]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSerialization(t *testing.T) {
	now := uint32(time.Now().UTC().Truncate(1 * time.Second).Unix())
	hash, _ := chainhash.NewHashFromStr("a")

	var randomProof [296]byte
	if _, err := rand.Read(randomProof[:]); err != nil {
		t.Fatal(err)
	}

	var randomCiphertexts [2][601]byte
	for _, b := range randomCiphertexts {
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name string
		txn  Transaction
	}{
		{
			name: "empty v1",
			txn: Transaction{
				Version: 1,
				Inputs:  []Input{{}},
				Outputs: []Output{},
			},
		},
		{
			name: "v1",
			txn: Transaction{
				Version:  1,
				LockTime: now,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{*hash, 1}, SignatureScript: []byte("signatureScript"), Sequence: 9},
				},
				Outputs: []Output{
					{Value: 1234, ScriptPubKey: []byte("scriptPubKey")},
				},
			},
		},
		{
			name: "v2",
			txn: Transaction{
				Version:  2,
				LockTime: now,
				Inputs:   []Input{},
				Outputs:  []Output{},
				JoinSplits: []JoinSplit{
					{
						VPubOld:      1234,
						VPubNew:      5678,
						Anchor:       byteSlice32(t),
						Nullifiers:   [2][32]byte{byteSlice32(t), byteSlice32(t)},
						Commitments:  [2][32]byte{byteSlice32(t), byteSlice32(t)},
						EphemeralKey: byteSlice32(t),
						RandomSeed:   byteSlice32(t),
						Macs:         [2][32]byte{byteSlice32(t), byteSlice32(t)},
						Proof:        randomProof,
						Ciphertexts:  randomCiphertexts,
					},
				},
				JoinSplitPubKey:    byteSlice32(t),
				JoinSplitSignature: byteSlice64(t),
			},
		},
		{
			name: "overwinter",
			txn: Transaction{
				IsOverwinter:   true,
				Version:        3,
				VersionGroupID: OverwinterVersionGroupID,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{*hash, 1}, SignatureScript: []byte("signatureScript"), Sequence: 9},
				},
				Outputs: []Output{
					{Value: 1234, ScriptPubKey: []byte("scriptPubKey")},
				},
			},
		},
		{
			name: "overwinter with expiry",
			txn: Transaction{
				IsOverwinter:   true,
				Version:        3,
				VersionGroupID: OverwinterVersionGroupID,
				LockTime:       now,
				ExpiryHeight:   99,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{*hash, 1}, SignatureScript: []byte("signatureScript"), Sequence: 9},
				},
				Outputs: []Output{
					{Value: 1234, ScriptPubKey: []byte("scriptPubKey")},
				},
			},
		},
		// TODO: nJoinSplit handling
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.txn.MarshalBinary()
			if err != nil {
				t.Fatalf("error encoding transaction: %v", err)
			}

			var got Transaction
			if err := got.UnmarshalBinary(b); err != nil {
				t.Fatalf("error decoding transaction: %v", err)
			}
			if !got.IsEqual(&tc.txn) {
				t.Fatalf("\nExpected: %+v\n     Got: %+v", tc.txn, got)
			}
		})
	}
}

func TestSerializationWithRandomTransactions(t *testing.T) {
	for i := 0; i < 500; i++ {
		nHashType := txscript.SigHashType(rand.Int())
		var consensusBranchID uint32
		if randBool() {
			consensusBranchID = SproutVersionGroupID
		} else {
			consensusBranchID = OverwinterVersionGroupID
		}
		txn := RandomTransaction(t, (nHashType&0x1f) == txscript.SigHashSingle, consensusBranchID)
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			b, err := txn.MarshalBinary()
			if err != nil {
				t.Fatalf("error encoding transaction: %v", err)
			}
			t.Logf("Encoded: %v", hex.EncodeToString(b))
			var got Transaction
			if err := got.UnmarshalBinary(b); err != nil {
				t.Fatalf("error decoding transaction: %v", err)
			}
			if !got.IsEqual(txn) {
				t.Fatalf("\nExpected: %#v\n     Got: %#v", *txn, got)
			}
			diff, equal := messagediff.PrettyDiff(*txn, got)
			if !equal {
				t.Fatalf(diff)
			}
		})
	}
}

func TestTransactionValidate(t *testing.T) {
	for _, tc := range []struct {
		err string
		txn *Transaction
	}{
		{
			err: "transaction version too low",
			txn: &Transaction{Version: 0, Inputs: []Input{{}}, Outputs: []Output{{}}},
		},
		{
			err: "transaction has no inputs",
			txn: &Transaction{Version: 1, Outputs: []Output{{}}},
		},
		{
			err: "transaction has no outputs",
			txn: &Transaction{Version: 1, Inputs: []Input{{}}},
		},
		{
			err: "overwinter transaction version too low",
			txn: &Transaction{IsOverwinter: true, Version: 2, Inputs: []Input{{}}, Outputs: []Output{{}}},
		},
		{
			err: "transaction has unknown version group id",
			txn: &Transaction{IsOverwinter: true, Version: 3, VersionGroupID: 9999, Inputs: []Input{{}}, Outputs: []Output{{}}},
		},
		{
			err: "coinbase transaction has outputs",
			txn: &Transaction{
				Version: 1,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{Index: math.MaxUint32}, SignatureScript: []byte("signatureScript")},
				},
				Outputs: []Output{{}},
			},
		},
		// TODO: nJoinSplit handling
		// TODO: Other rules inherited from Bitcoin
	} {
		t.Run(tc.err, func(t *testing.T) {
			err := tc.txn.Validate()
			if err == nil {
				t.Errorf("Did not reject invalid txn")
			} else if err.Error() != tc.err {
				t.Errorf("Expected %q error, got: %q", tc.err, err.Error())
			}
		})
	}
}

func TestTransactionHash(t *testing.T) {
	for _, tc := range []struct {
		err      string
		raw      string
		expected string
	}{
		{
			err:      "known v1 transaction",
			raw:      "0100000001f46a9e5cffedb9f68c4f8e457cc18b325010ac71ab9e001b17c54f83067d90cf000000006a473044022026036022a59253748421a3f28086d3895825d1e88acd2a77c494a162f19e261a022049187cfc01c3509e9c8a33cd5b7d7424647349ab78ab5c4913e79cf3fe18d491012103a30461296a521162e1043b66bf127241481cf42a4a9abd734dfe6d0d6dc74189feffffff02e5561000000000001976a914844a562e6668ea0c26c72185289985e914163ac788ac76ab0000000000001976a91418cdff2033e706ad21cf7798c62e91037e711caa88ac4fb10400",
			expected: "cc44a449c485847872c54dac7bb5d59cf1c3d3d807b2a5b2d78686a9f72e946d",
		},
	} {
		t.Run(tc.err, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			var txn Transaction
			if err := txn.UnmarshalBinary(raw); err != nil {
				t.Fatal(err)
			}
			hash := txn.TxHash().String()
			if hash != tc.expected {
				t.Errorf("\nExpected: %q\n     Got: %q", tc.expected, hash)
			}
		})
	}
}
