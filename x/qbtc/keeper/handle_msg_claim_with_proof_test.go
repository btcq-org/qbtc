package keeper_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"cosmossdk.io/math"
	storetypes "cosmossdk.io/store/types"
	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	module "github.com/btcq-org/qbtc/x/qbtc/module"
	qbtctestutil "github.com/btcq-org/qbtc/x/qbtc/testutil"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/cometbft/cometbft/crypto/mldsa"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testChainID is the chain ID used for testing
const testChainID = "qbtc-test-1"

// claimTestFixture contains all dependencies for claim tests
type claimTestFixture struct {
	ctx           sdk.Context
	keeper        *keeper.Keeper
	stakingKeeper *qbtctestutil.MockStakingKeeper
	bankKeeper    *qbtctestutil.MockBankKeeper
	authKeeper    *qbtctestutil.MockAuthKeeper
	prover        *zk.Prover
	claimerAddr   string
	addressHash   [20]byte
	btcPrivKey    *btcec.PrivateKey
}

// setupClaimTest initializes the test environment with ZK verifier
func setupClaimTest(t *testing.T) *claimTestFixture {
	t.Helper()

	// Setup ZK circuit (TSS-compatible)
	setup, err := zk.SetupWithOptions(zk.TestSetupOptions())
	require.NoError(t, err, "ZK circuit setup should succeed")

	vkBytes, err := zk.SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err, "VK serialization should succeed")

	err = zk.RegisterVerifier(vkBytes)
	if err != nil && !errors.Is(err, zk.ErrVerifierAlreadyInitialized) {
		t.Fatalf("verifier registration failed: %v", err)
	}

	prover := zk.ProverFromSetup(setup)

	// Initialize SDK config
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	sdk.GetConfig().SetBech32PrefixForValidator(common.AccountAddressPrefix+sdk.PrefixValidator, common.AccountAddressPrefix+sdk.PrefixPublic)

	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	addressCodec := addresscodec.NewBech32Codec(common.AccountAddressPrefix)
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)

	storeService := runtime.NewKVStoreService(storeKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx
	ctx = ctx.WithChainID(testChainID)

	ctrl := gomock.NewController(t)

	stakingKeeper := qbtctestutil.NewMockStakingKeeper(ctrl)
	validatorPrivKey := mldsa.GenPrivKey()
	pubKey := validatorPrivKey.PubKey()
	pKey, err := codec.FromCmtPubKeyInterface(pubKey)
	require.NoError(t, err)
	validator, err := stakingtypes.NewValidator("", pKey, stakingtypes.Description{})
	require.NoError(t, err)
	validator.Status = stakingtypes.Bonded
	validator.Tokens = math.NewInt(1000000000)

	stakingKeeper.EXPECT().GetLastTotalPower(gomock.Any()).AnyTimes().Return(math.NewInt(1000000), nil)
	stakingKeeper.EXPECT().GetValidator(gomock.Any(), gomock.Any()).AnyTimes().Return(validator, nil)
	stakingKeeper.EXPECT().PowerReduction(gomock.Any()).AnyTimes().Return(math.NewInt(1000))

	authKeeper := qbtctestutil.NewMockAuthKeeper(ctrl)
	bankKeeper := qbtctestutil.NewMockBankKeeper(ctrl)

	k := keeper.NewKeeper(
		storeService,
		encCfg.Codec,
		addressCodec,
		stakingKeeper,
		bankKeeper,
		authKeeper,
		govtypes.ModuleName,
	)

	// Create claimer address
	claimerAddr := qbtctestutil.GetRandomBTCQAddress()

	privateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err, "should create new private key")

	// Compute the address hash from test private key
	addressHash, err := zk.PrivateKeyToAddressHash(privateKey)
	require.NoError(t, err, "should compute address hash")

	return &claimTestFixture{
		ctx:           ctx,
		keeper:        k,
		stakingKeeper: stakingKeeper,
		bankKeeper:    bankKeeper,
		authKeeper:    authKeeper,
		prover:        prover,
		claimerAddr:   claimerAddr,
		addressHash:   addressHash,
		btcPrivKey:    privateKey,
	}
}

type publicInput struct {
	MessageHash     [32]byte
	AddressHash     [20]byte
	BTCQAddressHash [32]byte
}

// generateProof generates a ZK proof for the test fixture's claimer
func (f *claimTestFixture) generateProof(t *testing.T) ([]byte, publicInput) {
	t.Helper()

	btcqAddressHash := zk.HashBTCQAddress(f.claimerAddr)
	chainIDHash := zk.ComputeChainIDHash(testChainID)

	// Compute the claim message that needs to be signed
	messageHash := zk.ComputeClaimMessage(f.addressHash, btcqAddressHash, chainIDHash)

	// Sign the message with ECDSA (simulating what TSS would do)
	sig := ecdsa.Sign(f.btcPrivKey, messageHash[:])

	// Parse R and S from DER-encoded signature
	sigBytes := sig.Serialize()
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]

	// Remove leading zeros (DER uses signed integers)
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	sigR := new(big.Int).SetBytes(rBytes)
	sigS := new(big.Int).SetBytes(sBytes)

	// Get public key coordinates
	pubKey := f.btcPrivKey.PubKey()

	// Generate the ZK proof
	proof, err := f.prover.GenerateProof(zk.ProofParams{
		SignatureR:      sigR,
		SignatureS:      sigS,
		PublicKeyX:      pubKey.X(),
		PublicKeyY:      pubKey.Y(),
		MessageHash:     messageHash,
		AddressHash:     f.addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "proof generation should succeed")

	return proof.ToProtoZKProof(), publicInput{
		MessageHash:     messageHash,
		AddressHash:     f.addressHash,
		BTCQAddressHash: btcqAddressHash,
	}
}

// bitcoinAddressFromHash creates a valid P2PKH Bitcoin address from hash160
// this method is only used in test , so it is ok to panic on error
func bitcoinAddressFromHash(hash [20]byte) string {
	addr, err := zk.Hash160ToP2PKHAddress(hash)
	if err != nil {
		panic(fmt.Sprintf("failed to create Bitcoin address from hash: %v", err))
	}
	return addr
}

// TestClaimWithProof_PartialClaiming tests the partial claiming behavior.
// NOTE: These tests require a working ZK proof generation. If they fail on
// "proof generation should succeed", there's likely a bug in the ZK circuit.
func TestClaimWithProof_PartialClaiming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tests := []struct {
		name           string
		setupUTXOs     func(t *testing.T, f *claimTestFixture)
		utxos          []types.UTXORef
		expectedClaim  uint32
		expectedSkip   uint32
		expectedAmount uint64
		expectErr      bool
		errContains    string
	}{
		{
			name: "all UTXOs match - all claimed",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				btcAddr := bitcoinAddressFromHash(f.addressHash)
				utxo1 := types.UTXO{
					Txid:           "aaaa000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}
				utxo2 := types.UTXO{
					Txid:           "aaaa000000000000000000000000000000000000000000000000000000000002",
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 150000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "aaaa000000000000000000000000000000000000000000000000000000000001-0", utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "aaaa000000000000000000000000000000000000000000000000000000000002-1", utxo2))

				// When recipient is provided, MintCoins uses ModuleName, then SendCoinsFromModuleToAccount
				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(2)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
			utxos: []types.UTXORef{
				{Txid: "aaaa000000000000000000000000000000000000000000000000000000000001", Vout: 0},
				{Txid: "aaaa000000000000000000000000000000000000000000000000000000000002", Vout: 1},
			},
			expectedClaim:  2,
			expectedSkip:   0,
			expectedAmount: 200000000,
			expectErr:      false,
		},
		{
			name: "partial claim - some UTXOs have wrong address",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				btcAddr := bitcoinAddressFromHash(f.addressHash)
				wrongAddr := "1WrongAddressXXXXXXXXXXXXXXXXXXXXX"

				// Matching address - will be claimed
				utxo1 := types.UTXO{
					Txid:           "bbbb000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}
				// Wrong address - will be skipped
				utxo2 := types.UTXO{
					Txid:           "bbbb000000000000000000000000000000000000000000000000000000000002",
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 150000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: wrongAddr},
				}
				// Matching address - will be claimed
				utxo3 := types.UTXO{
					Txid:           "bbbb000000000000000000000000000000000000000000000000000000000003",
					Vout:           2,
					Amount:         300000000,
					EntitledAmount: 250000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}

				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "bbbb000000000000000000000000000000000000000000000000000000000001-0", utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "bbbb000000000000000000000000000000000000000000000000000000000002-1", utxo2))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "bbbb000000000000000000000000000000000000000000000000000000000003-2", utxo3))

				// Only 2 UTXOs should be minted (the matching ones)
				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(2)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
			utxos: []types.UTXORef{
				{Txid: "bbbb000000000000000000000000000000000000000000000000000000000001", Vout: 0},
				{Txid: "bbbb000000000000000000000000000000000000000000000000000000000002", Vout: 1},
				{Txid: "bbbb000000000000000000000000000000000000000000000000000000000003", Vout: 2},
			},
			expectedClaim:  2,
			expectedSkip:   1,
			expectedAmount: 300000000, // 50M + 250M
			expectErr:      false,
		},
		{
			name: "partial claim - some UTXOs not found",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				btcAddr := bitcoinAddressFromHash(f.addressHash)
				utxo1 := types.UTXO{
					Txid:           "cccc000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 75000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}
				// Only set up one UTXO
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "cccc000000000000000000000000000000000000000000000000000000000001-0", utxo1))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			utxos: []types.UTXORef{
				{Txid: "cccc000000000000000000000000000000000000000000000000000000000001", Vout: 0},
				{Txid: "cccc000000000000000000000000000000000000000000000000000000000099", Vout: 0}, // doesn't exist
			},
			expectedClaim:  1,
			expectedSkip:   1,
			expectedAmount: 75000000,
			expectErr:      false,
		},
		{
			name: "partial claim - some UTXOs already claimed",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				btcAddr := bitcoinAddressFromHash(f.addressHash)
				// Claimable UTXO
				utxo1 := types.UTXO{
					Txid:           "dddd000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 80000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}
				// Already claimed (EntitledAmount = 0)
				utxo2 := types.UTXO{
					Txid:           "dddd000000000000000000000000000000000000000000000000000000000002",
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 0,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}

				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "dddd000000000000000000000000000000000000000000000000000000000001-0", utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "dddd000000000000000000000000000000000000000000000000000000000002-1", utxo2))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			utxos: []types.UTXORef{
				{Txid: "dddd000000000000000000000000000000000000000000000000000000000001", Vout: 0},
				{Txid: "dddd000000000000000000000000000000000000000000000000000000000002", Vout: 1},
			},
			expectedClaim:  1,
			expectedSkip:   1,
			expectedAmount: 80000000,
			expectErr:      false,
		},
		{
			name: "no valid UTXOs - error",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				// Don't set up any UTXOs
			},
			utxos: []types.UTXORef{
				{Txid: "eeee000000000000000000000000000000000000000000000000000000000001", Vout: 0},
			},
			expectErr:   true,
			errContains: "no valid claimable UTXOs found",
		},
		{
			name: "mixed scenarios - comprehensive test",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				btcAddr := bitcoinAddressFromHash(f.addressHash)
				wrongAddr := "1WrongAddressYYYYYYYYYYYYYYYYYYYYY"

				// Valid - will be claimed
				utxo1 := types.UTXO{
					Txid:           "ffff000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 40000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}
				// Already claimed - will be skipped
				utxo2 := types.UTXO{
					Txid:           "ffff000000000000000000000000000000000000000000000000000000000002",
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 0,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}
				// Wrong address - will be skipped
				utxo3 := types.UTXO{
					Txid:           "ffff000000000000000000000000000000000000000000000000000000000003",
					Vout:           2,
					Amount:         300000000,
					EntitledAmount: 250000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: wrongAddr},
				}
				// Valid - will be claimed
				utxo4 := types.UTXO{
					Txid:           "ffff000000000000000000000000000000000000000000000000000000000004",
					Vout:           3,
					Amount:         400000000,
					EntitledAmount: 60000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
				}

				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "ffff000000000000000000000000000000000000000000000000000000000001-0", utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "ffff000000000000000000000000000000000000000000000000000000000002-1", utxo2))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "ffff000000000000000000000000000000000000000000000000000000000003-2", utxo3))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "ffff000000000000000000000000000000000000000000000000000000000004-3", utxo4))

				// Only 2 valid UTXOs
				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(2)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
			utxos: []types.UTXORef{
				{Txid: "ffff000000000000000000000000000000000000000000000000000000000001", Vout: 0},
				{Txid: "ffff000000000000000000000000000000000000000000000000000000000002", Vout: 1},
				{Txid: "ffff000000000000000000000000000000000000000000000000000000000003", Vout: 2},
				{Txid: "ffff000000000000000000000000000000000000000000000000000000000004", Vout: 3},
				{Txid: "ffff000000000000000000000000000000000000000000000000000000000099", Vout: 9}, // not found
			},
			expectedClaim:  2,
			expectedSkip:   3,         // already claimed + wrong address + not found
			expectedAmount: 100000000, // 40M + 60M
			expectErr:      false,
		},
	}

	f := setupClaimTest(t)
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			//defer zk.ClearVerifierForTesting()

			// Setup UTXOs for this test
			if tc.setupUTXOs != nil {
				tc.setupUTXOs(st, f)
			}

			// Generate proof
			proofData, publicInput := f.generateProof(st)
			// Create claim message
			msg := &types.MsgClaimWithProof{
				Claimer:         f.claimerAddr,
				Utxos:           tc.utxos,
				Proof:           hex.EncodeToString(proofData),
				MessageHash:     hex.EncodeToString(publicInput.MessageHash[:]),
				AddressHash:     hex.EncodeToString(publicInput.AddressHash[:]),
				QbtcAddressHash: hex.EncodeToString(publicInput.BTCQAddressHash[:]),
			}

			// Execute
			server := keeper.NewMsgServerImpl(f.keeper)
			resp, err := server.ClaimWithProof(f.ctx, msg)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, tc.expectedClaim, resp.UtxosClaimed, "claimed count mismatch")
				assert.Equal(t, tc.expectedSkip, resp.UtxosSkipped, "skipped count mismatch")
				assert.Equal(t, tc.expectedAmount, resp.TotalAmountClaimed, "amount mismatch")
			}
		})
	}
}

// TestClaimWithProof_InvalidProof tests that invalid proofs are rejected
func TestClaimWithProof_InvalidProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f := setupClaimTest(t)
	//defer zk.ClearVerifierForTesting()

	// Set up a valid UTXO
	btcAddr := bitcoinAddressFromHash(f.addressHash)
	utxo := types.UTXO{
		Txid:           "9999000000000000000000000000000000000000000000000000000000000001",
		Vout:           0,
		Amount:         100000000,
		EntitledAmount: 50000000,
		ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "9999000000000000000000000000000000000000000000000000000000000001-0", utxo))

	qbtcAddr := zk.HashBTCQAddress(f.claimerAddr)
	// Create claim with invalid proof data (random bytes)
	msg := &types.MsgClaimWithProof{
		Claimer: f.claimerAddr,
		Utxos: []types.UTXORef{
			{Txid: "9999000000000000000000000000000000000000000000000000000000000001", Vout: 0},
		},
		Proof:           hex.EncodeToString(make([]byte, 500)),
		MessageHash:     hex.EncodeToString(make([]byte, 32)),
		AddressHash:     hex.EncodeToString(make([]byte, 20)),
		QbtcAddressHash: hex.EncodeToString(qbtcAddr[:]),
	}

	server := keeper.NewMsgServerImpl(f.keeper)
	resp, err := server.ClaimWithProof(f.ctx, msg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proof verification failed")
	assert.Nil(t, resp)
}
