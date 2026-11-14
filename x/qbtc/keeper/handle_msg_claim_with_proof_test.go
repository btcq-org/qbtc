package keeper_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	module "github.com/btcq-org/qbtc/x/qbtc/module"
	qbtctestutil "github.com/btcq-org/qbtc/x/qbtc/testutil"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcq-org/qbtc/x/qbtc/zk/zktest"
	"github.com/btcsuite/btcd/btcec/v2"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
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
	btcAddress    string // P2PKH address of btcPrivKey, as stored on the test UTXOs
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

	err = zk.InitializeVerifier(vkBytes)
	if err != nil && !errors.Is(err, zk.ErrVerifierAlreadyInitialized) {
		t.Fatalf("verifier registration failed: %v", err)
	}

	prover := zk.ProverFromSetup(setup)

	// Initialize SDK config
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	sdk.GetConfig().SetBech32PrefixForValidator(common.AccountAddressPrefix+sdk.PrefixValidator, common.AccountAddressPrefix+sdk.PrefixValidator+sdk.PrefixPublic)

	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	addressCodec := addresscodec.NewBech32Codec(common.AccountAddressPrefix)
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)

	storeService := runtime.NewKVStoreService(storeKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx
	ctx = ctx.WithChainID(testChainID)

	ctrl := gomock.NewController(t)

	stakingKeeper := qbtctestutil.NewMockStakingKeeper(ctrl)
	validatorPrivKey := qbtctestutil.MustGenPrivKey()
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
	claimerAddr := qbtctestutil.GetRandomQBTCAddress()

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
		btcAddress:    bitcoinAddressFromHash(addressHash),
		btcPrivKey:    privateKey,
	}
}

// generateProof generates a ZK proof for the test fixture's claimer and
// returns it with the SHA256 of the compressed pubkey the message must carry.
func (f *claimTestFixture) generateProof(t *testing.T) ([]byte, [32]byte) {
	t.Helper()
	return f.generateProofForRecipient(t, f.claimerAddr)
}

// generateProofForRecipient signs the claim message for the given recipient
// the way a wallet would and generates the ZK proof from that signature.
func (f *claimTestFixture) generateProofForRecipient(t *testing.T, recipientAddr string) ([]byte, [32]byte) {
	t.Helper()
	return f.generateReferredProof(t, recipientAddr, "")
}

// generateReferredProof is generateProofForRecipient with a referrer in the
// signed claim message.
func (f *claimTestFixture) generateReferredProof(t *testing.T, recipientAddr, referrer string) ([]byte, [32]byte) {
	t.Helper()

	params, _, err := zktest.SignClaim(f.btcPrivKey, testChainID, f.btcAddress, recipientAddr, referrer)
	require.NoError(t, err)

	pubKeyHashSHA256, err := zk.PubKeyHashSHA256(f.btcPrivKey.PubKey().SerializeCompressed())
	require.NoError(t, err)

	proof, err := f.prover.GenerateProof(params)
	require.NoError(t, err, "proof generation should succeed")
	require.NotEmpty(t, proof)

	return proof, pubKeyHashSHA256
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
		{
			name: "same key at its other address type is skipped",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				signed := types.UTXO{
					Txid:           "abab000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 40000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: f.btcAddress},
				}
				unsigned := types.UTXO{
					Txid:           "abab000000000000000000000000000000000000000000000000000000000002",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 60000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: zktest.P2WPKHAddress(f.btcPrivKey.PubKey())},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "abab000000000000000000000000000000000000000000000000000000000001-0", signed))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "abab000000000000000000000000000000000000000000000000000000000002-0", unsigned))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			utxos: []types.UTXORef{
				{Txid: "abab000000000000000000000000000000000000000000000000000000000001", Vout: 0},
				{Txid: "abab000000000000000000000000000000000000000000000000000000000002", Vout: 0},
			},
			expectedClaim:  1,
			expectedSkip:   1,
			expectedAmount: 40000000,
		},
		{
			name: "first listed UTXO at an address the proof does not sign fails",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				unsigned := types.UTXO{
					Txid:           "acac000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 60000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: zktest.P2WPKHAddress(f.btcPrivKey.PubKey())},
				}
				signed := types.UTXO{
					Txid:           "acac000000000000000000000000000000000000000000000000000000000002",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 40000000,
					ScriptPubKey:   &types.ScriptPubKeyResult{Address: f.btcAddress},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "acac000000000000000000000000000000000000000000000000000000000001-0", unsigned))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "acac000000000000000000000000000000000000000000000000000000000002-0", signed))
			},
			utxos: []types.UTXORef{
				{Txid: "acac000000000000000000000000000000000000000000000000000000000001", Vout: 0},
				{Txid: "acac000000000000000000000000000000000000000000000000000000000002", Vout: 0},
			},
			expectErr:   true,
			errContains: "proof verification failed",
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
			proofData, pubKeyHashSHA256 := f.generateProof(st)
			// Create claim message
			msg := &types.MsgClaimWithProof{
				Claimer:          f.claimerAddr,
				Broadcaster:      f.claimerAddr,
				Utxos:            tc.utxos,
				Proof:            hex.EncodeToString(proofData),
				PubKeyHashSha256: hex.EncodeToString(pubKeyHashSHA256[:]),
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

	// Create claim with a well-formed but bogus proof, so it passes the layout
	// check and fails PLONK verification.
	msg := &types.MsgClaimWithProof{
		Claimer:     f.claimerAddr,
		Broadcaster: f.claimerAddr,
		Utxos: []types.UTXORef{
			{Txid: "9999000000000000000000000000000000000000000000000000000000000001", Vout: 0},
		},
		Proof:            hex.EncodeToString(zktest.WellFormedProof(zk.ClaimCircuitNbCommitments)),
		PubKeyHashSha256: hex.EncodeToString(make([]byte, 32)),
	}

	server := keeper.NewMsgServerImpl(f.keeper)
	resp, err := server.ClaimWithProof(f.ctx, msg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proof verification failed")
	assert.Nil(t, resp)
}

// TestClaimWithProof_Receiver tests that the receiver field redirects coins and
// is the destination the signed claim message must name.
func TestClaimWithProof_Receiver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f := setupClaimTest(t)

	// A separate address that will receive the coins instead of the claimer.
	receiverAddr := qbtctestutil.GetRandomQBTCAddress()

	btcAddr := bitcoinAddressFromHash(f.addressHash)
	utxo := types.UTXO{
		Txid:           "aaab000000000000000000000000000000000000000000000000000000000001",
		Vout:           0,
		Amount:         100000000,
		EntitledAmount: 60000000,
		ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "aaab000000000000000000000000000000000000000000000000000000000001-0", utxo))

	t.Run("coins go to receiver when set", func(t *testing.T) {
		// Proof is bound to receiverAddr, not claimerAddr.
		proofData, pubKeyHashSHA256 := f.generateProofForRecipient(t, receiverAddr)

		receiverAccAddr, err := sdk.AccAddressFromBech32(receiverAddr)
		require.NoError(t, err)

		f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
		// Coins must go to the receiver address, not the claimer.
		f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, receiverAccAddr, gomock.Any()).Return(nil).Times(1)

		msg := &types.MsgClaimWithProof{
			Claimer:          f.claimerAddr,
			Broadcaster:      f.claimerAddr,
			Receiver:         receiverAddr,
			Utxos:            []types.UTXORef{{Txid: "aaab000000000000000000000000000000000000000000000000000000000001", Vout: 0}},
			Proof:            hex.EncodeToString(proofData),
			PubKeyHashSha256: hex.EncodeToString(pubKeyHashSHA256[:]),
		}

		server := keeper.NewMsgServerImpl(f.keeper)
		resp, err := server.ClaimWithProof(f.ctx, msg)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, uint32(1), resp.UtxosClaimed)
		assert.Equal(t, uint64(60000000), resp.TotalAmountClaimed)
	})

	t.Run("proof bound to claimer rejected when receiver set", func(t *testing.T) {
		// Re-insert the UTXO (previous sub-test may have zeroed EntitledAmount).
		utxo2 := types.UTXO{
			Txid:           "aaab000000000000000000000000000000000000000000000000000000000002",
			Vout:           0,
			Amount:         100000000,
			EntitledAmount: 60000000,
			ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
		}
		require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "aaab000000000000000000000000000000000000000000000000000000000002-0", utxo2))

		// Proof is bound to claimerAddr but message says receiver = receiverAddr.
		proofData, pubKeyHashSHA256 := f.generateProof(t) // claimer-bound proof

		msg := &types.MsgClaimWithProof{
			Claimer:          f.claimerAddr,
			Broadcaster:      f.claimerAddr,
			Receiver:         receiverAddr,
			Utxos:            []types.UTXORef{{Txid: "aaab000000000000000000000000000000000000000000000000000000000002", Vout: 0}},
			Proof:            hex.EncodeToString(proofData),
			PubKeyHashSha256: hex.EncodeToString(pubKeyHashSHA256[:]),
		}

		server := keeper.NewMsgServerImpl(f.keeper)
		resp, err := server.ClaimWithProof(f.ctx, msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "proof verification failed")
		assert.Nil(t, resp)
	})
}

// TestClaimWithProof_Referrer checks the referrer is bound by the signed claim
// message, recorded on the claimed UTXO and paid from the referral pool.
func TestClaimWithProof_Referrer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f := setupClaimTest(t)
	require.NoError(t, f.keeper.ConstOverrides.Set(f.ctx, constants.ReferrerRewardBps.String(), 500))
	require.NoError(t, f.keeper.ConstOverrides.Set(f.ctx, constants.RefereeRewardBps.String(), 0))

	referrer := qbtctestutil.GetRandomQBTCAddress()
	referrerAcc, err := sdk.AccAddressFromBech32(referrer)
	require.NoError(t, err)
	claimerAcc, err := sdk.AccAddressFromBech32(f.claimerAddr)
	require.NoError(t, err)

	const txid = "aaac000000000000000000000000000000000000000000000000000000000001"
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, txid+"-0", types.UTXO{
		Txid:           txid,
		Vout:           0,
		Amount:         100000000,
		EntitledAmount: 60000000,
		ScriptPubKey:   &types.ScriptPubKeyResult{Address: f.btcAddress},
	}))

	proofData, pubKeyHashSHA256 := f.generateReferredProof(t, f.claimerAddr, referrer)
	newMsg := func(referrer string) *types.MsgClaimWithProof {
		return &types.MsgClaimWithProof{
			Claimer:          f.claimerAddr,
			Broadcaster:      f.claimerAddr,
			Referrer:         referrer,
			Utxos:            []types.UTXORef{{Txid: txid, Vout: 0}},
			Proof:            hex.EncodeToString(proofData),
			PubKeyHashSha256: hex.EncodeToString(pubKeyHashSHA256[:]),
		}
	}
	server := keeper.NewMsgServerImpl(f.keeper)

	t.Run("swapped referrer is rejected", func(t *testing.T) {
		_, err := server.ClaimWithProof(f.ctx, newMsg(qbtctestutil.GetRandomQBTCAddress()))
		require.ErrorContains(t, err, "proof verification failed")
	})

	t.Run("dropped referrer is rejected", func(t *testing.T) {
		_, err := server.ClaimWithProof(f.ctx, newMsg(""))
		require.ErrorContains(t, err, "proof verification failed")
	})

	t.Run("signed referrer is paid", func(t *testing.T) {
		poolAddr := sdk.AccAddress([]byte("referral-pool-addr00"))
		f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
		f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, claimerAcc, gomock.Any()).Return(nil).Times(1)
		f.authKeeper.EXPECT().GetModuleAddress(types.ReferralModuleName).Return(poolAddr).AnyTimes()
		f.bankKeeper.EXPECT().GetBalance(gomock.Any(), poolAddr, sdk.DefaultBondDenom).
			Return(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1_000_000_000)).AnyTimes()
		f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ReferralModuleName, referrerAcc,
			sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 3_000_000))).Return(nil).Times(1)

		ctx := f.ctx.WithEventManager(sdk.NewEventManager())
		resp, err := server.ClaimWithProof(ctx, newMsg(referrer))
		require.NoError(t, err)
		require.Equal(t, uint64(60000000), resp.TotalAmountClaimed)

		utxo, err := f.keeper.Utxoes.Get(ctx, txid+"-0")
		require.NoError(t, err)
		require.Equal(t, referrer, utxo.Referrer)

		stats, err := f.keeper.GetReferralStats(ctx, referrerAcc)
		require.NoError(t, err)
		require.Equal(t, uint64(1), stats.ReferredClaims)
		require.Equal(t, uint64(60000000), stats.ReferredAmount)
		require.Equal(t, uint64(3_000_000), stats.ReferrerRewardsPaid)

		var sawReward bool
		for _, e := range ctx.EventManager().Events() {
			switch e.Type {
			case "claim_with_proof":
				attr, ok := e.GetAttribute("referrer")
				require.True(t, ok)
				require.Equal(t, referrer, attr.Value)
			case types.EventTypeReferralReward:
				sawReward = true
			}
		}
		require.True(t, sawReward)
	})

	t.Run("referrer equal to destination is rejected", func(t *testing.T) {
		_, err := server.ClaimWithProof(f.ctx, newMsg(f.claimerAddr))
		require.ErrorContains(t, err, "referrer cannot be the claim destination")
	})
}
