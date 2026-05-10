package keeper_test

import (
	"bytes"
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

const testChainID = "qbtc-test-1"

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

func setupClaimTest(t *testing.T) *claimTestFixture {
	t.Helper()

	setup, err := zk.SetupWithOptions(zk.TestSetupOptions())
	require.NoError(t, err, "ZK circuit setup should succeed")

	vkBytes, err := zk.SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err, "VK serialization should succeed")

	err = zk.InitializeVerifier(vkBytes)
	if err != nil && !errors.Is(err, zk.ErrVerifierAlreadyInitialized) {
		t.Fatalf("verifier registration failed: %v", err)
	}

	prover := zk.ProverFromSetup(setup)

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

	claimerAddr := qbtctestutil.GetRandomQBTCAddress()

	privateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err, "should create new private key")

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
	MessageHash      [32]byte
	AddressHash      [20]byte
	PubKeyHashSHA256 [32]byte
	QBTCAddressHash  [32]byte
}

func (f *claimTestFixture) generateProof(t *testing.T) ([]byte, publicInput) {
	t.Helper()
	return f.generateProofForRecipient(t, f.claimerAddr)
}

func (f *claimTestFixture) generateProofForRecipient(t *testing.T, recipientAddr string) ([]byte, publicInput) {
	t.Helper()

	qbtcAddressHash := zk.HashQBTCAddress(recipientAddr)
	chainIDHash := zk.ComputeChainIDHash(testChainID)

	messageHash := zk.ComputeClaimMessage(f.addressHash, qbtcAddressHash, chainIDHash)

	sig := ecdsa.Sign(f.btcPrivKey, messageHash[:])

	sigBytes := sig.Serialize()
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]

	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	sigR := new(big.Int).SetBytes(rBytes)
	sigS := new(big.Int).SetBytes(sBytes)

	pubKey := f.btcPrivKey.PubKey()
	pubKeyHashSHA256, err := zk.PubKeyHashSHA256(pubKey.SerializeCompressed())
	require.NoError(t, err)

	proof, err := f.prover.GenerateProof(zk.ProofParams{
		SignatureR:  sigR,
		SignatureS:  sigS,
		PublicKeyX:  pubKey.X(),
		PublicKeyY:  pubKey.Y(),
		MessageHash: messageHash,
	})
	require.NoError(t, err, "proof generation should succeed")
	require.NotEmpty(t, proof)

	return proof, publicInput{
		MessageHash:      messageHash,
		AddressHash:      f.addressHash,
		PubKeyHashSHA256: pubKeyHashSHA256,
		QBTCAddressHash:  qbtcAddressHash,
	}
}

// hexTxid decodes a Bitcoin txid hex string into the 32-byte little-endian
// wire format used by the slim UTXO proto.
func hexTxid(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex txid %q: %v", s, err))
	}
	if len(b) != 32 {
		panic(fmt.Sprintf("txid %q must be 32 bytes, got %d", s, len(b)))
	}
	return b
}

// TestClaimWithProof_PartialClaiming tests the partial claiming behavior.
func TestClaimWithProof_PartialClaiming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	wrongAddr := bytes.Repeat([]byte{0xee}, 20)

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
				utxo1 := types.UTXO{
					Txid:           hexTxid("aaaa000000000000000000000000000000000000000000000000000000000001"),
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					Address:        f.addressHash[:],
				}
				utxo2 := types.UTXO{
					Txid:           hexTxid("aaaa000000000000000000000000000000000000000000000000000000000002"),
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 150000000,
					Address:        f.addressHash[:],
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo1.GetKey(), utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo2.GetKey(), utxo2))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(2)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
			utxos: []types.UTXORef{
				{Txid: hexTxid("aaaa000000000000000000000000000000000000000000000000000000000001"), Vout: 0},
				{Txid: hexTxid("aaaa000000000000000000000000000000000000000000000000000000000002"), Vout: 1},
			},
			expectedClaim:  2,
			expectedSkip:   0,
			expectedAmount: 200000000,
			expectErr:      false,
		},
		{
			name: "partial claim - some UTXOs have wrong address",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				utxo1 := types.UTXO{
					Txid:           hexTxid("bbbb000000000000000000000000000000000000000000000000000000000001"),
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					Address:        f.addressHash[:],
				}
				utxo2 := types.UTXO{
					Txid:           hexTxid("bbbb000000000000000000000000000000000000000000000000000000000002"),
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 150000000,
					Address:        wrongAddr,
				}
				utxo3 := types.UTXO{
					Txid:           hexTxid("bbbb000000000000000000000000000000000000000000000000000000000003"),
					Vout:           2,
					Amount:         300000000,
					EntitledAmount: 250000000,
					Address:        f.addressHash[:],
				}

				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo1.GetKey(), utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo2.GetKey(), utxo2))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo3.GetKey(), utxo3))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(2)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
			utxos: []types.UTXORef{
				{Txid: hexTxid("bbbb000000000000000000000000000000000000000000000000000000000001"), Vout: 0},
				{Txid: hexTxid("bbbb000000000000000000000000000000000000000000000000000000000002"), Vout: 1},
				{Txid: hexTxid("bbbb000000000000000000000000000000000000000000000000000000000003"), Vout: 2},
			},
			expectedClaim:  2,
			expectedSkip:   1,
			expectedAmount: 300000000,
			expectErr:      false,
		},
		{
			name: "partial claim - some UTXOs not found",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				utxo1 := types.UTXO{
					Txid:           hexTxid("cccc000000000000000000000000000000000000000000000000000000000001"),
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 75000000,
					Address:        f.addressHash[:],
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo1.GetKey(), utxo1))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			utxos: []types.UTXORef{
				{Txid: hexTxid("cccc000000000000000000000000000000000000000000000000000000000001"), Vout: 0},
				{Txid: hexTxid("cccc000000000000000000000000000000000000000000000000000000000099"), Vout: 0},
			},
			expectedClaim:  1,
			expectedSkip:   1,
			expectedAmount: 75000000,
			expectErr:      false,
		},
		{
			name: "partial claim - some UTXOs already claimed",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				utxo1 := types.UTXO{
					Txid:           hexTxid("dddd000000000000000000000000000000000000000000000000000000000001"),
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 80000000,
					Address:        f.addressHash[:],
				}
				utxo2 := types.UTXO{
					Txid:           hexTxid("dddd000000000000000000000000000000000000000000000000000000000002"),
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 0,
					Address:        f.addressHash[:],
				}

				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo1.GetKey(), utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo2.GetKey(), utxo2))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			utxos: []types.UTXORef{
				{Txid: hexTxid("dddd000000000000000000000000000000000000000000000000000000000001"), Vout: 0},
				{Txid: hexTxid("dddd000000000000000000000000000000000000000000000000000000000002"), Vout: 1},
			},
			expectedClaim:  1,
			expectedSkip:   1,
			expectedAmount: 80000000,
			expectErr:      false,
		},
		{
			name: "no valid UTXOs - error",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
			},
			utxos: []types.UTXORef{
				{Txid: hexTxid("eeee000000000000000000000000000000000000000000000000000000000001"), Vout: 0},
			},
			expectErr:   true,
			errContains: "no valid claimable UTXOs found",
		},
		{
			name: "mixed scenarios - comprehensive test",
			setupUTXOs: func(t *testing.T, f *claimTestFixture) {
				utxo1 := types.UTXO{
					Txid:           hexTxid("ffff000000000000000000000000000000000000000000000000000000000001"),
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 40000000,
					Address:        f.addressHash[:],
				}
				utxo2 := types.UTXO{
					Txid:           hexTxid("ffff000000000000000000000000000000000000000000000000000000000002"),
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 0,
					Address:        f.addressHash[:],
				}
				utxo3 := types.UTXO{
					Txid:           hexTxid("ffff000000000000000000000000000000000000000000000000000000000003"),
					Vout:           2,
					Amount:         300000000,
					EntitledAmount: 250000000,
					Address:        wrongAddr,
				}
				utxo4 := types.UTXO{
					Txid:           hexTxid("ffff000000000000000000000000000000000000000000000000000000000004"),
					Vout:           3,
					Amount:         400000000,
					EntitledAmount: 60000000,
					Address:        f.addressHash[:],
				}

				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo1.GetKey(), utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo2.GetKey(), utxo2))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo3.GetKey(), utxo3))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo4.GetKey(), utxo4))

				f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(2)
				f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
			utxos: []types.UTXORef{
				{Txid: hexTxid("ffff000000000000000000000000000000000000000000000000000000000001"), Vout: 0},
				{Txid: hexTxid("ffff000000000000000000000000000000000000000000000000000000000002"), Vout: 1},
				{Txid: hexTxid("ffff000000000000000000000000000000000000000000000000000000000003"), Vout: 2},
				{Txid: hexTxid("ffff000000000000000000000000000000000000000000000000000000000004"), Vout: 3},
				{Txid: hexTxid("ffff000000000000000000000000000000000000000000000000000000000099"), Vout: 9},
			},
			expectedClaim:  2,
			expectedSkip:   3,
			expectedAmount: 100000000,
			expectErr:      false,
		},
	}

	f := setupClaimTest(t)
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			if tc.setupUTXOs != nil {
				tc.setupUTXOs(st, f)
			}

			proofData, pi := f.generateProof(st)
			msg := &types.MsgClaimWithProof{
				Claimer:          f.claimerAddr,
				Broadcaster:      f.claimerAddr,
				Utxos:            tc.utxos,
				Proof:            hex.EncodeToString(proofData),
				MessageHash:      hex.EncodeToString(pi.MessageHash[:]),
				AddressHash:      hex.EncodeToString(pi.AddressHash[:]),
				PubKeyHashSha256: hex.EncodeToString(pi.PubKeyHashSHA256[:]),
				QbtcAddressHash:  hex.EncodeToString(pi.QBTCAddressHash[:]),
			}

			server := keeper.NewMsgServerImpl(f.keeper)
			resp, err := server.ClaimWithProof(f.ctx, msg)

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

	utxo := types.UTXO{
		Txid:           hexTxid("9999000000000000000000000000000000000000000000000000000000000001"),
		Vout:           0,
		Amount:         100000000,
		EntitledAmount: 50000000,
		Address:        f.addressHash[:],
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))

	qbtcAddr := zk.HashQBTCAddress(f.claimerAddr)
	msg := &types.MsgClaimWithProof{
		Claimer:     f.claimerAddr,
		Broadcaster: f.claimerAddr,
		Utxos: []types.UTXORef{
			{Txid: hexTxid("9999000000000000000000000000000000000000000000000000000000000001"), Vout: 0},
		},
		Proof:            hex.EncodeToString(make([]byte, 500)),
		MessageHash:      hex.EncodeToString(make([]byte, 32)),
		AddressHash:      hex.EncodeToString(make([]byte, 20)),
		PubKeyHashSha256: hex.EncodeToString(make([]byte, 32)),
		QbtcAddressHash:  hex.EncodeToString(qbtcAddr[:]),
	}

	server := keeper.NewMsgServerImpl(f.keeper)
	resp, err := server.ClaimWithProof(f.ctx, msg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proof verification failed")
	assert.Nil(t, resp)
}

// TestClaimWithProof_Receiver tests that the receiver field redirects coins and
// is used as the qbtcAddressHash binding in ZK proof verification.
func TestClaimWithProof_Receiver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f := setupClaimTest(t)

	receiverAddr := qbtctestutil.GetRandomQBTCAddress()

	utxo := types.UTXO{
		Txid:           hexTxid("aaab000000000000000000000000000000000000000000000000000000000001"),
		Vout:           0,
		Amount:         100000000,
		EntitledAmount: 60000000,
		Address:        f.addressHash[:],
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))

	t.Run("coins go to receiver when set", func(t *testing.T) {
		proofData, pi := f.generateProofForRecipient(t, receiverAddr)

		receiverAccAddr, err := sdk.AccAddressFromBech32(receiverAddr)
		require.NoError(t, err)

		f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(1)
		f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, receiverAccAddr, gomock.Any()).Return(nil).Times(1)

		msg := &types.MsgClaimWithProof{
			Claimer:          f.claimerAddr,
			Broadcaster:      f.claimerAddr,
			Receiver:         receiverAddr,
			Utxos:            []types.UTXORef{{Txid: hexTxid("aaab000000000000000000000000000000000000000000000000000000000001"), Vout: 0}},
			Proof:            hex.EncodeToString(proofData),
			MessageHash:      hex.EncodeToString(pi.MessageHash[:]),
			AddressHash:      hex.EncodeToString(pi.AddressHash[:]),
			PubKeyHashSha256: hex.EncodeToString(pi.PubKeyHashSHA256[:]),
			QbtcAddressHash:  hex.EncodeToString(pi.QBTCAddressHash[:]),
		}

		server := keeper.NewMsgServerImpl(f.keeper)
		resp, err := server.ClaimWithProof(f.ctx, msg)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, uint32(1), resp.UtxosClaimed)
		assert.Equal(t, uint64(60000000), resp.TotalAmountClaimed)
	})

	t.Run("proof bound to claimer rejected when receiver set", func(t *testing.T) {
		utxo2 := types.UTXO{
			Txid:           hexTxid("aaab000000000000000000000000000000000000000000000000000000000002"),
			Vout:           0,
			Amount:         100000000,
			EntitledAmount: 60000000,
			Address:        f.addressHash[:],
		}
		require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo2.GetKey(), utxo2))

		proofData, pi := f.generateProof(t)

		msg := &types.MsgClaimWithProof{
			Claimer:          f.claimerAddr,
			Broadcaster:      f.claimerAddr,
			Receiver:         receiverAddr,
			Utxos:            []types.UTXORef{{Txid: hexTxid("aaab000000000000000000000000000000000000000000000000000000000002"), Vout: 0}},
			Proof:            hex.EncodeToString(proofData),
			MessageHash:      hex.EncodeToString(pi.MessageHash[:]),
			AddressHash:      hex.EncodeToString(pi.AddressHash[:]),
			PubKeyHashSha256: hex.EncodeToString(pi.PubKeyHashSHA256[:]),
			QbtcAddressHash:  hex.EncodeToString(pi.QBTCAddressHash[:]),
		}

		server := keeper.NewMsgServerImpl(f.keeper)
		resp, err := server.ClaimWithProof(f.ctx, msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "proof verification failed")
		assert.Nil(t, resp)
	})
}
