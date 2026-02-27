package app

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"cosmossdk.io/log"
	"cosmossdk.io/math"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/stretchr/testify/require"

	qbtcmoduletypes "github.com/btcq-org/qbtc/x/qbtc/types"
)

// TestClaimUTXO_MintViaQBTCModuleAccount test minting to the module account succeeds
func TestClaimUTXO_MintViaQBTCModuleAccount(t *testing.T) {
	// --- boot the full app with real keepers ---
	app, ctx, accounts := setupTestApp(t)

	require.NotNil(t, app.QbtcKeeper, "qbtc keeper must be wired")
	require.GreaterOrEqual(t, len(accounts), 1, "need at least one funded account")

	recipient := accounts[0].Address

	// --- seed a UTXO into the qbtc store ---
	txid := "aabb000000000000000000000000000000000000000000000000000000001234"
	vout := uint32(0)
	key := fmt.Sprintf("%s-%d", txid, vout)

	utxo := qbtcmoduletypes.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         100_000_000, // 1 BTC in satoshis
		EntitledAmount: 50_000_000,  // 0.5 BTC claimable
		ScriptPubKey: &qbtcmoduletypes.ScriptPubKeyResult{
			Hex:     "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
			Type:    "pubkeyhash",
			Address: "1DummyBitcoinAddress000000000000X",
		},
	}
	require.NoError(t, app.QbtcKeeper.Utxoes.Set(ctx, key, utxo))

	// --- attempt the claim (recipient != nil → mints via "qbtc" module account) ---
	err := app.QbtcKeeper.ClaimUTXO(ctx, txid, vout, recipient)
	require.NoError(t, err,
		"ClaimUTXO with a recipient must succeed; if this fails with "+
			"'module account qbtc does not have permissions to mint tokens' "+
			"then the qbtc module account is missing the Minter permission "+
			"in moduleAccPerms (FUND-01)")

	// --- verify the UTXO entitled amount was zeroed ---
	claimed, err := app.QbtcKeeper.Utxoes.Get(ctx, key)
	require.NoError(t, err)
	require.Equal(t, uint64(0), claimed.EntitledAmount,
		"entitled amount must be reset to 0 after a successful claim")

	// --- verify recipient actually received the coins ---
	balance := app.BankKeeper.GetBalance(ctx, recipient, sdk.DefaultBondDenom)
	require.True(t, balance.Amount.GTE(math.NewInt(50_000_000)),
		"recipient must have received the minted coins, got %s", balance)
}

// TestClaimUTXO_ReserveMint test with the reserver module account (governance)
func TestClaimUTXO_ReserveMint(t *testing.T) {
	app, ctx, _ := setupTestApp(t)

	txid := "ccdd000000000000000000000000000000000000000000000000000000005678"
	vout := uint32(0)
	key := fmt.Sprintf("%s-%d", txid, vout)

	utxo := qbtcmoduletypes.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         200_000_000,
		EntitledAmount: 100_000_000,
		ScriptPubKey: &qbtcmoduletypes.ScriptPubKeyResult{
			Hex:  "76a91400000000000000000000000000000000000000aa88ac",
			Type: "pubkeyhash",
		},
	}
	require.NoError(t, app.QbtcKeeper.Utxoes.Set(ctx, key, utxo))

	// recipient == nil → mints via "reserve" module account
	err := app.QbtcKeeper.ClaimUTXO(ctx, txid, vout, nil)
	require.NoError(t, err, "ClaimUTXO via reserve module should always succeed")

	claimed, err := app.QbtcKeeper.Utxoes.Get(ctx, key)
	require.NoError(t, err)
	require.Equal(t, uint64(0), claimed.EntitledAmount)
}

// setupTestApp boots the full application with real keepers and returns a
// usable context along with funded simulation accounts.
func setupTestApp(t *testing.T) (*App, sdk.Context, []simtypes.Account) {
	t.Helper()

	db := dbm.NewMemDB()
	logger := log.NewNopLogger()

	appOptions := make(simtestutil.AppOptionsMap, 0)
	appOptions[flags.FlagHome] = t.TempDir()

	application := New(
		logger,
		db,
		nil,
		true,
		appOptions,
		baseapp.SetChainID("qbtc-test-1"),
	)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	accounts := simtypes.RandomAccounts(r, 3)

	config := simtypes.Config{
		ChainID:     "qbtc-test-1",
		GenesisTime: time.Now().Unix(),
	}

	appStateFn := simtestutil.AppStateFn(
		application.AppCodec(),
		application.SimulationManager(),
		application.DefaultGenesis(),
	)
	appState, simAccounts, _, _ := appStateFn(r, accounts, config)

	_, err := application.InitChain(&abci.RequestInitChain{
		ChainId:         "qbtc-test-1",
		AppStateBytes:   appState,
		ConsensusParams: simtestutil.DefaultConsensusParams,
	})
	require.NoError(t, err)

	_, err = application.Commit()
	require.NoError(t, err)

	header := cmtproto.Header{
		Height:  application.LastBlockHeight(),
		Time:    time.Now().UTC(),
		ChainID: "qbtc-test-1",
	}
	ctx := application.NewUncachedContext(false, header)

	return application, ctx, simAccounts
}
