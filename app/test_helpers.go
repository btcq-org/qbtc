package app

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/mldsa"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/stretchr/testify/require"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	qbtctypes "github.com/btcq-org/qbtc/x/qbtc/types"
)

// TestChainID is the chain ID used for integration tests
const TestChainID = "qbtc-test-1"

// DefaultTestDenom is the default denomination for test tokens
const DefaultTestDenom = "uqbtc"

// EmptyAppOptions implements servertypes.AppOptions with no values
type EmptyAppOptions struct{}

func (EmptyAppOptions) Get(key string) interface{} {
	// Return false for ebifrost.enable to disable it in tests
	if key == "ebifrost.enable" {
		return false
	}
	return nil
}

// TestAppOptions returns AppOptions suitable for testing.
// Uses a unique temporary directory to avoid CosmWasm lock conflicts between tests.
func TestAppOptions() servertypes.AppOptions {
	appOptions := make(simtestutil.AppOptionsMap)
	// Use a unique temp directory for each test to avoid wasm lock conflicts
	tempDir, err := os.MkdirTemp("", "qbtc-test-*")
	if err != nil {
		panic(err)
	}
	appOptions[flags.FlagHome] = tempDir
	appOptions["ebifrost.enable"] = false
	return appOptions
}

// ValidatorKeyPair holds a CometBFT validator key pair
type ValidatorKeyPair struct {
	PrivKey cmtcrypto.PrivKey
	PubKey  cmtcrypto.PubKey
	Address cmtcrypto.Address
}

// Sign signs a message with the validator's private key
func (v ValidatorKeyPair) Sign(msg []byte) ([]byte, error) {
	return v.PrivKey.Sign(msg)
}

// GetSDKPubKey returns the SDK public key for this validator
func (v ValidatorKeyPair) GetSDKPubKey() (cryptotypes.PubKey, error) {
	return cryptocodec.FromCmtPubKeyInterface(v.PubKey)
}

// Setup initializes a new App with a single validator for testing.
// This is the simplest setup for basic tests.
func Setup(t *testing.T, isCheckTx bool) *App {
	t.Helper()

	valSet, _ := CreateTestValidatorSet(t, 1)
	genAccs, balances := CreateTestGenesisAccounts(t, 1)

	app := SetupWithGenesisValSet(t, valSet, genAccs, balances...)
	return app
}

// SetupWithValidators initializes a new App with a specified number of validators.
// Returns the app, validator set, and validator key pairs for signing.
func SetupWithValidators(t *testing.T, numValidators int) (*App, *cmttypes.ValidatorSet, []ValidatorKeyPair) {
	t.Helper()

	valSet, valKeys := CreateTestValidatorSet(t, numValidators)
	genAccs, balances := CreateTestGenesisAccounts(t, numValidators)

	app := SetupWithGenesisValSet(t, valSet, genAccs, balances...)

	return app, valSet, valKeys
}

// SetupWithGenesisValSet initializes a new App with a validator set and genesis accounts
// that also act as delegators. For simplicity, each validator is bonded with a delegation
// of one consensus engine unit in the default token of the app from first genesis account.
func SetupWithGenesisValSet(t *testing.T, valSet *cmttypes.ValidatorSet, genAccs []authtypes.GenesisAccount, balances ...banktypes.Balance) *App {
	t.Helper()

	app, genesisState := setup(t, true)
	genesisState, err := genesisStateWithValSet(app.AppCodec(), genesisState, valSet, genAccs, balances...)
	require.NoError(t, err)

	stateBytes, err := json.MarshalIndent(genesisState, "", " ")
	require.NoError(t, err)

	// Initialize the chain
	_, err = app.InitChain(&abci.RequestInitChain{
		Validators:      []abci.ValidatorUpdate{},
		ConsensusParams: simtestutil.DefaultConsensusParams,
		AppStateBytes:   stateBytes,
		ChainId:         TestChainID,
	})
	require.NoError(t, err)

	// Finalize block to move past genesis
	_, err = app.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height:             app.LastBlockHeight() + 1,
		Hash:               app.LastCommitID().Hash,
		NextValidatorsHash: valSet.Hash(),
	})
	require.NoError(t, err)

	// Commit to finalize the state
	_, err = app.Commit()
	require.NoError(t, err)

	return app
}

// SetupWithGenesisQBTC initializes the app with QBTC-specific genesis state
// including UTXOs, peer addresses, and ZK verifying key.
func SetupWithGenesisQBTC(
	t *testing.T,
	qbtcGenesis *qbtctypes.GenesisState,
	valSet *cmttypes.ValidatorSet,
	genAccs []authtypes.GenesisAccount,
	balances ...banktypes.Balance,
) *App {
	t.Helper()

	app, genesisState := setup(t, true)
	genesisState, err := genesisStateWithValSet(app.AppCodec(), genesisState, valSet, genAccs, balances...)
	require.NoError(t, err)

	// Override QBTC genesis state if provided
	if qbtcGenesis != nil {
		genesisState[qbtctypes.ModuleName] = app.AppCodec().MustMarshalJSON(qbtcGenesis)
	}

	stateBytes, err := json.MarshalIndent(genesisState, "", " ")
	require.NoError(t, err)

	// Initialize the chain
	_, err = app.InitChain(&abci.RequestInitChain{
		Validators:      []abci.ValidatorUpdate{},
		ConsensusParams: simtestutil.DefaultConsensusParams,
		AppStateBytes:   stateBytes,
		ChainId:         TestChainID,
	})
	require.NoError(t, err)

	// Finalize block to move past genesis
	_, err = app.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height:             app.LastBlockHeight() + 1,
		Hash:               app.LastCommitID().Hash,
		NextValidatorsHash: valSet.Hash(),
	})
	require.NoError(t, err)

	// Commit to finalize the state
	_, err = app.Commit()
	require.NoError(t, err)

	return app
}

// setup creates a new App with genesis state
func setup(t *testing.T, withGenesis bool) (*App, GenesisState) {
	t.Helper()

	db := dbm.NewMemDB()
	appOptions := TestAppOptions()

	app := New(
		log.NewNopLogger(),
		db,
		nil,
		true,
		appOptions,
		baseapp.SetChainID(TestChainID),
	)

	if withGenesis {
		return app, app.DefaultGenesis()
	}
	return app, GenesisState{}
}

// CreateTestValidatorSet creates a CometBFT validator set with the specified number
// of validators using ML-DSA keys (post-quantum). Returns both the validator set
// and the corresponding key pairs for signing.
func CreateTestValidatorSet(t *testing.T, numValidators int) (*cmttypes.ValidatorSet, []ValidatorKeyPair) {
	t.Helper()

	validators := make([]*cmttypes.Validator, numValidators)
	keyPairs := make([]ValidatorKeyPair, numValidators)

	for i := 0; i < numValidators; i++ {
		// Use ML-DSA keys for validators (post-quantum)
		cmtPrivKey := mldsa.GenPrivKey()
		cmtPubKey := cmtPrivKey.PubKey()

		// Create validator with voting power >= DefaultPowerReduction (typically 10^6)
		// Each validator gets 10 million tokens to ensure they have enough delegation
		validators[i] = cmttypes.NewValidator(cmtPubKey, 10_000_000)

		// Store key pair
		keyPairs[i] = ValidatorKeyPair{
			PrivKey: cmtPrivKey,
			PubKey:  cmtPubKey,
			Address: cmtPubKey.Address(),
		}
	}

	return cmttypes.NewValidatorSet(validators), keyPairs
}

// CreateTestGenesisAccounts creates genesis accounts with initial balances.
// Each account gets a large initial balance for testing.
func CreateTestGenesisAccounts(t *testing.T, numAccounts int) ([]authtypes.GenesisAccount, []banktypes.Balance) {
	t.Helper()

	genAccs := make([]authtypes.GenesisAccount, numAccounts)
	balances := make([]banktypes.Balance, numAccounts)

	initBalance := sdkmath.NewInt(100_000_000_000_000) // 100 trillion micro units

	for i := 0; i < numAccounts; i++ {
		// Use secp256k1 for account keys (different from validator consensus keys)
		privKey := secp256k1.GenPrivKey()
		pubKey := privKey.PubKey()
		addr := sdk.AccAddress(pubKey.Address())

		genAccs[i] = authtypes.NewBaseAccount(addr, pubKey, uint64(i), 0)
		balances[i] = banktypes.Balance{
			Address: addr.String(),
			Coins:   sdk.NewCoins(sdk.NewCoin(DefaultTestDenom, initBalance)),
		}
	}

	return genAccs, balances
}

// CreateTestAccountsWithKeys creates test accounts and returns their addresses and private keys.
func CreateTestAccountsWithKeys(t *testing.T, numAccounts int) ([]sdk.AccAddress, []cryptotypes.PrivKey) {
	t.Helper()

	addrs := make([]sdk.AccAddress, numAccounts)
	privKeys := make([]cryptotypes.PrivKey, numAccounts)

	for i := 0; i < numAccounts; i++ {
		privKey := secp256k1.GenPrivKey()
		pubKey := privKey.PubKey()
		addrs[i] = sdk.AccAddress(pubKey.Address())
		privKeys[i] = privKey
	}

	return addrs, privKeys
}

// AddTestAddrs creates test addresses with initial balances and funds them.
func AddTestAddrs(app *App, ctx sdk.Context, accNum int, accAmt sdkmath.Int) []sdk.AccAddress {
	testAddrs := simtestutil.CreateIncrementalAccounts(accNum)

	initCoins := sdk.NewCoins(sdk.NewCoin(DefaultTestDenom, accAmt))

	for _, addr := range testAddrs {
		initAccountWithCoins(app, ctx, addr, initCoins)
	}

	return testAddrs
}

// initAccountWithCoins mints coins and sends them to the specified address.
func initAccountWithCoins(app *App, ctx sdk.Context, addr sdk.AccAddress, coins sdk.Coins) {
	err := app.BankKeeper.MintCoins(ctx, qbtctypes.ReserveModuleName, coins)
	if err != nil {
		panic(err)
	}

	err = app.BankKeeper.SendCoinsFromModuleToAccount(ctx, qbtctypes.ReserveModuleName, addr, coins)
	if err != nil {
		panic(err)
	}
}

// GetTestContext returns a new context for the app at the current block height.
func GetTestContext(app *App) sdk.Context {
	header := cmtproto.Header{
		Height:  app.LastBlockHeight(),
		ChainID: TestChainID,
		Time:    time.Now().UTC(),
	}
	return app.BaseApp.NewUncachedContext(false, header)
}

// genesisStateWithValSet returns a genesis state with the given validator set and accounts.
func genesisStateWithValSet(
	cdc codec.Codec,
	genesisState GenesisState,
	valSet *cmttypes.ValidatorSet,
	genAccs []authtypes.GenesisAccount,
	balances ...banktypes.Balance,
) (GenesisState, error) {
	// Set validators in staking genesis
	stakingGenesis := stakingtypes.GetGenesisStateFromAppState(cdc, genesisState)
	if stakingGenesis == nil {
		stakingGenesis = stakingtypes.DefaultGenesisState()
	}

	// Get bond denom from staking genesis params
	bondDenom := stakingGenesis.Params.BondDenom

	// Create staking validators from CometBFT validators
	stakingValidators := make([]stakingtypes.Validator, 0, len(valSet.Validators))
	delegations := make([]stakingtypes.Delegation, 0, len(valSet.Validators))

	for i, val := range valSet.Validators {
		// Convert CometBFT public key to SDK public key
		pk, err := cryptocodec.FromCmtPubKeyInterface(val.PubKey)
		if err != nil {
			return nil, err
		}

		pkAny, err := codectypes.NewAnyWithValue(pk)
		if err != nil {
			return nil, err
		}

		// Create validator
		validator := stakingtypes.Validator{
			OperatorAddress:   sdk.ValAddress(val.Address).String(),
			ConsensusPubkey:   pkAny,
			Jailed:            false,
			Status:            stakingtypes.Bonded,
			Tokens:            sdkmath.NewInt(val.VotingPower),
			DelegatorShares:   sdkmath.LegacyNewDec(val.VotingPower),
			Description:       stakingtypes.Description{},
			UnbondingHeight:   0,
			UnbondingTime:     time.Unix(0, 0).UTC(),
			Commission:        stakingtypes.NewCommission(sdkmath.LegacyZeroDec(), sdkmath.LegacyZeroDec(), sdkmath.LegacyZeroDec()),
			MinSelfDelegation: sdkmath.ZeroInt(),
		}
		stakingValidators = append(stakingValidators, validator)

		// Create delegation from the first genesis account
		if len(genAccs) > 0 {
			delegations = append(delegations, stakingtypes.NewDelegation(
				genAccs[i%len(genAccs)].GetAddress().String(),
				sdk.ValAddress(val.Address).String(),
				sdkmath.LegacyNewDec(val.VotingPower),
			))
		}
	}

	stakingGenesis.Validators = stakingValidators
	stakingGenesis.Delegations = delegations
	genesisState[stakingtypes.ModuleName] = cdc.MustMarshalJSON(stakingGenesis)

	// Add bonded amount to bonded pool module account
	totalBonded := sdkmath.ZeroInt()
	for _, val := range stakingValidators {
		totalBonded = totalBonded.Add(val.Tokens)
	}

	// Update bank genesis with balances
	bankGenesisPtr := banktypes.GetGenesisStateFromAppState(cdc, genesisState)
	if bankGenesisPtr == nil {
		bankGenesisPtr = banktypes.DefaultGenesisState()
	}
	bankGenesis := bankGenesisPtr

	// Add genesis account balances
	bankGenesis.Balances = append(bankGenesis.Balances, balances...)

	// Add bonded pool balance
	bankGenesis.Balances = append(bankGenesis.Balances, banktypes.Balance{
		Address: authtypes.NewModuleAddress(stakingtypes.BondedPoolName).String(),
		Coins:   sdk.NewCoins(sdk.NewCoin(bondDenom, totalBonded)),
	})

	genesisState[banktypes.ModuleName] = cdc.MustMarshalJSON(bankGenesis)

	// Update auth genesis with accounts
	authGenesis := authtypes.GetGenesisStateFromAppState(cdc, genesisState)

	accounts, err := authtypes.PackAccounts(genAccs)
	if err != nil {
		return nil, err
	}
	authGenesis.Accounts = append(authGenesis.Accounts, accounts...)
	genesisState[authtypes.ModuleName] = cdc.MustMarshalJSON(&authGenesis)

	return genesisState, nil
}
