package app

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/stretchr/testify/require"

	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/btcq-org/qbtc/testdata/contracts"
)

const (
	WasmTestChainID = "qbtc-wasm-test"
)

// TestWasmIntegration tests the full WASM integration:
// 1. Store a contract
// 2. Instantiate the contract
// 3. Query the contract
// 4. Execute a transaction on the contract
func TestWasmIntegration(t *testing.T) {
	// Setup test app with funded accounts
	setup := setupWasmTestApp(t)
	app := setup.App
	ctx := setup.Ctx

	// Use simulation-generated accounts (they are already funded)
	require.GreaterOrEqual(t, len(setup.Accounts), 3, "need at least 3 accounts for testing")
	creator := setup.Accounts[0]
	verifier := setup.Accounts[1]
	beneficiary := setup.Accounts[2]

	// Check that the creator has funds
	creatorBalance := app.BankKeeper.GetAllBalances(ctx, creator.Address)
	t.Logf("Creator balance: %s", creatorBalance.String())

	// Step 1: Store the hackatom contract
	t.Run("StoreContract", func(t *testing.T) {
		wasmCode := contracts.HackatomContractWasm()
		require.NotEmpty(t, wasmCode, "hackatom contract should not be empty")

		codeID, err := storeContract(ctx, app, creator.Address, wasmCode)
		require.NoError(t, err)
		require.Equal(t, uint64(1), codeID, "first stored contract should have code ID 1")

		// Verify code was stored
		codeInfo := app.WasmKeeper.GetCodeInfo(ctx, codeID)
		require.NotNil(t, codeInfo)
		require.Equal(t, creator.Address.String(), codeInfo.Creator)
		t.Logf("Contract stored with code ID: %d", codeID)
	})

	// Step 2: Instantiate the contract
	var contractAddr sdk.AccAddress
	t.Run("InstantiateContract", func(t *testing.T) {
		initMsg := contracts.HackatomInitMsg{
			Verifier:    verifier.Address.String(),
			Beneficiary: beneficiary.Address.String(),
		}
		initMsgBytes, err := json.Marshal(initMsg)
		require.NoError(t, err)

		// Instantiate without deposit (simulation may disable transfers for certain denoms)
		contractAddr, err = instantiateContract(ctx, app, creator.Address, 1, initMsgBytes, "hackatom-test", nil)
		require.NoError(t, err)
		require.NotEmpty(t, contractAddr)
		t.Logf("Contract instantiated at: %s", contractAddr.String())

		// Verify contract info
		contractInfo := app.WasmKeeper.GetContractInfo(ctx, contractAddr)
		require.NotNil(t, contractInfo)
		require.Equal(t, uint64(1), contractInfo.CodeID)
		require.Equal(t, creator.Address.String(), contractInfo.Creator)
		require.Equal(t, "hackatom-test", contractInfo.Label)
	})

	// Step 3: Query the contract
	t.Run("QueryContract", func(t *testing.T) {
		require.NotEmpty(t, contractAddr, "contract must be instantiated first")

		queryMsg := contracts.HackatomQueryMsg{
			Verifier: &struct{}{},
		}
		queryMsgBytes, err := json.Marshal(queryMsg)
		require.NoError(t, err)

		result, err := app.WasmKeeper.QuerySmart(ctx, contractAddr, queryMsgBytes)
		require.NoError(t, err)

		var response contracts.VerifierResponse
		err = json.Unmarshal(result, &response)
		require.NoError(t, err)
		require.Equal(t, verifier.Address.String(), response.Verifier)
		t.Logf("Contract verifier: %s", response.Verifier)
	})

	// Step 4: Verify contract was created (no funds since we didn't deposit)
	t.Run("VerifyContractCreated", func(t *testing.T) {
		require.NotEmpty(t, contractAddr, "contract must be instantiated first")

		// Contract info should exist
		contractInfo := app.WasmKeeper.GetContractInfo(ctx, contractAddr)
		require.NotNil(t, contractInfo)
		require.Equal(t, "hackatom-test", contractInfo.Label)
		t.Logf("Contract verified at: %s", contractAddr.String())
	})

	// Step 5: Test execute functionality (release without funds - will succeed but transfer 0)
	t.Run("ExecuteRelease", func(t *testing.T) {
		require.NotEmpty(t, contractAddr, "contract must be instantiated first")

		executeMsg := contracts.HackatomExecuteMsg{
			Release: &struct{}{},
		}
		executeMsgBytes, err := json.Marshal(executeMsg)
		require.NoError(t, err)

		// Execute release as verifier (releases 0 funds since contract has no balance)
		_, err = executeContract(ctx, app, verifier.Address, contractAddr, executeMsgBytes, nil)
		require.NoError(t, err)
		t.Logf("Execute release completed successfully")
	})
}

// TestWasmModuleParams tests that WASM module params are correctly set.
func TestWasmModuleParams(t *testing.T) {
	setup := setupWasmTestApp(t)

	params := setup.App.WasmKeeper.GetParams(setup.Ctx)
	require.NotNil(t, params)

	// Verify WASM is enabled (code upload allowed)
	require.NotNil(t, params.CodeUploadAccess)
	t.Logf("WASM params: CodeUploadAccess=%v, InstantiateDefaultPermission=%v",
		params.CodeUploadAccess.Permission, params.InstantiateDefaultPermission)
}

// TestWasmListCodes tests listing stored codes.
func TestWasmListCodes(t *testing.T) {
	setup := setupWasmTestApp(t)
	app := setup.App
	ctx := setup.Ctx

	// Initially no codes
	var codeInfos []wasmtypes.CodeInfo
	app.WasmKeeper.IterateCodeInfos(ctx, func(codeID uint64, info wasmtypes.CodeInfo) bool {
		codeInfos = append(codeInfos, info)
		return false
	})
	require.Empty(t, codeInfos)

	// Store a contract using a simulation account
	require.NotEmpty(t, setup.Accounts)
	creator := setup.Accounts[0]

	_, err := storeContract(ctx, app, creator.Address, contracts.HackatomContractWasm())
	require.NoError(t, err)

	// Now should have one code
	codeInfos = nil
	app.WasmKeeper.IterateCodeInfos(ctx, func(codeID uint64, info wasmtypes.CodeInfo) bool {
		codeInfos = append(codeInfos, info)
		return false
	})
	require.Len(t, codeInfos, 1)
	t.Logf("Found %d stored codes", len(codeInfos))
}

// wasmTestSetup holds the test app and context along with funded accounts.
type wasmTestSetup struct {
	App      *App
	Ctx      sdk.Context
	Accounts []simtypes.Account
}

// setupWasmTestApp creates a test app with WASM enabled.
func setupWasmTestApp(t *testing.T) wasmTestSetup {
	t.Helper()

	db := dbm.NewMemDB()
	logger := log.NewNopLogger()

	appOptions := make(simtestutil.AppOptionsMap, 0)
	appOptions[flags.FlagHome] = t.TempDir()

	app := New(
		logger,
		db,
		nil,
		true,
		appOptions,
		baseapp.SetChainID(WasmTestChainID),
	)

	// Create random accounts for simulation
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	accounts := simtypes.RandomAccounts(r, 5) // Create 5 accounts for tests

	// Create config for AppStateFn
	config := simtypes.Config{
		ChainID:     WasmTestChainID,
		GenesisTime: time.Now().Unix(),
	}

	// Generate genesis state with validators using AppStateFn
	appStateFn := simtestutil.AppStateFn(app.AppCodec(), app.SimulationManager(), app.DefaultGenesis())
	appState, simAccounts, _, _ := appStateFn(r, accounts, config)

	// Initialize chain with genesis state
	_, err := app.InitChain(&abci.RequestInitChain{
		ChainId:         WasmTestChainID,
		AppStateBytes:   appState,
		ConsensusParams: simtestutil.DefaultConsensusParams,
	})
	require.NoError(t, err)

	// Commit genesis state
	_, err = app.Commit()
	require.NoError(t, err)

	// Create a checked context using the committed multi-store
	header := cmtproto.Header{
		Height:  app.LastBlockHeight(),
		Time:    time.Now().UTC(),
		ChainID: WasmTestChainID,
	}
	ctx := app.NewUncachedContext(false, header)

	// Ensure WASM params are set (simulation doesn't initialize them)
	wasmParams := wasmtypes.DefaultParams()
	err = app.WasmKeeper.SetParams(ctx, wasmParams)
	require.NoError(t, err)

	return wasmTestSetup{
		App:      app,
		Ctx:      ctx,
		Accounts: simAccounts,
	}
}

// getContractKeeper returns a PermissionedKeeper that exposes contract operations.
func getContractKeeper(app *App) *wasmkeeper.PermissionedKeeper {
	return wasmkeeper.NewDefaultPermissionKeeper(&app.WasmKeeper)
}

func storeContract(ctx sdk.Context, app *App, creator sdk.AccAddress, wasmCode []byte) (uint64, error) {
	contractKeeper := getContractKeeper(app)
	codeID, _, err := contractKeeper.Create(ctx, creator, wasmCode, nil)
	return codeID, err
}

func instantiateContract(ctx sdk.Context, app *App, creator sdk.AccAddress, codeID uint64, initMsg []byte, label string, deposit sdk.Coins) (sdk.AccAddress, error) {
	contractKeeper := getContractKeeper(app)
	contractAddr, _, err := contractKeeper.Instantiate(ctx, codeID, creator, creator, initMsg, label, deposit)
	return contractAddr, err
}

func executeContract(ctx sdk.Context, app *App, sender sdk.AccAddress, contractAddr sdk.AccAddress, msg []byte, funds sdk.Coins) ([]byte, error) {
	contractKeeper := getContractKeeper(app)
	return contractKeeper.Execute(ctx, contractAddr, sender, msg, funds)
}

// TestWasmStoreKey verifies the WASM store key is properly registered.
func TestWasmStoreKey(t *testing.T) {
	setup := setupWasmTestApp(t)

	storeKey := setup.App.GetKey(wasmtypes.StoreKey)
	require.NotNil(t, storeKey, "WASM store key should be registered")
	require.Equal(t, wasmtypes.StoreKey, storeKey.Name())
}

// TestMultipleContracts tests storing and instantiating multiple contracts.
func TestMultipleContracts(t *testing.T) {
	setup := setupWasmTestApp(t)
	app := setup.App
	ctx := setup.Ctx

	require.GreaterOrEqual(t, len(setup.Accounts), 5, "need at least 5 accounts")
	creator := setup.Accounts[0]

	// Store the same contract twice (simulating different versions)
	codeID1, err := storeContract(ctx, app, creator.Address, contracts.HackatomContractWasm())
	require.NoError(t, err)
	require.Equal(t, uint64(1), codeID1)

	codeID2, err := storeContract(ctx, app, creator.Address, contracts.HackatomContractWasm())
	require.NoError(t, err)
	require.Equal(t, uint64(2), codeID2)

	// Instantiate multiple instances of the first code
	// Use the same verifier/beneficiary for all instances
	for i := 0; i < 3; i++ {
		verifier := setup.Accounts[1]
		beneficiary := setup.Accounts[2]

		initMsg := contracts.HackatomInitMsg{
			Verifier:    verifier.Address.String(),
			Beneficiary: beneficiary.Address.String(),
		}
		initMsgBytes, err := json.Marshal(initMsg)
		require.NoError(t, err)

		contractAddr, err := instantiateContract(ctx, app, creator.Address, codeID1, initMsgBytes, "hackatom-instance-"+string(rune('A'+i)), nil)
		require.NoError(t, err)
		require.NotEmpty(t, contractAddr)
		t.Logf("Instance %d: %s", i+1, contractAddr.String())
	}

	// Count contracts
	var contractCount int
	app.WasmKeeper.IterateContractInfo(ctx, func(addr sdk.AccAddress, info wasmtypes.ContractInfo) bool {
		contractCount++
		return false
	})
	require.Equal(t, 3, contractCount)
	t.Logf("Total contracts instantiated: %d", contractCount)
}

