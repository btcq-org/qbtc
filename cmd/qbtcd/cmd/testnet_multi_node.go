package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/p2p"
	cmtconfig "github.com/cometbft/cometbft/config"
	types "github.com/cometbft/cometbft/types"
	tmtime "github.com/cometbft/cometbft/types/time"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/server"
	srvconfig "github.com/cosmos/cosmos-sdk/server/config"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	runtime "github.com/cosmos/cosmos-sdk/runtime"

	bifrostconfig "github.com/btcq-org/qbtc/bifrost/config"
	qbtctypes "github.com/btcq-org/qbtc/x/qbtc/types"
)

var (
	flagNodeDirPrefix         = "node-dir-prefix"
	flagPorts                 = "list-ports"
	flagNumValidators         = "v"
	flagOutputDir             = "output-dir"
	flagValidatorsStakeAmount = "validators-stake-amount"
	flagStartingIPAddress     = "starting-ip-address"

	// bifrost specific arguments
	flagBifrostStartBlockHeight = "bifrost-start-block-height"

	// bitcoin specific arguments
	flagBitcoinRPCHost     = "bitcoin-rpc-host"
	flagBitcoinRPCPort     = "bitcoin-rpc-port"
	flagBitcoinRPCUser     = "bitcoin-rpc-user"
	flagBitcoinRPCPassword = "bitcoin-rpc-password"
)

const nodeDirPerm = 0o755

type initArgs struct {
	algo                   string
	chainID                string
	keyringBackend         string
	minGasPrices           string
	nodeDirPrefix          string
	numValidators          int
	outputDir              string
	startingIPAddress      string
	validatorsStakesAmount map[int]sdk.Coin
	ports                  map[int]string

	// bifrost specific arguments
	bifrostStartBlockHeight int64

	// bitcoin specific arguments
	bitcoinRPCHost     string
	bitcoinRPCPort     int64
	bitcoinRPCUser     string
	bitcoinRPCPassword string
}

// NewTestnetMultiNodeCmd returns a cmd to initialize all files for tendermint testnet and application
func NewTestnetMultiNodeCmd(mbm module.BasicManager, genBalIterator banktypes.GenesisBalancesIterator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "multi-node",
		Short: "Initialize config directories & files for a multi-validator testnet running locally via separate processes (e.g. Docker Compose or similar)",
		Long: `multi-node will setup "v" number of directories and populate each with
necessary files (private validator, genesis, config, etc.) for running "v" validator nodes.

Booting up a network with these validator folders is intended to be used with Docker Compose,
or a similar setup where each node has a manually configurable IP address.

Note, strict routability for addresses is turned off in the config file.

Example:
	qbtcd multi-node --v 4 --output-dir ./.testnets --validators-stake-amount 1000000,200000,300000,400000 --list-ports 47222,50434,52851,44210
	`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			serverCtx := server.GetServerContextFromCmd(cmd)
			config := serverCtx.Config

			args := initArgs{}
			args.outputDir, _ = cmd.Flags().GetString(flagOutputDir)
			args.keyringBackend, _ = cmd.Flags().GetString(flags.FlagKeyringBackend)
			args.chainID, _ = cmd.Flags().GetString(flags.FlagChainID)
			args.minGasPrices, _ = cmd.Flags().GetString(server.FlagMinGasPrices)
			args.nodeDirPrefix, _ = cmd.Flags().GetString(flagNodeDirPrefix)
			args.startingIPAddress, _ = cmd.Flags().GetString(flagStartingIPAddress)
			args.numValidators, _ = cmd.Flags().GetInt(flagNumValidators)
			args.algo, _ = cmd.Flags().GetString(flags.FlagKeyType)

			args.ports = map[int]string{}
			args.validatorsStakesAmount = make(map[int]sdk.Coin)
			top := 0
			// If the flag string is invalid, the amount will default to 100000000.
			if s, err := cmd.Flags().GetString(flagValidatorsStakeAmount); err == nil {
				for _, amount := range strings.Split(s, ",") {
					a, ok := math.NewIntFromString(amount)
					if !ok {
						continue
					}
					args.validatorsStakesAmount[top] = sdk.NewCoin(sdk.DefaultBondDenom, a)
					top += 1
				}

			}
			top = 0
			if s, err := cmd.Flags().GetString(flagPorts); err == nil {
				if s == "" {
					for i := 0; i < args.numValidators; i++ {
						args.ports[top] = strconv.Itoa(26657 - 3*i)
						top += 1
					}
				} else {
					for _, port := range strings.Split(s, ",") {
						args.ports[top] = port
						top += 1
					}
				}
			}

			// bifrost
			args.bifrostStartBlockHeight, _ = cmd.Flags().GetInt64(flagBifrostStartBlockHeight)
			if args.bifrostStartBlockHeight == 0 {
				return fmt.Errorf("bifrost start block height is required")
			}
			args.bitcoinRPCHost, _ = cmd.Flags().GetString(flagBitcoinRPCHost)
			args.bitcoinRPCPort, _ = cmd.Flags().GetInt64(flagBitcoinRPCPort)
			args.bitcoinRPCUser, _ = cmd.Flags().GetString(flagBitcoinRPCUser)
			args.bitcoinRPCPassword, _ = cmd.Flags().GetString(flagBitcoinRPCPassword)

			return initTestnetFiles(clientCtx, cmd, config, mbm, genBalIterator, args)
		},
	}

	addTestnetFlagsToCmd(cmd)
	cmd.Flags().String(flagPorts, "", "Ports of nodes (default 26657,26654,26651,26648.. )")
	cmd.Flags().String(flagNodeDirPrefix, "validator", "Prefix the directory name for each node with (node results in node0, node1, ...)")
	cmd.Flags().String(flagValidatorsStakeAmount, "100000000,100000000,100000000,100000000", "Amount of stake for each validator")
	cmd.Flags().String(flagStartingIPAddress, "localhost", "Starting IP address (192.168.0.1 results in persistent peers list ID0@192.168.0.1:46656, ID1@192.168.0.2:46656, ...)")
	cmd.Flags().String(flags.FlagKeyringBackend, "test", "Select keyring's backend (os|file|test)")

	// bifrost specific arguments
	cmd.Flags().Int64(flagBifrostStartBlockHeight, 0, "Start block height for bifrost")

	// bitcoin specific arguments
	cmd.Flags().String(flagBitcoinRPCHost, "localhost", "Bitcoin RPC host")
	cmd.Flags().Int64(flagBitcoinRPCPort, 8332, "Bitcoin RPC port")
	cmd.Flags().String(flagBitcoinRPCUser, "bitcoinrpc", "Bitcoin RPC user")
	cmd.Flags().String(flagBitcoinRPCPassword, "", "Bitcoin RPC password (consider using BITCOIN_RPC_PASSWORD env var)")
	return cmd
}

func addTestnetFlagsToCmd(cmd *cobra.Command) {
	cmd.Flags().Int(flagNumValidators, 4, "Number of validators to initialize the testnet with")
	cmd.Flags().StringP(flagOutputDir, "o", "./.testnets", "Directory to store initialization data for the testnet")
	cmd.Flags().String(flags.FlagChainID, "", "genesis file chain-id, if left blank will be randomly created")
	cmd.Flags().String(server.FlagMinGasPrices, fmt.Sprintf("0.0001%s", sdk.DefaultBondDenom), "Minimum gas prices to accept for transactions; All fees in a tx must meet this minimum (e.g. 0.01photino,0.001stake)")
	cmd.Flags().String(flags.FlagKeyType, string(hd.Secp256k1Type), "Key signing algorithm to generate keys for")

	// support old flags name for backwards compatibility
	cmd.Flags().SetNormalizeFunc(func(f *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "algo" {
			name = flags.FlagKeyType
		}

		return pflag.NormalizedName(name)
	})
}

type PeerInfo struct {
	Validator   string
	PeerAddress string
}

// initTestnetFiles initializes testnet files for a testnet to be run in a separate process
func initTestnetFiles(
	clientCtx client.Context,
	cmd *cobra.Command,
	nodeConfig *cmtconfig.Config,
	mbm module.BasicManager,
	genBalIterator banktypes.GenesisBalancesIterator,
	args initArgs,
) error {
	if args.chainID == "" {
		args.chainID = "chain-" + generateRandomString(6)
	}
	nodeIDs := make([]string, args.numValidators)
	valPubKeys := make([]cryptotypes.PubKey, args.numValidators)

	appConfig := srvconfig.DefaultConfig()
	appConfig.MinGasPrices = args.minGasPrices
	if args.minGasPrices == "" {
		appConfig.MinGasPrices = "0.0001" + sdk.DefaultBondDenom
	}
	appConfig.API.Enable = false
	// 	appConfig.MinGasPrices = "0.0001" + sdk.DefaultBondDenom
	appConfig.Telemetry.EnableHostnameLabel = false
	appConfig.Telemetry.Enabled = false
	appConfig.Telemetry.PrometheusRetentionTime = 0

	var (
		genAccounts     []authtypes.GenesisAccount
		genBalances     []banktypes.Balance
		genFiles        []string
		persistentPeers string
		gentxsFiles     []string
		p2pPeers        []PeerInfo
	)

	inBuf := bufio.NewReader(cmd.InOrStdin())

	nodes := make([]ValidatorNode, args.numValidators)
	for i := range nodes {
		nodes[i] = ValidatorNode{
			Name:              fmt.Sprintf("node_%d", i),
			RPCPort:           args.ports[i],
			Volume:            fmt.Sprintf("validator%d", i),
			BifrostPort:       strconv.Itoa(30006 - 3*i),
			BifrostHealthPort: strconv.Itoa(30007 - 3*i),
		}
	}

	for i := 0; i < args.numValidators; i++ {
		nodeDirName := fmt.Sprintf("%s%d", args.nodeDirPrefix, i)
		nodeDir := filepath.Join(args.outputDir, nodeDirName)
		gentxsDir := filepath.Join(args.outputDir, nodeDirName, "config", "gentx")
		nodeConfig.SetRoot(nodeDir)
		nodeConfig.Moniker = nodeDirName
		nodeConfig.RPC.ListenAddress = "tcp://0.0.0.0:" + args.ports[i]
		nodeConfig.RPC.CORSAllowedOrigins = []string{"*"}

		var err error
		if err := os.MkdirAll(filepath.Join(nodeDir, "config"), nodeDirPerm); err != nil {
			_ = os.RemoveAll(args.outputDir)
			return err
		}

		bifrostHome := filepath.Join(nodeDir, "bifrost")
		// Create bifrost home directory
		err = ensureDir(bifrostHome)
		if err != nil {
			_ = os.RemoveAll(args.outputDir)
			return err
		}

		kstore, err := keystore.NewFileKeyStore(bifrostHome)
		if err != nil {
			return err
		}
		p2pKey, err := keystore.GetOrCreateKey(kstore, "bifrost-p2p-key")
		if err != nil {
			return fmt.Errorf("failed to get or create p2p key, err: %w", err)
		}
		p2pPrivKey, err := crypto.UnmarshalPrivateKey(p2pKey.Body)
		if err != nil {
			return fmt.Errorf("failed to unmarshal p2p key, err: %w", err)
		}
		id, err := p2p.ID(p2pPrivKey)
		if err != nil {
			return fmt.Errorf("failed to get peer id, err: %w", err)
		}

		nodeIDs[i], valPubKeys[i], err = genutil.InitializeNodeValidatorFiles(nodeConfig)
		if err != nil {
			_ = os.RemoveAll(args.outputDir)
			return err
		}

		memo := fmt.Sprintf("%s@node_%d:"+strconv.Itoa(26656-3*i), nodeIDs[i], i)

		if persistentPeers == "" {
			persistentPeers = memo
		} else {
			persistentPeers = persistentPeers + "," + memo
		}

		genFiles = append(genFiles, nodeConfig.GenesisFile())

		kb, err := keyring.New(sdk.KeyringServiceName(), args.keyringBackend, nodeDir, inBuf, clientCtx.Codec)
		if err != nil {
			return err
		}

		keyringAlgos, _ := kb.SupportedAlgorithms()
		algo, err := keyring.NewSigningAlgoFromString(args.algo, keyringAlgos)
		if err != nil {
			return err
		}

		addr, secret, err := testutil.GenerateSaveCoinKey(kb, nodeDirName, "", true, algo)
		if err != nil {
			_ = os.RemoveAll(args.outputDir)
			return err
		}

		peerInfo := PeerInfo{
			Validator:   sdk.ValAddress(addr).String(),
			PeerAddress: id.String(),
		}
		p2pPeers = append(p2pPeers, peerInfo)

		info := map[string]string{"secret": secret}

		cliPrint, err := json.Marshal(info)
		if err != nil {
			return err
		}

		// save private key seed words
		file := filepath.Join(nodeDir, fmt.Sprintf("%v.json", "key_seed"))
		if err := writeFile(file, nodeDir, cliPrint); err != nil {
			return err
		}

		accTokens := sdk.TokensFromConsensusPower(1000, sdk.DefaultPowerReduction)
		accStakingTokens := sdk.TokensFromConsensusPower(500, sdk.DefaultPowerReduction)
		coins := sdk.Coins{
			sdk.NewCoin("testtoken", accTokens),
			sdk.NewCoin(sdk.DefaultBondDenom, accStakingTokens),
		}

		genBalances = append(genBalances, banktypes.Balance{Address: addr.String(), Coins: coins.Sort()})
		genAccounts = append(genAccounts, authtypes.NewBaseAccount(addr, nil, 0, 0))

		var valTokens sdk.Coin
		valTokens, ok := args.validatorsStakesAmount[i]
		if !ok {
			valTokens = sdk.NewCoin(sdk.DefaultBondDenom, sdk.TokensFromConsensusPower(100, sdk.DefaultPowerReduction))
		}
		createValMsg, err := stakingtypes.NewMsgCreateValidator(
			sdk.ValAddress(addr).String(),
			valPubKeys[i],
			valTokens,
			stakingtypes.NewDescription(nodeDirName, "", "", "", ""),
			stakingtypes.NewCommissionRates(math.LegacyOneDec(), math.LegacyOneDec(), math.LegacyOneDec()),
			math.OneInt(),
		)
		if err != nil {
			return err
		}

		txBuilder := clientCtx.TxConfig.NewTxBuilder()
		if err := txBuilder.SetMsgs(createValMsg); err != nil {
			return err
		}

		txBuilder.SetMemo(memo)

		txFactory := tx.Factory{}
		txFactory = txFactory.
			WithChainID(args.chainID).
			WithMemo(memo).
			WithKeybase(kb).
			WithTxConfig(clientCtx.TxConfig)

		if err := tx.Sign(cmd.Context(), txFactory, nodeDirName, txBuilder, true); err != nil {
			return err
		}

		txBz, err := clientCtx.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
		if err != nil {
			return err
		}
		file = filepath.Join(gentxsDir, fmt.Sprintf("%v.json", "gentx-"+nodeIDs[i]))
		gentxsFiles = append(gentxsFiles, file)
		if err := writeFile(file, gentxsDir, txBz); err != nil {
			return err
		}

		appConfig.GRPC.Address = "0.0.0.0:" + strconv.Itoa(9090-2*i)
		appConfig.API.Address = "tcp://0.0.0.0:" + strconv.Itoa(1317-i)
		srvconfig.WriteConfigFile(filepath.Join(nodeDir, "config", "app.toml"), appConfig)

		bitcoinDataHome := filepath.Join(nodeDir, "bitcoin_data")
		// Create bitcoin data home directory
		err = ensureDir(bitcoinDataHome)
		if err != nil {
			_ = os.RemoveAll(args.outputDir)
			return err
		}
		if err := initBifrostFiles(args,
			bifrostHome,
			fmt.Sprintf("node_%d:50051", i),
			fmt.Sprintf("node_%d:%d", i, 9090-2*i),
			"/qbtc_data/.qbtc/bitcoin_data"); err != nil {
			return err
		}
	}

	if err := initGenFiles(clientCtx, mbm, args.chainID, genAccounts, genBalances, genFiles, args.numValidators, p2pPeers); err != nil {
		return err
	}
	// copy gentx file
	for i := 0; i < args.numValidators; i++ {
		for _, file := range gentxsFiles {
			nodeDirName := fmt.Sprintf("%s%d", args.nodeDirPrefix, i)
			nodeDir := filepath.Join(args.outputDir, nodeDirName)
			gentxsDir := filepath.Join(nodeDir, "config", "gentx")

			yes, err := isSubDir(file, gentxsDir)
			if err != nil || yes {
				continue
			}
			_, err = copyFile(file, gentxsDir)
			if err != nil {
				return err
			}
		}
	}
	err := collectGenFiles(
		clientCtx, nodeConfig, nodeIDs, valPubKeys,
		genBalIterator,
		clientCtx.TxConfig.SigningContext().ValidatorAddressCodec(),
		persistentPeers, args,
	)
	if err != nil {
		return err
	}

	def, err := docker(nodes, "localnet")
	if err != nil {
		return err
	}

	dockComposeFile := filepath.Join(args.outputDir, "docker-compose.yml")

	err = writeFile(dockComposeFile, args.outputDir, []byte(def))
	if err != nil {
		return err
	}

	cmd.PrintErrf("Successfully initialized %d node directories\n", args.numValidators)
	return nil
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %q: %w", dir, err)
	}
	return nil
}
func writeFile(file, dir string, contents []byte) error {

	err := ensureDir(dir)
	if err != nil {
		return err
	}

	if err := os.WriteFile(file, contents, 0o644); err != nil {
		return err
	}

	return nil
}

func initBifrostFiles(args initArgs, outputDir, ebifrostAddress, nodeGRPCAddress, dataDir string) error {
	bifrostConfig := bifrostconfig.DefaultConfig()
	bifrostConfig.StartBlockHeight = args.bifrostStartBlockHeight
	bifrostConfig.BitcoinConfig.Host = args.bitcoinRPCHost
	bifrostConfig.BitcoinConfig.Port = args.bitcoinRPCPort
	bifrostConfig.BitcoinConfig.RPCUser = args.bitcoinRPCUser
	bifrostConfig.BitcoinConfig.Password = args.bitcoinRPCPassword
	bifrostConfig.BitcoinConfig.LocalDBPath = filepath.Join(dataDir, "db")

	bifrostConfig.RootPath = "/qbtc_data/.qbtc/bifrost"
	bifrostConfig.KeyName = "bifrost-p2p-key"
	bifrostConfig.ListenAddr = "0.0.0.0:30006"
	bifrostConfig.ExternalIP = ""

	bifrostConfig.QBTCHome = "/qbtc_data/.qbtc"
	bifrostConfig.EbifrostAddress = ebifrostAddress
	bifrostConfig.QBTCGRPCAddress = nodeGRPCAddress

	bifrostConfigJSON, err := json.Marshal(bifrostConfig)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(outputDir, "config.json"), outputDir, bifrostConfigJSON)
}

func initGenFiles(
	clientCtx client.Context, mbm module.BasicManager, chainID string,
	genAccounts []authtypes.GenesisAccount, genBalances []banktypes.Balance,
	genFiles []string, numValidators int, p2pPeers []PeerInfo,
) error {
	appGenState := mbm.DefaultGenesis(clientCtx.Codec)

	// set the accounts in the genesis state
	var authGenState authtypes.GenesisState
	clientCtx.Codec.MustUnmarshalJSON(appGenState[authtypes.ModuleName], &authGenState)

	accounts, err := authtypes.PackAccounts(genAccounts)
	if err != nil {
		return err
	}

	authGenState.Accounts = accounts
	appGenState[authtypes.ModuleName] = clientCtx.Codec.MustMarshalJSON(&authGenState)

	// set the balances in the genesis state
	var bankGenState banktypes.GenesisState
	clientCtx.Codec.MustUnmarshalJSON(appGenState[banktypes.ModuleName], &bankGenState)

	bankGenState.Balances = banktypes.SanitizeGenesisBalances(genBalances)
	for _, bal := range bankGenState.Balances {
		bankGenState.Supply = bankGenState.Supply.Add(bal.Coins...)
	}
	appGenState[banktypes.ModuleName] = clientCtx.Codec.MustMarshalJSON(&bankGenState)

	var btcqGenesis qbtctypes.GenesisState
	clientCtx.Codec.MustUnmarshalJSON(appGenState[qbtctypes.ModuleName], &btcqGenesis)

	btcqGenesis.PeerAddresses = make([]qbtctypes.GenesisPeerAddress, len(p2pPeers))
	for i, peer := range p2pPeers {
		peerAddress := fmt.Sprintf("%s@%s:%s", peer.PeerAddress, fmt.Sprintf("node_%d_bifrost", i), "30006")
		btcqGenesis.PeerAddresses[i] = qbtctypes.GenesisPeerAddress{
			Validator:   peer.Validator,
			PeerAddress: peerAddress,
		}
	}
	appGenState[qbtctypes.ModuleName] = clientCtx.Codec.MustMarshalJSON(&btcqGenesis)
	appGenStateJSON, err := json.MarshalIndent(appGenState, "", "  ")
	if err != nil {
		return err
	}

	genDoc := types.GenesisDoc{
		ChainID:    chainID,
		AppState:   appGenStateJSON,
		Validators: nil,
	}

	// generate empty genesis files for each validator and save
	for i := 0; i < numValidators; i++ {
		if err := genDoc.SaveAs(genFiles[i]); err != nil {
			return err
		}
	}
	return nil
}

func collectGenFiles(
	clientCtx client.Context, nodeConfig *cmtconfig.Config,
	nodeIDs []string, valPubKeys []cryptotypes.PubKey,
	genBalIterator banktypes.GenesisBalancesIterator,
	valAddrCodec runtime.ValidatorAddressCodec, persistentPeers string,
	args initArgs,
) error {
	chainID := args.chainID
	numValidators := args.numValidators
	outputDir := args.outputDir
	nodeDirPrefix := args.nodeDirPrefix

	var appState json.RawMessage
	genTime := tmtime.Now()

	for i := 0; i < numValidators; i++ {
		nodeDirName := fmt.Sprintf("%s%d", nodeDirPrefix, i)
		nodeDir := filepath.Join(outputDir, nodeDirName)
		gentxsDir := filepath.Join(nodeDir, "config", "gentx")
		nodeConfig.Moniker = nodeDirName

		nodeConfig.SetRoot(nodeDir)

		nodeID, valPubKey := nodeIDs[i], valPubKeys[i]
		initCfg := genutiltypes.NewInitConfig(chainID, gentxsDir, nodeID, valPubKey)

		appGenesis, err := genutiltypes.AppGenesisFromFile(nodeConfig.GenesisFile())
		if err != nil {
			return err
		}

		nodeAppState, err := genutil.GenAppStateFromConfig(clientCtx.Codec, clientCtx.TxConfig, nodeConfig, initCfg, appGenesis, genBalIterator, genutiltypes.DefaultMessageValidator,
			valAddrCodec)
		if err != nil {
			return err
		}

		nodeConfig.P2P.PersistentPeers = persistentPeers
		nodeConfig.P2P.AllowDuplicateIP = true
		nodeConfig.P2P.ListenAddress = "tcp://0.0.0.0:" + strconv.Itoa(26656-3*i)
		nodeConfig.RPC.ListenAddress = "tcp://0.0.0.0:" + args.ports[i]
		nodeConfig.ProxyApp = "tcp://127.0.0.1:" + strconv.Itoa(26658-3*i)
		nodeConfig.Instrumentation.PrometheusListenAddr = ":" + strconv.Itoa(26660+i)
		nodeConfig.Instrumentation.Prometheus = true
		cmtconfig.WriteConfigFile(filepath.Join(nodeConfig.RootDir, "config", "config.toml"), nodeConfig)
		if appState == nil {
			// set the canonical application state (they should not differ)
			appState = nodeAppState
		}

		genFile := nodeConfig.GenesisFile()

		// overwrite each validator's genesis file to have a canonical genesis time
		if err := genutil.ExportGenesisFileWithTime(genFile, chainID, nil, appState, genTime); err != nil {
			return err
		}
	}

	return nil
}

func copyFile(src, dstDir string) (int64, error) {
	// Extract the file name from the source path
	fileName := filepath.Base(src)

	// Create the full destination path (directory + file name)
	dst := filepath.Join(dstDir, fileName)

	// Open the source file
	sourceFile, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer sourceFile.Close()

	// Create the destination file
	destinationFile, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destinationFile.Close()

	// Copy content from the source file to the destination file
	bytesCopied, err := io.Copy(destinationFile, sourceFile)
	if err != nil {
		return 0, err
	}

	// Ensure the content is written to the destination file
	err = destinationFile.Sync()
	if err != nil {
		return 0, err
	}

	return bytesCopied, nil
}

// isSubDir checks if dstDir is a parent directory of src
func isSubDir(src, dstDir string) (bool, error) {
	// Get the absolute path of src and dstDir
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return false, err
	}
	absDstDir, err := filepath.Abs(dstDir)
	if err != nil {
		return false, err
	}

	// Check if absSrc is within absDstDir
	relativePath, err := filepath.Rel(absDstDir, absSrc)
	if err != nil {
		return false, err
	}

	// If the relative path doesn't go up the directory tree (doesn't contain ".."), it is inside dstDir
	isInside := !strings.HasPrefix(relativePath, "..") && !filepath.IsAbs(relativePath)
	return isInside, nil
}

// generateRandomString generates a random string of the specified length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

type ValidatorNode struct {
	Name              string
	Volume            string
	RPCPort           string
	BifrostPort       string
	BifrostHealthPort string
}

const dockerComposeDefinition = `
services:{{range $validator := .Validators }}
	{{ $validator.Name }}:
		image: btcq-org/qbtc:{{ $.Tag }}
		restart: always
		ports:
			- "{{ $validator.RPCPort }}:26657"
		volumes:
			- ./{{ $validator.Volume }}:/qbtc_data/.qbtc
	{{ $validator.Name }}_bifrost:
		image: btcq-org/qbtc:{{ $.Tag }}
		restart: always
		command: [ "bifrost", "--config", "/qbtc_data/.qbtc/bifrost/config.json"]
		ports:
			- "{{ $validator.BifrostPort }}:30006"
			- "{{ $validator.BifrostHealthPort }}:30007"
		volumes:
			- ./{{ $validator.Volume }}:/qbtc_data/.qbtc
		depends_on:
			- {{ $validator.Name }}
{{end}}
`

func docker(validators []ValidatorNode, tag string) (string, error) {
	def := strings.ReplaceAll(dockerComposeDefinition, "\t", "  ")
	t, err := template.New("definition").Parse(def)
	if err != nil {
		return "", err
	}
	d := struct {
		Validators []ValidatorNode
		Tag        string
	}{Validators: validators, Tag: tag}

	buf := bytes.NewBufferString("")
	err = t.Execute(buf, d)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
