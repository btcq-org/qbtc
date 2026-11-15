package btcreader_test

import (
	"context"
	"testing"

	"cosmossdk.io/log/v2"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	"github.com/stretchr/testify/require"
	protov2 "google.golang.org/protobuf/proto"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
	"github.com/btcq-org/qbtc/x/qbtc/module"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

const (
	testMaxGas  = 1_000_000
	injectGas   = 5 * testMaxGas
	userTxGas   = 100_000
	userTxCount = 3
)

// gasServer burns a fixed amount of gas for each message it handles.
type gasServer struct {
	types.UnimplementedMsgServer
}

func (gasServer) SetMsgReportBlock(ctx context.Context, _ *types.MsgBtcBlock) (*types.MsgEmpty, error) {
	sdk.UnwrapSDKContext(ctx).GasMeter().ConsumeGas(injectGas, "bitcoin blocks")
	return &types.MsgEmpty{}, nil
}

func (gasServer) UpdateParam(ctx context.Context, _ *types.MsgUpdateParam) (*types.MsgEmpty, error) {
	sdk.UnwrapSDKContext(ctx).GasMeter().ConsumeGas(userTxGas, "user tx")
	return &types.MsgEmpty{}, nil
}

// userTx is a regular transaction with a gas limit.
type userTx struct {
	msgs []sdk.Msg
	cdc  codec.Codec
}

func (t userTx) GetMsgs() []sdk.Msg { return t.msgs }

func (t userTx) GetMsgsV2() ([]protov2.Message, error) {
	out := make([]protov2.Message, len(t.msgs))
	for i, msg := range t.msgs {
		msgAny, err := codectypes.NewAnyWithValue(msg)
		if err != nil {
			return nil, err
		}
		if _, out[i], err = t.cdc.GetMsgAnySigners(msgAny); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type paramStore struct{ cp *cmtproto.ConsensusParams }

func (s *paramStore) Get(context.Context) (cmtproto.ConsensusParams, error) { return *s.cp, nil }
func (s *paramStore) Has(context.Context) (bool, error)                     { return s.cp != nil, nil }
func (s *paramStore) Set(_ context.Context, cp cmtproto.ConsensusParams) error {
	s.cp = &cp
	return nil
}

// A batch of Bitcoin blocks may use more gas than block.max_gas. The SDK
// leaves the block gas meter off by default and relies on ProcessProposal, which
// leaves the inject tx out. With the meter on, the inject tx must still not use
// it up: it would fail itself, and every tx after it would find no gas left.
func TestInjectTxDoesNotUseBlockGas(t *testing.T) {
	for _, disableBlockGasMeter := range []bool{true, false} {
		res := finalizeInjectBlock(t, disableBlockGasMeter)
		require.Len(t, res.TxResults, 1+userTxCount)
		for i, r := range res.TxResults {
			require.Zero(t, r.Code, "block gas meter disabled %v, tx %d: %s", disableBlockGasMeter, i, r.Log)
		}
		require.EqualValues(t, injectGas, res.TxResults[0].GasUsed)
	}
}

// finalizeInjectBlock runs one block of an inject tx and userTxCount user txs
// under block.max_gas = testMaxGas.
func finalizeInjectBlock(t *testing.T, disableBlockGasMeter bool) *abci.ResponseFinalizeBlock {
	t.Helper()
	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	signer := sdk.AccAddress("signer______________").String()

	inject := btcreader.NewInjectTx(encCfg.Codec, []sdk.Msg{&types.MsgBtcBlock{
		Blocks:             []*types.BtcBlock{{Height: 1, Hash: "00", BlockContent: []byte{1}}},
		ExtendedCommitInfo: []byte{1},
		Signer:             signer,
	}})
	user := userTx{cdc: encCfg.Codec, msgs: []sdk.Msg{&types.MsgUpdateParam{
		Authority: signer,
		Key:       constants.MinUtxoConfirmationBlocks.String(),
		Value:     1,
	}}}
	txs := map[string]sdk.Tx{"inject": inject, "user": user}
	decode := func(bz []byte) (sdk.Tx, error) { return txs[string(bz)], nil }

	app := baseapp.NewBaseApp(t.Name(), log.NewNopLogger(), dbm.NewMemDB(), decode)
	app.SetDisableBlockGasMeter(disableBlockGasMeter)
	app.SetInterfaceRegistry(encCfg.InterfaceRegistry)
	types.RegisterMsgServer(app.MsgServiceRouter(), &gasServer{})
	app.SetParamStore(&paramStore{})
	app.SetAnteHandler(sdk.ChainAnteDecorators(btcreader.NewInjectedTxDecorator()))
	app.MountStores(storetypes.NewKVStoreKey("test"))
	require.NoError(t, app.LoadLatestVersion())

	cp := cmttypes.DefaultConsensusParams().ToProto()
	cp.Block.MaxGas = testMaxGas
	_, err := app.InitChain(&abci.RequestInitChain{ConsensusParams: &cp, InitialHeight: 1})
	require.NoError(t, err)

	block := [][]byte{[]byte("inject")}
	for range userTxCount {
		block = append(block, []byte("user"))
	}
	res, err := app.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Txs: block})
	require.NoError(t, err)
	return res
}
