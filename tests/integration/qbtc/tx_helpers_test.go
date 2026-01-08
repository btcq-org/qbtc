package qbtc_test

import (
	"testing"
	"time"

	"github.com/btcq-org/qbtc/app"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/client"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
)

// GenSignedTx generates a signed transaction with the given messages.
func (s *IntegrationTestSuite) GenSignedTx(
	txConfig client.TxConfig,
	msgs []sdk.Msg,
	feeAmt sdk.Coins,
	gas uint64,
	chainID string,
	accNums, accSeqs []uint64,
	priv ...cryptotypes.PrivKey,
) (sdk.Tx, error) {
	sigs := make([]signing.SignatureV2, len(priv))

	// Create first round of signatures (empty)
	for i, p := range priv {
		sigs[i] = signing.SignatureV2{
			PubKey: p.PubKey(),
			Data: &signing.SingleSignatureData{
				SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
				Signature: nil,
			},
			Sequence: accSeqs[i],
		}
	}

	txBuilder := txConfig.NewTxBuilder()
	if err := txBuilder.SetMsgs(msgs...); err != nil {
		return nil, err
	}
	if err := txBuilder.SetSignatures(sigs...); err != nil {
		return nil, err
	}
	txBuilder.SetFeeAmount(feeAmt)
	txBuilder.SetGasLimit(gas)

	// Create second round of signatures (with actual signatures)
	for i, p := range priv {
		signerData := authsigning.SignerData{
			ChainID:       chainID,
			AccountNumber: accNums[i],
			Sequence:      accSeqs[i],
		}

		signBytes, err := authsigning.GetSignBytesAdapter(
			sdk.Context{},
			txConfig.SignModeHandler(),
			signing.SignMode_SIGN_MODE_DIRECT,
			signerData,
			txBuilder.GetTx(),
		)
		if err != nil {
			return nil, err
		}

		sig, err := p.Sign(signBytes)
		if err != nil {
			return nil, err
		}

		sigs[i] = signing.SignatureV2{
			PubKey: p.PubKey(),
			Data: &signing.SingleSignatureData{
				SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
				Signature: sig,
			},
			Sequence: accSeqs[i],
		}
	}

	if err := txBuilder.SetSignatures(sigs...); err != nil {
		return nil, err
	}

	return txBuilder.GetTx(), nil
}

// SignAndDeliver signs a transaction and delivers it to the app.
// Returns the result and any error.
func (s *IntegrationTestSuite) SignAndDeliver(

	msgs []sdk.Msg,
	chainID string,
	accNums, accSeqs []uint64,
	priv ...cryptotypes.PrivKey,
) (*abci.ExecTxResult, error) {
	s.T().Helper()

	tx, err := s.GenSignedTx(
		s.app.TxConfig(),
		msgs,
		sdk.NewCoins(sdk.NewCoin(s.bondDenom, sdkmath.NewInt(10000))), // Fee
		300000, // Gas limit
		chainID,
		accNums,
		accSeqs,
		priv...,
	)
	if err != nil {
		return nil, err
	}

	txBytes, err := s.app.TxConfig().TxEncoder()(tx)
	if err != nil {
		return nil, err
	}

	// Deliver the transaction
	res, err := s.app.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height: s.app.LastBlockHeight() + 1,
		Txs:    [][]byte{txBytes},
	})
	if err != nil {
		return nil, err
	}

	// Commit the block
	_, err = s.app.Commit()
	if err != nil {
		return nil, err
	}

	if len(res.TxResults) > 0 {
		return res.TxResults[0], nil
	}

	return nil, nil
}

// SignCheckDeliver signs a transaction, optionally simulates it, and delivers it.
// expSimPass indicates if simulation should pass.
// expPass indicates if delivery should pass.
func (s *IntegrationTestSuite) SignCheckDeliver(
	t *testing.T,
	txCfg client.TxConfig,
	header cmtproto.Header,
	msgs []sdk.Msg,
	chainID string,
	accNums, accSeqs []uint64,
	expSimPass, expPass bool,
	priv ...cryptotypes.PrivKey,
) (sdk.GasInfo, *sdk.Result, error) {
	t.Helper()

	tx, err := s.GenSignedTx(
		txCfg,
		msgs,
		sdk.NewCoins(sdk.NewCoin(s.bondDenom, sdkmath.NewInt(10000))),
		300000,
		chainID,
		accNums,
		accSeqs,
		priv...,
	)
	require.NoError(t, err)

	txBytes, err := txCfg.TxEncoder()(tx)
	require.NoError(t, err)

	// Optionally simulate
	if expSimPass {
		_, simRes, err := s.app.Simulate(txBytes)
		if expSimPass {
			require.NoError(t, err)
			require.NotNil(t, simRes)
		}
	}

	// Deliver the transaction
	res, err := s.app.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height: header.Height,
		Time:   header.Time,
		Txs:    [][]byte{txBytes},
	})

	if expPass {
		require.NoError(t, err)
		require.NotNil(t, res)
		if len(res.TxResults) > 0 {
			require.True(t, res.TxResults[0].IsOK(), "tx failed: %s", res.TxResults[0].Log)
		}
	}

	// Commit
	_, err = s.app.Commit()
	require.NoError(t, err)

	var result *sdk.Result
	var gasInfo sdk.GasInfo

	if len(res.TxResults) > 0 {
		txResult := res.TxResults[0]
		gasInfo = sdk.GasInfo{
			GasWanted: uint64(txResult.GasWanted),
			GasUsed:   uint64(txResult.GasUsed),
		}
		result = &sdk.Result{
			Data:   txResult.Data,
			Log:    txResult.Log,
			Events: txResult.Events,
		}
	}

	return gasInfo, result, nil
}

// NextBlock advances the chain by one block.
func (s *IntegrationTestSuite) NextBlock(valSet *cmttypes.ValidatorSet, jumpTime time.Duration) (sdk.Context, error) {
	header := cmtproto.Header{
		Height:  s.app.LastBlockHeight() + 1,
		ChainID: s.chainID,
		Time:    time.Now().UTC().Add(jumpTime),
	}

	var nextValsHash []byte
	if valSet != nil {
		nextValsHash = valSet.Hash()
	}

	_, err := s.app.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height:             header.Height,
		Time:               header.Time,
		NextValidatorsHash: nextValsHash,
	})
	if err != nil {
		return sdk.Context{}, err
	}

	_, err = s.app.Commit()
	if err != nil {
		return sdk.Context{}, err
	}

	return s.app.BaseApp.NewUncachedContext(false, header), nil
}

// NextBlockWithTxs advances the chain by one block with the given transactions.
func (s *IntegrationTestSuite) NextBlockWithTxs(valSet *cmttypes.ValidatorSet, txs [][]byte) (*abci.ResponseFinalizeBlock, error) {
	header := cmtproto.Header{
		Height:  s.app.LastBlockHeight() + 1,
		ChainID: s.chainID,
		Time:    time.Now().UTC(),
	}

	var nextValsHash []byte
	if valSet != nil {
		nextValsHash = valSet.Hash()
	}

	res, err := s.app.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height:             header.Height,
		Time:               header.Time,
		NextValidatorsHash: nextValsHash,
		Txs:                txs,
	})
	if err != nil {
		return nil, err
	}

	_, err = s.app.Commit()
	if err != nil {
		return nil, err
	}

	return res, nil
}

// BuildTx builds a transaction with the given messages without signing.
func (s *IntegrationTestSuite) BuildTx(
	txConfig client.TxConfig,
	msgs []sdk.Msg,
	feeAmt sdk.Coins,
	gas uint64,
	memo string,
) (client.TxBuilder, error) {
	txBuilder := txConfig.NewTxBuilder()
	if err := txBuilder.SetMsgs(msgs...); err != nil {
		return nil, err
	}
	txBuilder.SetFeeAmount(feeAmt)
	txBuilder.SetGasLimit(gas)
	txBuilder.SetMemo(memo)

	return txBuilder, nil
}

// GetAccountInfo retrieves account number and sequence for the given address.
func (s *IntegrationTestSuite) GetAccountInfo(ctx sdk.Context, addr sdk.AccAddress) (uint64, uint64, error) {
	acc := s.app.AuthKeeper.GetAccount(ctx, addr)
	if acc == nil {
		return 0, 0, nil
	}
	return acc.GetAccountNumber(), acc.GetSequence(), nil
}

// FundAccount funds an account with the specified coins.
func (s *IntegrationTestSuite) FundAccount(ctx sdk.Context, addr sdk.AccAddress, coins sdk.Coins) error {
	if err := s.app.BankKeeper.MintCoins(ctx, "qbtc_reserve", coins); err != nil {
		return err
	}
	return s.app.BankKeeper.SendCoinsFromModuleToAccount(ctx, "qbtc_reserve", addr, coins)
}

// GetBalance returns the balance of the given address for the specified denomination.
func (s *IntegrationTestSuite) GetBalance(ctx sdk.Context, addr sdk.AccAddress, denom string) sdk.Coin {
	return s.app.BankKeeper.GetBalance(ctx, addr, denom)
}

// ExecuteMsg is a helper to execute a single message and return the result.
// It handles getting account info, signing, and delivering the transaction.
func (s *IntegrationTestSuite) ExecuteMsg(
	msg sdk.Msg,
	signer sdk.AccAddress,
	signerPrivKey cryptotypes.PrivKey,
) (*abci.ExecTxResult, error) {
	s.T().Helper()

	ctx := app.GetTestContext(s.app)
	accNum, accSeq, err := s.GetAccountInfo(ctx, signer)
	if err != nil {
		return nil, err
	}

	return s.SignAndDeliver(
		[]sdk.Msg{msg},
		s.chainID,
		[]uint64{accNum},
		[]uint64{accSeq},
		signerPrivKey,
	)
}
