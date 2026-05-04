package proofservice

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync/atomic"

	"github.com/btcq-org/qbtc/proof-service/config"
	qbtctypes "github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdktx "github.com/cosmos/cosmos-sdk/types/tx"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/std"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// gasAdjustment is the multiplier applied to the simulated gas usage.
const gasAdjustment = 1.5

// keyEntry holds a private key and its derived bech32 address.
type keyEntry struct {
	privKey  cryptotypes.PrivKey
	fromAddr string
}

// Broadcaster signs and broadcasts MsgClaimWithProof transactions to the qbtc chain.
// Multiple signing keys are supported and selected in round-robin order.
type Broadcaster struct {
	keys     []keyEntry
	counter  atomic.Uint64
	chainID  string
	grpcConn *grpc.ClientConn
	txConfig client.TxConfig
	cdc      codec.Codec
}

// NewBroadcaster creates a Broadcaster from the service config.
// Returns nil, nil when broadcasting is not configured (missing addr or keys).
func NewBroadcaster(cfg config.Config) (*Broadcaster, error) {
	if cfg.BroadcastGRPCAddr == "" || len(cfg.BroadcastPrivKeyHexList) == 0 {
		return nil, nil
	}

	// Decode all private keys
	keys := make([]keyEntry, 0, len(cfg.BroadcastPrivKeyHexList))
	for i, hexKey := range cfg.BroadcastPrivKeyHexList {
		privKeyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("broadcast_priv_key_hex_list[%d]: invalid hex: %w", i, err)
		}
		if len(privKeyBytes) != 32 {
			return nil, fmt.Errorf("broadcast_priv_key_hex_list[%d]: must be 64 hex characters (32 bytes), got %d bytes", i, len(privKeyBytes))
		}
		privKey := &secp256k1.PrivKey{Key: privKeyBytes}
		keys = append(keys, keyEntry{
			privKey:  privKey,
			fromAddr: sdk.AccAddress(privKey.PubKey().Address()).String(),
		})
	}

	// Set up codec and tx config
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	qbtctypes.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	txConfig := authtx.NewTxConfig(cdc, authtx.DefaultSignModes)

	// Connect to gRPC node
	conn, err := grpc.NewClient(cfg.BroadcastGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC node at %s: %w", cfg.BroadcastGRPCAddr, err)
	}

	return &Broadcaster{
		keys:     keys,
		chainID:  cfg.ChainID,
		grpcConn: conn,
		txConfig: txConfig,
		cdc:      cdc,
	}, nil
}

// FromAddresses returns the bech32 addresses of all configured signing keys.
func (b *Broadcaster) FromAddresses() []string {
	addrs := make([]string, len(b.keys))
	for i, k := range b.keys {
		addrs[i] = k.fromAddr
	}
	return addrs
}

// nextKey returns the next signing key in round-robin order.
func (b *Broadcaster) nextKey() keyEntry {
	idx := b.counter.Add(1) - 1
	return b.keys[idx%uint64(len(b.keys))]
}

// Close releases the underlying gRPC connection.
func (b *Broadcaster) Close() {
	_ = b.grpcConn.Close()
}

// BroadcastClaim builds, signs, and broadcasts a MsgClaimWithProof derived from
// the given ProveResponse. A signing key is chosen in round-robin order.
// Gas is estimated via simulation. No fee is required.
// Returns the transaction hash on success.
func (b *Broadcaster) BroadcastClaim(ctx context.Context, resp *ProveResponse) (string, error) {
	key := b.nextKey()

	// Build the message
	msg := &qbtctypes.MsgClaimWithProof{
		Claimer:          resp.ClaimerAddress,
		Utxos:            resp.UTXOs,
		Proof:            resp.Proof,
		MessageHash:      resp.MessageHash,
		AddressHash:      resp.AddressHash,
		QbtcAddressHash:  resp.QBTCAddressHash,
		PubKeyHashSha256: resp.PubKeyHashSHA256,
	}

	// Fetch account number and sequence from chain
	accountNum, seq, err := b.fetchAccountInfo(ctx, key.fromAddr)
	if err != nil {
		return "", fmt.Errorf("failed to fetch account info for %s: %w", key.fromAddr, err)
	}

	// Build tx with zero gas for simulation
	txBuilder := b.txConfig.NewTxBuilder()
	if err := txBuilder.SetMsgs(msg); err != nil {
		return "", fmt.Errorf("failed to set msgs: %w", err)
	}
	txBuilder.SetGasLimit(0)

	// Sign with zero gas to get valid tx bytes for simulation
	if err := b.signTx(ctx, key, txBuilder, accountNum, seq); err != nil {
		return "", fmt.Errorf("failed to sign tx for simulation: %w", err)
	}

	// Simulate to estimate gas
	gasLimit, err := b.simulateGas(ctx, txBuilder)
	if err != nil {
		return "", fmt.Errorf("gas simulation failed: %w", err)
	}

	// Rebuild and re-sign with the estimated gas limit
	txBuilder = b.txConfig.NewTxBuilder()
	if err := txBuilder.SetMsgs(msg); err != nil {
		return "", fmt.Errorf("failed to set msgs: %w", err)
	}
	txBuilder.SetGasLimit(gasLimit)

	if err := b.signTx(ctx, key, txBuilder, accountNum, seq); err != nil {
		return "", fmt.Errorf("failed to sign tx: %w", err)
	}

	// Encode and broadcast
	txBytes, err := b.txConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return "", fmt.Errorf("failed to encode tx: %w", err)
	}

	txClient := sdktx.NewServiceClient(b.grpcConn)
	broadcastResp, err := txClient.BroadcastTx(ctx, &sdktx.BroadcastTxRequest{
		TxBytes: txBytes,
		Mode:    sdktx.BroadcastMode_BROADCAST_MODE_SYNC,
	})
	if err != nil {
		return "", fmt.Errorf("broadcast rpc failed: %w", err)
	}
	if broadcastResp.TxResponse.Code != 0 {
		return "", fmt.Errorf("tx rejected by chain (code %d): %s", broadcastResp.TxResponse.Code, broadcastResp.TxResponse.RawLog)
	}

	return broadcastResp.TxResponse.TxHash, nil
}

// simulateGas encodes the current tx and calls the chain's Simulate RPC,
// returning the adjusted gas limit (simulated * gasAdjustment).
func (b *Broadcaster) simulateGas(ctx context.Context, txBuilder client.TxBuilder) (uint64, error) {
	txBytes, err := b.txConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return 0, fmt.Errorf("failed to encode tx for simulation: %w", err)
	}

	txClient := sdktx.NewServiceClient(b.grpcConn)
	simResp, err := txClient.Simulate(ctx, &sdktx.SimulateRequest{TxBytes: txBytes})
	if err != nil {
		return 0, fmt.Errorf("simulate rpc failed: %w", err)
	}

	return uint64(float64(simResp.GasInfo.GasUsed) * gasAdjustment), nil
}

// fetchAccountInfo retrieves the account number and sequence for the given address.
func (b *Broadcaster) fetchAccountInfo(ctx context.Context, addr string) (accountNum, seq uint64, err error) {
	authClient := authtypes.NewQueryClient(b.grpcConn)
	resp, err := authClient.Account(ctx, &authtypes.QueryAccountRequest{Address: addr})
	if err != nil {
		return 0, 0, err
	}

	var account authtypes.BaseAccount
	if err := b.cdc.Unmarshal(resp.Account.Value, &account); err != nil {
		return 0, 0, fmt.Errorf("failed to unmarshal account: %w", err)
	}
	return account.AccountNumber, account.Sequence, nil
}

// signTx signs the tx builder in-place with the given key.
func (b *Broadcaster) signTx(ctx context.Context, key keyEntry, txBuilder client.TxBuilder, accountNum, seq uint64) error {
	// Set empty signature first so the tx bytes are well-formed for sign-byte derivation.
	emptySig := txsigning.SignatureV2{
		PubKey: key.privKey.PubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
			Signature: nil,
		},
		Sequence: seq,
	}
	if err := txBuilder.SetSignatures(emptySig); err != nil {
		return err
	}

	signerData := authsigning.SignerData{
		Address:       key.fromAddr,
		ChainID:       b.chainID,
		AccountNumber: accountNum,
		Sequence:      seq,
		PubKey:        key.privKey.PubKey(),
	}

	signBytes, err := authsigning.GetSignBytesAdapter(
		ctx,
		b.txConfig.SignModeHandler(),
		txsigning.SignMode_SIGN_MODE_DIRECT,
		signerData,
		txBuilder.GetTx(),
	)
	if err != nil {
		return fmt.Errorf("failed to get sign bytes: %w", err)
	}

	signature, err := key.privKey.Sign(signBytes)
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	realSig := txsigning.SignatureV2{
		PubKey: key.privKey.PubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
			Signature: signature,
		},
		Sequence: seq,
	}
	return txBuilder.SetSignatures(realSig)
}
