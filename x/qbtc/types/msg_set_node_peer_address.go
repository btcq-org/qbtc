package types

import (
	"net"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgSetNodePeerAddress{}
	_ sdk.HasValidateBasic = &MsgSetNodePeerAddress{}
	_ sdk.LegacyMsg        = &MsgSetNodePeerAddress{}
)

// NewMsgSetNodePeerAddress creates a new MsgSetNodePeerAddress instance
func NewMsgSetNodePeerAddress(peerAddress string, nodeAddress sdk.AccAddress) *MsgSetNodePeerAddress {
	return &MsgSetNodePeerAddress{
		Signer:      nodeAddress.String(),
		PeerAddress: peerAddress,
	}
}

// ValidateBasic implements HasValidateBasic
func (m *MsgSetNodePeerAddress) ValidateBasic() error {
	if m.Signer == "" {
		return se.ErrInvalidAddress.Wrap("signer cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(m.Signer)
	if err != nil {
		return se.ErrInvalidAddress.Wrap(err.Error())
	}

	// Validate format: <peerId>@<host>:<port>
	addr := m.PeerAddress
	parts := strings.Split(addr, "@")
	if len(parts) != 2 {
		return se.ErrUnknownRequest.Wrap("peer address must be in format <peerId>@<host>:<port>")
	}
	peerId := parts[0]
	hostPort := parts[1]

	if peerId == "" {
		return se.ErrUnknownRequest.Wrap("peerId cannot be empty in peer address")
	}

	// host:port parsing
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return se.ErrUnknownRequest.Wrap("invalid host:port in peer address: " + err.Error())
	}
	if host == "" {
		return se.ErrUnknownRequest.Wrap("host cannot be empty in peer address")
	}
	if port == "" {
		return se.ErrUnknownRequest.Wrap("port cannot be empty in peer address")
	}

	return nil
}

// GetSigners defines whose signature is required
func (m *MsgSetNodePeerAddress) GetSigners() []sdk.AccAddress {
	acct, _ := sdk.AccAddressFromBech32(m.Signer)
	return []sdk.AccAddress{acct}
}
