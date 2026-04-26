package types

func DefaultGenesis() *GenesisState {
	params := make([]Param, 0, len(DefaultParams()))
	for k, v := range DefaultParams() {
		params = append(params, Param{Key: k, Value: v})
	}
	return &GenesisState{
		Vault:      nil, // genesis writer must supply DKLS pubkey + members
		TxOutQueue: nil,
		TxOutSeq:   0,
		Params:     params,
	}
}

func (gs GenesisState) Validate() error {
	for _, p := range gs.Params {
		if p.Key == "" {
			return ErrUnknownParam.Wrap("empty key")
		}
		if !IsKnownParam(p.Key) {
			return ErrUnknownParam.Wrap(p.Key)
		}
	}
	return nil
}
