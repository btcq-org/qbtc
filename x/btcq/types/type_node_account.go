package types

import (
	"strconv"
	"strings"
)

func (na *NodeAccount) String() string {
	sb := strings.Builder{}
	sb.WriteString("node:" + na.NodeAddress.String() + "\n")
	sb.WriteString("status:" + na.Status.String() + "\n")
	sb.WriteString("node pubkeys:" + na.PubKey + "\n")
	sb.WriteString("validator consensus pub key:" + na.ValidatorConsPubKey + "\n")
	sb.WriteString("bond:" + na.Bond.String() + "\n")
	sb.WriteString("version:" + na.Version + "\n")
	sb.WriteString("bond address:" + na.BondAddress.String() + "\n")
	sb.WriteString("requested to leave:" + strconv.FormatBool(na.RequestedToLeave) + "\n")
	return sb.String()
}
