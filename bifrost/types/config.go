package config

type P2PConfig struct {
	Port       int    `json:"port"`
	ExternalIP string `json:"external_ip"`
}
