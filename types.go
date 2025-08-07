package btauthsdk

type PublicKeyResponse struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	PEM string `json:"pem"`
}
