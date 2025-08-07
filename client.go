package btauthsdk

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL    string        // e.g. https://auth.example.com
	Timeout    time.Duration // e.g. 3 * time.Second
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		Timeout: 5 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *Client) FetchPublicKeys() ([]PublicKeyResponse, error) {
	url := c.BaseURL + "/public-key"
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch keys, status code: " + resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var keys []PublicKeyResponse
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return nil, err
	}
	return keys, nil
}
