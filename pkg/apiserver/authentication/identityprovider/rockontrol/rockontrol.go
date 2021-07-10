/*
Copyright 2020 The KubeSphere Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rockontrol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
)


func init() {
	identityprovider.RegisterOAuthProvider(&idpProviderFactory{})
}

type rockontrol struct {
	// ClientID is the application's ID.
	ClientID string `json:"clientID" yaml:"clientID"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"-" yaml:"clientSecret"`

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.endpoint.
	Endpoint endpoint `json:"endpoint" yaml:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `json:"redirectURL" yaml:"redirectURL"`

	// Used to turn off TLS certificate checks
	InsecureSkipVerify bool `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes" yaml:"scopes"`

	Config *oauth2.Config `json:"-" yaml:"-"`
}

// endpoint represents an OAuth 2.0 provider's authorization and token
// endpoint URLs.
type endpoint struct {
	AuthURL     string `json:"authURL" yaml:"authURL"`
	TokenURL    string `json:"tokenURL" yaml:"tokenURL"`
	UserInfoURL string `json:"userInfoURL" yaml:"userInfoURL"`
}

type rockontrolIdentity struct {
	AccountID string  `json:"accountID"`
	From      string         `json:"from,omitempty"`
	Nickname  string         `json:"nickname,omitempty"`
	Email     string         `json:"email,omitempty"`
	Mobile    string         `json:"email,omitempty"`
}

type idpProviderFactory struct {
}

func (r *idpProviderFactory) Type() string {
	return "RockontrolIdentityProvider"
}

func (r *idpProviderFactory) Create(options oauth.DynamicOptions) (identityprovider.OAuthProvider, error) {
	var rockontrol rockontrol
	if err := mapstructure.Decode(options, &rockontrol); err != nil {
		return nil, err
	}

	if rockontrol.Endpoint.AuthURL == "" {
		rockontrol.Endpoint.AuthURL = authURL
	}
	if rockontrol.Endpoint.TokenURL == "" {
		rockontrol.Endpoint.TokenURL = tokenURL
	}
	if rockontrol.Endpoint.UserInfoURL == "" {
		rockontrol.Endpoint.UserInfoURL = userInfoURL
	}
	// fixed options
	options["endpoint"] = oauth.DynamicOptions{
		"authURL":     rockontrol.Endpoint.AuthURL,
		"tokenURL":    rockontrol.Endpoint.TokenURL,
		"userInfoURL": rockontrol.Endpoint.UserInfoURL,
	}
	rockontrol.Config = &oauth2.Config{
		ClientID:     rockontrol.ClientID,
		ClientSecret: rockontrol.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  rockontrol.Endpoint.AuthURL,
			TokenURL: rockontrol.Endpoint.TokenURL,
		},
		RedirectURL: rockontrol.RedirectURL,
		Scopes:      rockontrol.Scopes,
	}
	return &rockontrol, nil
}

func (r rockontrolIdentity) GetUserID() string {
	return r.AccountID
}

func (r rockontrolIdentity) GetUsername() string {
	return r.AccountID
}

func (r rockontrolIdentity) GetEmail() string {
	return r.Email
}

func (r *rockontrol) IdentityExchange(code string) (identityprovider.Identity, error) {
	ctx := context.TODO()
	if r.InsecureSkipVerify {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	token, err := r.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	resp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)).Get(r.Endpoint.UserInfoURL)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rockontrolIdentity rockontrolIdentity
	err = json.Unmarshal(data, &rockontrolIdentity)
	if err != nil {
		return nil, err
	}

	return rockontrolIdentity, nil
}

