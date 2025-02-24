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
	"reflect"
	"testing"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
)

func Test_idaasProviderFactory_Create(t *testing.T) {
	type args struct {
		options oauth.DynamicOptions
	}

	mustUnmarshalYAML := func(data string) oauth.DynamicOptions {
		var dynamicOptions oauth.DynamicOptions
		_ = yaml.Unmarshal([]byte(data), &dynamicOptions)
		return dynamicOptions
	}

	tests := []struct {
		name    string
		args    args
		want    identityprovider.OAuthProvider
		wantErr bool
	}{
		{
			name: "should create successfully",
			args: args{options: mustUnmarshalYAML(`
clientID: observation
clientSecret: 8lSI13u4l08dgsMuiRyt7nbSQE3Hy3dL
endpoint:
  userInfoUrl: "http://api.rockontrol.com/oauth/user"
  authURL: "https://account.rockontrol.com/authorize"
  tokenURL: "https://api.rockontrol.com/oauth/token"
redirectURL: "http://ks-console/oauth/redirect"
scopes:
- read
`)},
			want: &rockontrol{
				ClientID:     "observation",
				ClientSecret: "8lSI13u4l08dgsMuiRyt7nbSQE3Hy3dL",
				Endpoint: endpoint{
					AuthURL:     "https://account.rockontrol.com/authorize",
					TokenURL:    "https://api.rockontrol.com/oauth/token",
					UserInfoURL: "http://api.rockontrol.com/oauth/user",
				},
				RedirectURL: "http://ks-console/oauth/redirect",
				Scopes:      []string{"read"},
				Config: &oauth2.Config{
					ClientID:     "observation",
					ClientSecret: "8lSI13u4l08dgsMuiRyt7nbSQE3Hy3dL",
					Endpoint: oauth2.Endpoint{
						AuthURL:   "https://account.rockontrol.com/authorize",
						TokenURL:  "https://api.rockontrol.com/oauth/token",
						AuthStyle: oauth2.AuthStyleAutoDetect,
					},
					RedirectURL: "http://ks-console/oauth/redirect",
					Scopes:      []string{"read"},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &idpProviderFactory{}
			got, err := f.Create(tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Create() got = %v, want %v", got, tt.want)
			}
		})
	}
}

