/*
 * Copyright (c) 2026-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package m2mauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	oaws "github.com/okta/okta-aws-cli/v2/internal/aws"
	"github.com/okta/okta-aws-cli/v2/internal/config"
	"github.com/okta/okta-aws-cli/v2/internal/exec"
	"github.com/okta/okta-aws-cli/v2/internal/okta"
	"github.com/okta/okta-aws-cli/v2/internal/output"
	"github.com/okta/okta-aws-cli/v2/internal/utils"
)

const (
	// DefaultScope The default scope value
	DefaultScope = "okta-m2m-access"
	// DefaultAuthzID The default authorization server id
	DefaultAuthzID = "default"
)

// M2MAuthentication Object structure for headless authentication
type M2MAuthentication struct {
	config *config.Config
}

// NewM2MAuthentication New M2M Authentication constructor
func NewM2MAuthentication(cfg *config.Config) (*M2MAuthentication, error) {
	// need to set our config defaults
	if cfg.CustomScope() == "" {
		_ = cfg.SetCustomScope(DefaultScope)
	}
	if cfg.AuthzID() == "" {
		_ = cfg.SetAuthzID(DefaultAuthzID)
	}

	// Check if exec arg is present and that there are args for it before doing any work
	if cfg.Exec() {
		if _, err := exec.NewExec(cfg); err != nil {
			return nil, err
		}
	}

	m := M2MAuthentication{
		config: cfg,
	}
	return &m, nil
}

// EstablishIAMCredentials Full operation to fetch temporary IAM credentials and
// output them to preferred format.
//
// The overall API interactions are as follows:
//
// - CLI requests access token from custom authz server at /oauth2/{authzID}/v1/token
// - CLI presents access token to AWS STS for temporary AWS IAM creds
func (m *M2MAuthentication) EstablishIAMCredentials() error {
	at, err := m.accessToken()
	if err != nil {
		return err
	}

	cc, err := oaws.AssumeRoleWithWebIdentity(m.config, at)
	if err != nil {
		return err
	}

	err = output.RenderAWSCredential(m.config, cc)
	if err != nil {
		return err
	}

	if m.config.Exec() {
		exe, _ := exec.NewExec(m.config)
		if err := exe.Run(cc); err != nil {
			return err
		}
	}

	return nil
}

func (m *M2MAuthentication) createKeySigner() (jose.Signer, error) {
	signerOptions := (&jose.SignerOptions{}).WithHeader("kid", m.config.KeyID())
	var priv []byte
	switch {
	case m.config.PrivateKey() != "":
		priv = []byte(strings.ReplaceAll(m.config.PrivateKey(), `\n`, "\n"))
	case m.config.PrivateKeyFile() != "":
		var err error
		priv, err = os.ReadFile(m.config.PrivateKeyFile())
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("either private key or private key file is a required m2m argument")
	}

	privPem, _ := pem.Decode(priv)
	if privPem == nil {
		return nil, errors.New("invalid private key value")
	}

	if privPem.Type == "RSA PRIVATE KEY" {
		parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
		if err != nil {
			return nil, err
		}
		return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: parsedKey}, signerOptions)
	}
	if privPem.Type == "PRIVATE KEY" {
		parsedKey, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
		if err != nil {
			return nil, err
		}
		var alg jose.SignatureAlgorithm
		switch parsedKey.(type) {
		case *rsa.PrivateKey:
			alg = jose.RS256
		case *ecdsa.PrivateKey:
			alg = jose.ES256 // TODO handle ES384 or ES512 ?
		default:
			// TODO are either of these also valid?
			// ed25519.PrivateKey:
			// *ecdh.PrivateKey
			return nil, fmt.Errorf("private key %q is unknown pkcs#8 format type", privPem.Type)
		}
		return jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: parsedKey}, signerOptions)
	}

	return nil, fmt.Errorf("private key %q is not pkcs#1 or pkcs#8 format", privPem.Type)
}

func (m *M2MAuthentication) makeClientAssertion() (string, error) {
	privateKeySinger, err := m.createKeySigner()
	if err != nil {
		return "", err
	}

	tokenRequestURL := fmt.Sprintf(okta.CustomAuthzV1TokenEndpointFormat, m.config.OrgDomain(), m.config.AuthzID())
	now := m.config.Clock().Now()
	claims := okta.ClientAssertionClaims{
		Subject:  m.config.OIDCAppID(),
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour * time.Duration(1))),
		Issuer:   m.config.OIDCAppID(),
		Audience: tokenRequestURL,
		ID:       uuid.New().String(),
	}

	jwtBuilder := jwt.Signed(privateKeySinger).Claims(claims)
	return jwtBuilder.Serialize()
}

// accessToken Takes okta-aws-cli private key and presents a client_credentials
// flow assertion to /oauth2/{authzServerID}/v1/token to gather an access token.
func (m *M2MAuthentication) accessToken() (*okta.AccessToken, error) {
	clientAssertion, err := m.makeClientAssertion()
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	tokenRequestURL := fmt.Sprintf(okta.CustomAuthzV1TokenEndpointFormat, m.config.OrgDomain(), m.config.AuthzID())

	query.Add("grant_type", "client_credentials")
	query.Add("scope", m.config.CustomScope())
	query.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	query.Add("client_assertion", clientAssertion)
	req, err := http.NewRequest("POST", tokenRequestURL, strings.NewReader(query.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
	req.Header.Add(utils.UserAgentHeader, m.config.UserAgent())
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIM2MOperation)
	resp, err := m.config.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		baseErrStr := "fetching access token received API response %q"
		if err != nil {
			return nil, fmt.Errorf(baseErrStr, resp.Status)
		}

		var apiErr okta.APIError
		err = json.NewDecoder(resp.Body).Decode(&apiErr)
		if err != nil {
			return nil, fmt.Errorf(baseErrStr, resp.Status)
		}

		return nil, fmt.Errorf(baseErrStr+okta.AccessTokenErrorFormat, resp.Status, apiErr.Error, apiErr.ErrorDescription)
	}

	token := &okta.AccessToken{}
	err = json.NewDecoder(resp.Body).Decode(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}
