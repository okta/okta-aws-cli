/*
 * Copyright (c) 2023-Present, Okta, Inc.
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
	"net/http"
	"os"
	"regexp"
	"testing"

	"github.com/okta/okta-aws-cli/v2/internal/config"
	"github.com/okta/okta-aws-cli/v2/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	var reset func()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_ORG_DOMAIN", testutils.TestDomainName)
	defer reset()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_OIDC_CLIENT_ID", "0oaa4htg72TNrkTDr1d7")
	defer reset()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_IAM_ROLE", "arn:aws:iam::123:role/RickRollNeverGonnaGiveYouUp")
	defer reset()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_AUTHZ_ID", "aus8w23r13NvyUwln1d7")
	defer reset()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_CUSTOM_SCOPE", "okta-m2m-access")
	defer reset()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_KEY_ID", "kid-rock")
	defer reset()

	// NOTE: Okta Security this is just some random PK to unit test the client
	// assertion generator in this app. PK was created with
	// `openssl genrsa 512 | pbcopy`
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_PRIVATE_KEY", `
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAzAZ73GY6TbcC0cQS
LQ+GfIkZxeTJjkW8+pdg0zmcGs4ZByZqp7oP02TbZ0UyLFHe8Eqik5rXR98mts5e
TuG2BwIDAQABAkEAmG2jrjdGCffYCGYnejjmLjaz5bCXkU6y8LmWIlkhMrg/F7uH
/yjmN3Hcj06F4b2DRczIIxWHpZVeFaqxvitZ6QIhAPlxhYIIpx4h+mf7cPXOlCZc
QDRqIa+pp3JH3Pgrz8mzAiEA0WNZP8acq251xTl2i+OrstH0o3YeYUmASv8bmyNs
0F0CIALSAsVunZ0cmz0zvZo55LjuUBeHn6vhyi/jmh8AN9A7AiEAoNtM1iTTeROb
4A7cFm2qGu8WnHkCr8SSjYrb/1vAnXUCIFgT6wGO6AFjQAahQlpVnqpppP9F8eSd
qrebTIkNMM8u
-----END PRIVATE KEY-----`)
	defer reset()

	os.Exit(m.Run())
}

// TestM2MAuthMakeClientAssertion Tests the private make client assertion method
// on m2mauth
func TestM2MAuthMakeClientAssertion(t *testing.T) {
	config, teardownTest := setupTest(t)
	config.SetClock(testutils.NewTestClock())
	defer teardownTest(t)

	m, err := NewM2MAuthentication(config)
	require.NoError(t, err)
	_, err = m.makeClientAssertion()
	require.NoError(t, err)
}

func TestM2MAuthAccessToken(t *testing.T) {
	config, teardownTest := setupTest(t)
	defer teardownTest(t)

	m, err := NewM2MAuthentication(config)
	require.NoError(t, err)

	at, err := m.accessToken()
	require.NoError(t, err)
	require.NotNil(t, at)

	require.Equal(t, "Bearer", at.TokenType)
	require.Equal(t, int64(3600), at.ExpiresIn)
	require.Equal(t, "okta-m2m-access", at.Scope)
	require.Regexp(t, regexp.MustCompile("^eyJ"), at.AccessToken)
}

func setupTest(t *testing.T) (*config.Config, func(t *testing.T)) {
	attrs := &config.Attributes{
		OrgDomain:   os.Getenv("OKTA_AWSCLI_ORG_DOMAIN"),
		OIDCAppID:   os.Getenv("OKTA_AWSCLI_OIDC_CLIENT_ID"),
		AWSIAMRole:  os.Getenv("OKTA_AWSCLI_IAM_ROLE"),
		AuthzID:     os.Getenv("OKTA_AWSCLI_AUTHZ_ID"),
		CustomScope: os.Getenv("OKTA_AWSCLI_CUSTOM_SCOPE"),
		KeyID:       os.Getenv("OKTA_AWSCLI_KEY_ID"),
		PrivateKey:  os.Getenv("OKTA_AWSCLI_PRIVATE_KEY"),
	}
	config, err := config.NewConfig(attrs)
	require.NoError(t, err)

	rt := config.HTTPClient().Transport
	vcr, err := testutils.NewVCRRecorder(t, rt)
	require.NoError(t, err)
	rt = http.RoundTripper(vcr)
	config.HTTPClient().Transport = rt

	tearDown := func(t *testing.T) {
		err := vcr.Stop()
		require.NoError(t, err)
	}

	return config, tearDown
}
