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
	"path"
	"regexp"
	"testing"

	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/testutils"
	"github.com/stretchr/testify/require"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

func TestMain(m *testing.M) {
	var reset func()
	reset = osSetEnvIfBlank("OKTA_ORG_DOMAIN", testutils.TestDomainName)
	defer reset()
	reset = osSetEnvIfBlank("OKTA_OIDC_CLIENT_ID", "0oaa4htg72TNrkTDr1d7")
	defer reset()
	reset = osSetEnvIfBlank("OKTA_AWSCLI_IAM_ROLE", "arn:aws:iam::123:role/RickRollNeverGonnaGiveYouUp")
	defer reset()
	reset = osSetEnvIfBlank("OKTA_AUTHZ_ID", "aus8w23r13NvyUwln1d7")
	defer reset()
	reset = osSetEnvIfBlank("OKTA_AWSCLI_CUSTOM_SCOPE", "okta-aws-cli")
	defer reset()
	reset = osSetEnvIfBlank("OKTA_AWSCLI_KEY_ID", "kid-rock")
	defer reset()

	// NOTE: Okta Security this is just some random PK to unit test the client
	// assertion generator in this app. PK was created with
	// `openssl genrsa 512 | pbcopy`
	reset = osSetEnvIfBlank("OKTA_AWSCLI_PRIVATE_KEY", `
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

func osSetEnvIfBlank(key, value string) func() {
	if os.Getenv(key) != "" {
		return func() {}
	}
	_ = os.Setenv(key, value)
	return func() {
		_ = os.Unsetenv(key)
	}
}

func TestM2MAuthEstablishIAMCredentials(t *testing.T) {
	t.Skip("TODO")
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

	at, err := m.AccessToken()
	require.NoError(t, err)
	require.NotNil(t, at)

	require.Equal(t, "Bearer", at.TokenType)
	require.Equal(t, int64(3600), at.ExpiresIn)
	require.Equal(t, "okta-aws-cli", at.Scope)
	require.Regexp(t, regexp.MustCompile("^eyJ"), at.AccessToken)
}

func setupTest(t *testing.T) (*config.Config, func(t *testing.T)) {
	attrs := &config.Attributes{
		OrgDomain:   os.Getenv("OKTA_ORG_DOMAIN"),
		OIDCAppID:   os.Getenv("OKTA_OIDC_CLIENT_ID"),
		AWSIAMRole:  os.Getenv("OKTA_AWSCLI_IAM_ROLE"),
		AuthzID:     os.Getenv("OKTA_AUTHZ_ID"),
		CustomScope: os.Getenv("OKTA_AWSCLI_CUSTOM_SCOPE"),
		KeyID:       os.Getenv("OKTA_AWSCLI_KEY_ID"),
		PrivateKey:  os.Getenv("OKTA_AWSCLI_PRIVATE_KEY"),
	}
	config, err := config.NewConfig(attrs)
	require.NoError(t, err)

	rt := config.HTTPClient().Transport
	vcr, err := newVCRRecorder(t, rt)
	require.NoError(t, err)
	rt = http.RoundTripper(vcr)
	config.HTTPClient().Transport = rt

	tearDown := func(t *testing.T) {
		err := vcr.Stop()
		require.NoError(t, err)
	}

	return config, tearDown
}

func newVCRRecorder(t *testing.T, transport http.RoundTripper) (rec *recorder.Recorder, err error) {
	dir, _ := os.Getwd()
	vcrFixturesHome := path.Join(dir, "../../test/fixtures/vcr")
	cassettesPath := path.Join(vcrFixturesHome, t.Name())
	rec, err = recorder.NewWithOptions(&recorder.Options{
		CassetteName:       cassettesPath,
		Mode:               recorder.ModeRecordOnce,
		SkipRequestLatency: true, // skip how vcr will mimic the real request latency that it can record allowing for fast playback
		RealTransport:      transport,
	})
	if err != nil {
		return
	}

	rec.SetMatcher(testutils.VCROktaAPIRequestMatcher)
	rec.AddHook(testutils.VCROktaAPIRequestHook, recorder.AfterCaptureHook)

	return
}
