/*
 * Copyright (c) 2022-Present, Okta, Inc.
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

package webssoauth

import (
	"net/http"
	"os"
	"testing"

	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	var reset func()
	reset = testutils.OsSetEnvIfBlank("OKTA_ORG_DOMAIN", testutils.TestDomainName)
	defer reset()
	reset = testutils.OsSetEnvIfBlank("OKTA_OIDC_CLIENT_ID", "0oa4x34ogyC1i1krJ1d7")
	defer reset()

	os.Exit(m.Run())
}

func TestWebSSOAuthIsClassicOrg(t *testing.T) {
	config, teardownTest := setupTest(t)
	defer teardownTest(t)

	w, err := NewWebSSOAuthentication(config)
	require.NoError(t, err)
	isClassic := w.isClassicOrg()
	require.False(t, isClassic)
}

func TestWebSSOAuthAuthorize(t *testing.T) {
	config, teardownTest := setupTest(t)
	defer teardownTest(t)

	w, err := NewWebSSOAuthentication(config)
	require.NoError(t, err)
	da, err := w.authorize()
	require.NoError(t, err)
	require.Equal(t, da.ExpiresIn, 600)
	require.Equal(t, da.Interval, 5)

	require.NoError(t, err)
}

func TestWebSSOAuthAccessToken(t *testing.T) {
	config, teardownTest := setupTest(t)
	defer teardownTest(t)

	w, err := NewWebSSOAuthentication(config)
	require.NoError(t, err)
	da, err := w.authorize()
	require.NoError(t, err)
	at, err := w.AccessToken(da)
	require.NoError(t, err)
	require.Equal(t, at.ExpiresIn, int64(3600))
	require.Equal(t, at.TokenType, "Bearer")

	require.NoError(t, err)
}

func setupTest(t *testing.T) (*config.Config, func(t *testing.T)) {
	attrs := &config.Attributes{
		OrgDomain: os.Getenv("OKTA_ORG_DOMAIN"),
		OIDCAppID: os.Getenv("OKTA_OIDC_CLIENT_ID"),
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
