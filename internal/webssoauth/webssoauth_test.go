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
	"reflect"
	"testing"

	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	var reset func()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_ORG_DOMAIN", testutils.TestDomainName)
	defer reset()
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_OIDC_CLIENT_ID", "0oa4x34ogyC1i1krJ1d7")
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
	at, err := w.accessToken(da)
	require.NoError(t, err)
	require.Equal(t, at.ExpiresIn, int64(3600))
	require.Equal(t, at.TokenType, "Bearer")

	require.NoError(t, err)
}

func setupTest(t *testing.T) (*config.Config, func(t *testing.T)) {
	attrs := &config.Attributes{
		OrgDomain: os.Getenv("OKTA_AWSCLI_ORG_DOMAIN"),
		OIDCAppID: os.Getenv("OKTA_AWSCLI_OIDC_CLIENT_ID"),
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

func TestOpenBrowserCommandSplitArgs(t *testing.T) {
	testCases := []struct {
		name     string
		command  string
		expected []string
	}{
		{
			name:     "osx open",
			command:  `open`,
			expected: []string{"open"},
		},
		{
			name:    "osx open named app google chrome in incognito mode",
			command: `open -na "Google Chrome" --args --incognito`,
			expected: []string{
				"open",
				"-na",
				"Google Chrome",
				"--args",
				"--incognito",
			},
		},
		{
			name:    "osx open named app google chrome in incognito mode",
			command: `/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --profile-directory=\"Person\ 1\"`,
			expected: []string{
				"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
				`--profile-directory="Person 1"`,
			},
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := splitArgs(tc.command)
			if err != nil {
				t.Errorf("didn't expect error for command %q: %+v", tc.command, err)
				return
			}
			equal := reflect.DeepEqual(result, tc.expected)
			if !equal {
				t.Errorf("expected %+v to equal %+v", tc.expected, result)
			}
		})
	}
}

// choiceFriendlyLabelIDP(alt, arn string, idps *map[string]string) string {
func TestChoiceFriendlyLabelIDP(t *testing.T) {
	config, teardownTest := setupTest(t)
	defer teardownTest(t)

	w, err := NewWebSSOAuthentication(config)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		alt      string
		arn      string
		idps     map[string]string
		expected string
	}{
		{
			name:     "Okta app label",
			alt:      "My AWS Fed App",
			arn:      "arn:aws:iam::123:saml-provider/myidp",
			idps:     map[string]string{},
			expected: "My AWS Fed App",
		},
		{
			name:     "nil map",
			alt:      "alternate",
			arn:      "arn",
			idps:     nil,
			expected: "alternate",
		},
		{
			name: "friendly label",
			alt:  "alternate",
			arn:  "arn:aws:iam::123:saml-provider/myidp",
			idps: map[string]string{
				"arn:aws:iam::123:saml-provider/youridp": "Your IdP",
				"arn:aws:iam::123:saml-provider/myidp":   "My IdP",
				"arn:aws:iam::.*:saml-provider/aidp":     "A IdP",
			},
			expected: "My IdP",
		},
		{
			name: "regexp friendly label",
			alt:  "alternate",
			arn:  "arn:aws:iam::789:saml-provider/aidp",
			idps: map[string]string{
				"arn:aws:iam::123:saml-provider/youridp": "YourIdP",
				"arn:aws:iam::123:saml-provider/myidp":   "My IdP",
				"arn:aws:iam::.*:saml-provider/aidp":     "A IdP",
			},
			expected: "A IdP",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := w.choiceFriendlyLabelIDP(tc.alt, tc.arn, tc.idps)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestChoiceFriendlyLabelRole(t *testing.T) {
	config, teardownTest := setupTest(t)
	defer teardownTest(t)

	w, err := NewWebSSOAuthentication(config)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		arn      string
		roles    map[string]string
		expected string
	}{
		{
			name:     "arn",
			arn:      "arn:aws:iam::123:role/rickrole",
			roles:    map[string]string{},
			expected: "arn:aws:iam::123:role/rickrole",
		},
		{
			name:     "nil map",
			arn:      "arn:aws:iam::123:role/rickrole",
			roles:    nil,
			expected: "arn:aws:iam::123:role/rickrole",
		},
		{
			name: "friendly label",
			arn:  "arn:aws:iam::123:role/rickrole",
			roles: map[string]string{
				"arn:aws:iam::123:role/rocknrole": "Rock N Role",
				"arn:aws:iam::123:role/rickrole":  "Rick Role",
				"arn:aws:iam::.*:role/never":      "Never Gonna Give You Up",
			},
			expected: "Rick Role",
		},
		{
			name: "regexp friendly label",
			arn:  "arn:aws:iam::789:role/never",
			roles: map[string]string{
				"arn:aws:iam::123:role/rocknrole": "Rock N Role",
				"arn:aws:iam::123:role/rickrole":  "Rick Role",
				"arn:aws:iam::.*:role/never":      "Never Gonna Give You Up",
			},
			expected: "Never Gonna Give You Up",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := w.choiceFriendlyLabelRole(tc.arn, tc.roles)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
func TestPromptForRole(t *testing.T) {
	testCases := []struct {
		name        string
		idpARN      string
		configRoles map[string]string
		roleARNs    []string
		roleArg     string
		expected    string
	}{
		{
			name:    "friendly label",
			idpARN:  "arn:aws:iam::123:role/rickrole",
			roleArg: "Rock N Role",
			roleARNs: []string{
				"arn:aws:iam::123:role/rocknrole",
				"arn:aws:iam::123:role/rickrole",
			},
			configRoles: map[string]string{
				"arn:aws:iam::123:role/rocknrole": "Rock N Role",
				"arn:aws:iam::123:role/rickrole":  "Rick Role",
				"arn:aws:iam::.*:role/never":      "Never Gonna Give You Up",
			},
			expected: "arn:aws:iam::123:role/rocknrole",
		},
		{
			name:    "friendly label configured but arn arg supplied",
			idpARN:  "arn:aws:iam::123:role/rickrole",
			roleArg: "arn:aws:iam::123:role/rocknrole",
			roleARNs: []string{
				"arn:aws:iam::123:role/rocknrole",
				"arn:aws:iam::123:role/rickrole",
			},
			configRoles: map[string]string{
				"arn:aws:iam::123:role/rocknrole": "Rock N Role",
				"arn:aws:iam::123:role/rickrole":  "Rick Role",
				"arn:aws:iam::.*:role/never":      "Never Gonna Give You Up",
			},
			expected: "arn:aws:iam::123:role/rocknrole",
		},
		{
			name:    "friendly label with wildcard",
			idpARN:  "arn:aws:iam::123:role/rickrole",
			roleArg: "Never Gonna Give You Up",
			roleARNs: []string{
				"arn:aws:iam::123:role/never",
				"arn:aws:iam::123:role/rocknrole",
			},
			configRoles: map[string]string{
				"arn:aws:iam::123:role/rocknrole": "Rock N Role",
				"arn:aws:iam::123:role/rickrole":  "Rick Role",
				"arn:aws:iam::.*:role/never":      "Never Gonna Give You Up",
			},
			expected: "arn:aws:iam::123:role/never",
		},
		{
			name:    "no friendly labels arn arg supplied",
			idpARN:  "arn:aws:iam::123:role/rickrole",
			roleArg: "arn:aws:iam::123:role/rocknrole",
			roleARNs: []string{
				"arn:aws:iam::123:role/never",
				"arn:aws:iam::123:role/rocknrole",
			},
			configRoles: nil,
			expected:    "arn:aws:iam::123:role/rocknrole",
		},
		{
			name:    "single arn option no arg supplied",
			idpARN:  "arn:aws:iam::123:role/rickrole",
			roleArg: "",
			roleARNs: []string{
				"arn:aws:iam::123:role/never",
			},
			configRoles: nil,
			expected:    "arn:aws:iam::123:role/never",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewConfig(&config.Attributes{
				AWSIAMRole: tc.roleArg,
			})
			require.NoError(t, err)

			w, err := NewWebSSOAuthentication(cfg)
			roleARn, err := w.promptForRole(tc.idpARN, tc.roleARNs, tc.configRoles)
			if roleARn != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, roleARn)
			}
		})
	}
}

func TestPromptForIdp(t *testing.T) {
	testCases := []struct {
		name       string
		configIdps map[string]string
		idpARNs    []string
		idpArg     string
		expected   string
	}{
		{
			name:   "friendly label",
			idpArg: "My IdP",
			idpARNs: []string{
				"arn:aws:iam::123:saml-provider/youridp",
				"arn:aws:iam::123:saml-provider/myidp",
				"arn:aws:iam::123:saml-provider/aidp",
			},
			configIdps: map[string]string{
				"arn:aws:iam::123:saml-provider/youridp": "Your IdP",
				"arn:aws:iam::123:saml-provider/myidp":   "My IdP",
				"arn:aws:iam::.*:saml-provider/aidp":     "A IdP",
			},
			expected: "arn:aws:iam::123:saml-provider/myidp",
		},
		{
			name:   "friendly label configured but arn arg supplied",
			idpArg: "arn:aws:iam::123:saml-provider/myidp",
			idpARNs: []string{
				"arn:aws:iam::123:saml-provider/youridp",
				"arn:aws:iam::123:saml-provider/myidp",
				"arn:aws:iam::123:saml-provider/aidp",
			},
			configIdps: map[string]string{
				"arn:aws:iam::123:saml-provider/youridp": "Your IdP",
				"arn:aws:iam::123:saml-provider/myidp":   "My IdP",
				"arn:aws:iam::.*:saml-provider/aidp":     "A IdP",
			},
			expected: "arn:aws:iam::123:saml-provider/myidp",
		},
		{
			name:   "friendly label with wildcard",
			idpArg: "A IdP",
			idpARNs: []string{
				"arn:aws:iam::123:saml-provider/youridp",
				"arn:aws:iam::123:saml-provider/myidp",
				"arn:aws:iam::123:saml-provider/aidp",
			},
			configIdps: map[string]string{
				"arn:aws:iam::123:saml-provider/youridp": "Your IdP",
				"arn:aws:iam::123:saml-provider/myidp":   "My IdP",
				"arn:aws:iam::.*:saml-provider/aidp":     "A IdP",
			},
			expected: "arn:aws:iam::123:saml-provider/aidp",
		},
		{
			name:   "no friendly labels arn arg supplied",
			idpArg: "arn:aws:iam::123:saml-provider/youridp",
			idpARNs: []string{
				"arn:aws:iam::123:saml-provider/youridp",
				"arn:aws:iam::123:saml-provider/myidp",
				"arn:aws:iam::123:saml-provider/aidp",
			},
			configIdps: nil,
			expected:   "arn:aws:iam::123:saml-provider/youridp",
		},
		{
			name:   "single arn option no arg supplied",
			idpArg: "",
			idpARNs: []string{
				"arn:aws:iam::123:saml-provider/myidp",
			},
			configIdps: nil,
			expected:   "arn:aws:iam::123:saml-provider/myidp",
		},
		{
			name:   "single arn option no arg supplied with friendly label",
			idpArg: "",
			idpARNs: []string{
				"arn:aws:iam::123:saml-provider/myidp",
			},
			configIdps: map[string]string{
				"arn:aws:iam::123:saml-provider/youridp": "Your IdP",
				"arn:aws:iam::123:saml-provider/myidp":   "My IdP",
				"arn:aws:iam::.*:saml-provider/aidp":     "A IdP",
			},
			expected: "arn:aws:iam::123:saml-provider/myidp",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewConfig(&config.Attributes{
				AWSIAMIdP: tc.idpArg,
			})
			require.NoError(t, err)

			w, err := NewWebSSOAuthentication(cfg)
			roleARn, err := w.promptForIDP(tc.idpARNs, tc.configIdps)
			if roleARn != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, roleARn)
			}
		})
	}
}
