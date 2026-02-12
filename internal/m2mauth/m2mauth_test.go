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
	// `openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt`
	reset = testutils.OsSetEnvIfBlank("OKTA_AWSCLI_PRIVATE_KEY", `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb6SvsSfrP69gO
yDpdXsZsT3ydS/ggCYFV8NhbHx6VtJeoLuQp+TCJ0pc4sC0ZvnBk5r6oAubLLDgK
zqDsf8rIzg91mZPH2KfQs0bM02q+2naLkHYIVXjCFMh3ibXGWuNH/cItm9CLHJz0
11K4LmsXUJdre4suSGDmUKOYgJqpcYHaWeEGNWcnMb7UGC+lcaXpwnkbp5ziBP6P
PC/OH9S/HVDpiuJioex/zLLeCF/jnjHnbIa5EY1I5eWDttDgCxBRe+0p8XOtI6KJ
wIUkhank99DoVp+KIcCxFW6WfQCac9/oT5I8I+j0lOtBAfQo+d2uVQd2xX80vsdM
D2zvgyUHAgMBAAECggEAP4iQDgYZljR3CV5DrnIRNX2JbRBjsS3N1fxtJXZKKcow
/n/9nzrFESxsUA5mGUfxxNT9RCECeLRfxI+J4onRFk6iHMGv9k7bvOnujIKQFm+b
TBsCXsoCx1+lwxNgFtxvSX9AuFiJ2Yb8uafz2A5hFi1McdsRjN+QTzoA6bBN/qGp
PO5PiVnfY9B9C/XAy2fWJ8JF0xZ8yBpJo9RNet241Ee0tiWwuHNpwntMT7C+K8f5
cv5ccE+mA81ZwOrhbaIRct3HaFhV8l1j5usbvmZXlzHgOXzDfdLx/scADBbDwjmo
djxrUBvLX1gwY6xRKXwgOv4ReZZcYV6Fvk5tTmgE8QKBgQD38fwyXZn24f4gb4X3
WXf5WUuVlQx5cMMP5WQUgSPeUKuau2g0OR9ypy3KIG4qZj0sKFEP/aD8tbKfcDEg
I+dK87nfUvvU3I+3TCgy16D8Ir7mmZimcUJ380d62I7YZSWTTRTjvrTb5S4MakoO
s++N8sty/XM3whZe1Ls0XAraRQKBgQDjDgpjg/J5d/W1pG6Ru9YsvtyK64wGLP2o
DpnQFUNNO+WR+VGBDitKvdzSsEinfSI3Reklydn+jzTt5BVNUvughfqX/fTb+QN1
7meHr8FPEPlLgKyLkmq9E6yZWuvOeMgjV7/P4Pwh66+rU7GVm14P7VEA1UOYmjvu
LJWjnw182wKBgQDOjGyefHEdRIhR9vWv531VYDjiBEdfBzvICz1DA42gzq0V+lbF
Ymy7M1+myTtc4MzG81MMMiohOy/xOCIEd0RfoQfPba7SVWb3uF6odA7s2/kR2xRa
W3GWwThjsvHUfPY/bnAfhSffI10oBIdrFiRSqNcpFNAdu/asyySkaqSzzQKBgFhS
PN5LFEYF0NFwfgY4b+6F69oqGBTK6Xy2+UQFEWH4u6tVtUujTFnNkxlts0VbmrSv
gCrP4vlvkWI8R8EFV5Ywp7L5+YabzanRK/qO9n4gFyk0i2nbcaPNBGW/BV0ShJ+i
4Z0mYk17laDqdHjCsAs4ADt3ucyhqlBSjX7RPvjjAoGAHoR+FJglKaY2U82VV5pK
sa8YdiJHAaJyd3olYNzq2QuxQOWN4d+BitVWPmM+IQkaBigESxTIam+n5/qHiVyV
XNY+9eUj7XwoMVz03BISN8TEmDlRyyQYHffRUF69wDLlSY1PG4k/9uED50YsQZAm
oO62j9Objbi/ntr/BSQIpYE=
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
