/*
 * Copyright (c) 2025-Present, Okta, Inc.
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

package directauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	oaws "github.com/okta/okta-aws-cli/v2/internal/aws"
	boff "github.com/okta/okta-aws-cli/v2/internal/backoff"
	"github.com/okta/okta-aws-cli/v2/internal/config"
	"github.com/okta/okta-aws-cli/v2/internal/exec"
	"github.com/okta/okta-aws-cli/v2/internal/okta"
	"github.com/okta/okta-aws-cli/v2/internal/output"
	"github.com/okta/okta-aws-cli/v2/internal/utils"
)

// DirectAuthentication Object structure for headless authentication
type DirectAuthentication struct {
	config *config.Config
}

// NewDirectAuthentication New Direct Authentication constructor
func NewDirectAuthentication(cfg *config.Config) (*DirectAuthentication, error) {
	// need to set our config defaults
	// Check if exec arg is present and that there are args for it before doing any work
	if cfg.Exec() {
		if _, err := exec.NewExec(cfg); err != nil {
			return nil, err
		}
	}

	da := DirectAuthentication{
		config: cfg,
	}
	return &da, nil
}

// EstablishIAMCredentials Full operation to fetch temporary IAM credentials and
// output them to preferred format.
//
// The overall API interactions are as follows:
//
// - CLI requests access token from custom authz server at /oauth2/{authzID}/v1/token
// - CLI triggers challenge to be pushed to Okta Verify over custom authz server at /oauth2/{authzID}/v1/challenge
// - CLI polls custom authz server at /oauth2/{authzID}/v1/token waiting for Okta Verify push to be acknowledged
// - CLI presents access token to AWS STS for temporary AWS IAM creds
func (da *DirectAuthentication) EstablishIAMCredentials() error {
	var at *okta.AccessToken
	var err error
	at = utils.CachedAccessToken(da.config)
	if at == nil {
		mfaToken, err := da.requestMFAToken()
		if err != nil {
			return err
		}

		at, err = da.challengeAndPollForAT(mfaToken)
		if err != nil {
			return err
		}
		at.Expiry = time.Now().Add(time.Duration(at.ExpiresIn) * time.Second).Format(time.RFC3339)

		utils.CacheAccessToken(da.config, at)
	}

	cc, err := oaws.AssumeRoleWithWebIdentity(da.config, at)
	if err != nil {
		return fmt.Errorf("AWS Assume Role With Web Identity error %w", err)
	}

	err = output.RenderAWSCredential(da.config, cc)
	if err != nil {
		return err
	}

	if da.config.Exec() {
		exe, _ := exec.NewExec(da.config)
		if err := exe.Run(cc); err != nil {
			return err
		}
	}

	return nil
}

// challengeAndPollForAT Isses a challenge request and then polls for Okta Verify result
// https://developer.okta.com/docs/guides/configure-direct-auth-grants/dmfaoobov/main/#challenge-request
func (da *DirectAuthentication) challengeAndPollForAT(mfaToken *okta.MFAToken) (at *okta.AccessToken, err error) {
	clientID := da.config.OIDCAppID()
        var challengeURL string
        if da.config.AuthzID() == "" {
            challengeURL = fmt.Sprintf(okta.OAuthV1ChallengeEndpointFormat, da.config.OrgDomain())
        } else {
            challengeURL = fmt.Sprintf(okta.CustomAuthzV1ChallengeEndpointFormat, da.config.OrgDomain(), da.config.AuthzID())
        }
	data := url.Values{
		"client_id":                 {clientID},
		"mfa_token":                 {mfaToken.Token},
		"challenge_types_supported": {"http://auth0.com/oauth/grant-type/mfa-oob"},
		"channel_hint":              {"push"},
	}
	body := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, challengeURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(utils.Accept, utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
	req.Header.Add(utils.UserAgentHeader, da.config.UserAgent())
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)
	resp, err := da.config.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	// https://developer.okta.com/docs/guides/configure-direct-auth-grants/dmfaoobov/main/#challenge-response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("challenging OOB MFA token received response %q", resp.Status)
	}

	ct := resp.Header.Get(utils.ContentType)
	if !strings.Contains(ct, utils.ApplicationJSON) {
		return nil, fmt.Errorf("challenge response incorrect content type %q", ct)
	}

	var challengeToken okta.ChallengeToken
	err = json.NewDecoder(resp.Body).Decode(&challengeToken)
	if err != nil {
		return nil, err
	}

	var bodyBytes []byte

	// Keep polling if Status Code is 400 and apiError.Error ==
	// "authorization_pending". Done if status code is 200. Else error.
	poll := func() error {
                var requestTokenURL string
                if da.config.AuthzID() == "" {
                    requestTokenURL = fmt.Sprintf(okta.OAuthV1TokenEndpointFormat, da.config.OrgDomain())
                } else {
                    requestTokenURL = fmt.Sprintf(okta.CustomAuthzV1TokenEndpointFormat, da.config.OrgDomain(), da.config.AuthzID())
                }
		data := url.Values{
			"client_id":  {clientID},
			"scope":      {"openid profile"},
			"grant_type": {"http://auth0.com/oauth/grant-type/mfa-oob"},
			"oob_code":   {challengeToken.OOBCode},
			"mfa_token":  {mfaToken.Token},
		}
		req, err := http.NewRequest(http.MethodPost, requestTokenURL, body)
		if err != nil {
			return err
		}
		body := strings.NewReader(data.Encode())
		req.Body = io.NopCloser(body)
		req.Header.Add(utils.Accept, utils.ApplicationJSON)
		req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
		req.Header.Add(utils.UserAgentHeader, da.config.UserAgent())
		req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)

		resp, err := da.config.HTTPClient().Do(req)
		bodyBytes, _ = io.ReadAll(resp.Body)
		if err != nil {
			return backoff.Permanent(fmt.Errorf(okta.PollingFetchAccessTokenAPIErrorMessage, err))
		}
		if resp.StatusCode == http.StatusOK {
			// done
			return nil
		}
		if resp.StatusCode == http.StatusBadRequest {
			// continue polling if status code is 400 and "error" is "authorization_pending"
			apiErr, err := okta.APIErr(bodyBytes)
			if err != nil {
				return backoff.Permanent(fmt.Errorf(okta.PollingFetchAccessTokenAPIErrorBodyMessage, string(bodyBytes)))
			}
			if apiErr.ErrorType != okta.AuthorizationPendingErrorType && apiErr.ErrorType != okta.SlowDownErrorType {
				return backoff.Permanent(fmt.Errorf(okta.PollingFetchAccessTokenAPIErrorPollingMessage, apiErr.ErrorType, apiErr.ErrorDescription))
			}

			return errors.New(okta.ContinuePollingMessage)
		}

		return backoff.Permanent(fmt.Errorf(okta.PollingFetchAccessTokenAPIErrorStatusMessage, resp.Status, string(bodyBytes)))
	}

	bOff := boff.NewBackoff(context.Background())
	err = backoff.Retry(poll, bOff)
	if err != nil {
		return nil, err
	}

	at = &okta.AccessToken{}
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(at)
	if err != nil {
		return nil, err
	}

	return
}

// requestMFAToken The start of the direct auth OOB MFA flow starts with requesting
// the beginning access token.
// https://developer.okta.com/docs/guides/configure-direct-auth-grants/dmfaoobov/main/
func (da *DirectAuthentication) requestMFAToken() (*okta.MFAToken, error) {
	clientID := da.config.OIDCAppID()
	username := da.config.Username()
	password := da.config.Password()
        var requestTokenURL string
                if da.config.AuthzID() == "" {
                    requestTokenURL = fmt.Sprintf(okta.OAuthV1TokenEndpointFormat, da.config.OrgDomain())
                } else {
                    requestTokenURL = fmt.Sprintf(okta.CustomAuthzV1TokenEndpointFormat, da.config.OrgDomain(), da.config.AuthzID())
                }
	data := url.Values{
		"client_id":  {clientID},
		"grant_type": {"password"},
		"scope":      {"openid profile"},
		"username":   {username},
		"password":   {password},
	}
	body := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, requestTokenURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(utils.Accept, utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
	req.Header.Add(utils.UserAgentHeader, da.config.UserAgent())
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIDirectOperation)

	resp, err := da.config.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	// we are in fact expecting a 403
	// https://developer.okta.com/docs/guides/configure-direct-auth-grants/dmfaoobov/main/#okta-token-response
	if resp.StatusCode != http.StatusForbidden {
		return nil, fmt.Errorf("requesting OOB MFA token received response %q", resp.Status)
	}

	ct := resp.Header.Get(utils.ContentType)
	if !strings.Contains(ct, utils.ApplicationJSON) {
		return nil, fmt.Errorf(okta.NonJSONContentTypeErrorMessage, ct)
	}

	var mfaToken okta.MFAToken
	err = json.NewDecoder(resp.Body).Decode(&mfaToken)
	if err != nil {
		return nil, err
	}

	return &mfaToken, nil
}
