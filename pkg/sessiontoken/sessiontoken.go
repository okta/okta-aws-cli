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

package sessiontoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/cenkalti/backoff/v4"
	"github.com/mdp/qrterminal"
	"golang.org/x/net/html"

	"github.com/okta/okta-aws-cli/pkg/agent"
	oaws "github.com/okta/okta-aws-cli/pkg/aws"
	boff "github.com/okta/okta-aws-cli/pkg/backoff"
	"github.com/okta/okta-aws-cli/pkg/config"
	"github.com/okta/okta-aws-cli/pkg/output"
)

// SessionToken Encapsulates the work of getting an AWS Session Token
type SessionToken struct {
	config *config.Config
}

// AuthToken Encapsulates an Okta Token
// https://developer.okta.com/docs/reference/api/oidc/#token
type AuthToken struct {
	AccessToken string `json:"access_token,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// DeviceAuthorization Encapsulates Okta API result to
// /oauth2/v1/device/authorize call
type DeviceAuthorization struct {
	UserCode                string `json:"user_code,omitempty"`
	DeviceCode              string `json:"device_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}

type apiError struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// IDPAndRole IdP and role pairs
type IDPAndRole struct {
	idp  string
	role string
}

// NewSessionToken Creates a new session token.
func NewSessionToken() (*SessionToken, error) {
	config := config.NewConfig()
	err := config.CheckConfig()
	if err != nil {
		return nil, err
	}

	return &SessionToken{
		config: config,
	}, nil
}

// EstablishToken Template method of the steps to establish an AWS session
// token.
func (s *SessionToken) EstablishToken() error {
	deviceAuth, err := s.Authorize()
	if err != nil {
		return err
	}

	s.PromptAuthentication(deviceAuth)

	authToken, err := s.GetAccessToken(deviceAuth)
	if err != nil {
		return err
	}

	authToken, err = s.GetSSOToken(authToken)
	if err != nil {
		return err
	}

	assertion, err := s.GetSAMLAssertion(authToken)
	if err != nil {
		return err
	}

	idpRolesMap, err := s.GetIDPRolesMapFromAssertion(assertion)
	if err != nil {
		return err
	}

	idpAndRole, err := s.PromptForIdpAndRole(idpRolesMap)
	if err != nil {
		return err
	}

	ac, err := s.GetAWSCredential(idpAndRole, assertion)
	if err != nil {
		return err
	}

	err = s.RenderCredential(ac)
	if err != nil {
		return err
	}

	return nil
}

// RenderCredential Renders the credentials in the prescribed format.
func (s *SessionToken) RenderCredential(ac *oaws.Credential) error {
	var o output.Outputter
	switch s.config.Format {
	case "aws-credentials":
		o = output.NewAWSCredentialsFile()
	default:
		o = output.NewEnvVar()
		fmt.Fprintf(os.Stderr, "\n")
	}

	return o.Output(s.config, ac)
}

// GetAWSCredential Get AWS Credentials with an STS Assume Role With SAML AWS
// API call.
func (s *SessionToken) GetAWSCredential(idpAndRole *IDPAndRole, assertion string) (*oaws.Credential, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	svc := sts.New(sess)
	input := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int64(3600),
		PrincipalArn:    aws.String(idpAndRole.idp),
		RoleArn:         aws.String(idpAndRole.role),
		SAMLAssertion:   aws.String(assertion),
	}
	svcResp, err := svc.AssumeRoleWithSAML(input)
	if err != nil {
		return nil, err
	}

	return &oaws.Credential{
		AccessKeyID:     *svcResp.Credentials.AccessKeyId,
		SecretAccessKey: *svcResp.Credentials.SecretAccessKey,
		SessionToken:    *svcResp.Credentials.SessionToken,
	}, nil
}

// PromptForIdpAndRole UX to prompt operator for the AWS role whose credentials
// will be utilized.
func (s *SessionToken) PromptForIdpAndRole(idpRoles map[string][]string) (*IDPAndRole, error) {
	result := &IDPAndRole{}

	idps := make([]string, 0, len(idpRoles))
	for idp := range idpRoles {
		idps = append(idps, idp)
	}

	if len(idps) == 0 {
		return result, errors.New("no IdPs to choose from")
	}

	stderrIsOutAskOpt := func(options *survey.AskOptions) error {
		options.Stdio = terminal.Stdio{
			In:  os.Stdin,
			Out: os.Stderr,
			Err: os.Stderr,
		}
		return nil
	}

	var idp string
	prompt := &survey.Select{
		Message: "Choose an IdP:",
		Options: idps,
	}
	if s.config.AWSIAMIdP != "" {
		prompt.Default = s.config.AWSIAMIdP
	}

	survey.AskOne(prompt, &idp, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
	if idp == "" {
		return result, errors.New("failed to select IdP value")
	}

	roles := idpRoles[idp]
	if len(roles) == 0 {
		return result, fmt.Errorf("IdP %q has no roles to choose from", idp)
	}

	var role string
	// survey for role
	prompt = &survey.Select{
		Message: "Choose a Role:",
		Options: roles,
	}
	if s.config.AWSIAMRole != "" {
		prompt.Default = s.config.AWSIAMRole
	}
	survey.AskOne(prompt, &role, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
	if role == "" {
		return result, fmt.Errorf("no roles chosen for IdP %q", idp)
	}

	result.idp = idp
	result.role = role
	return result, nil
}

// GetIDPRolesMapFromAssertion Get AWS IdP and Roles from SAML assertion. Result
// a map string string slice keyed by the IdP ARN value and slice of ARN role
// values.
func (s *SessionToken) GetIDPRolesMapFromAssertion(encoded string) (map[string][]string, error) {
	result := make(map[string][]string)
	assertion, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return result, err
	}
	doc, err := html.Parse(strings.NewReader(string(assertion)))
	if err != nil {
		return result, err
	}

	if role, ok := findSAMLRoleAttibute(doc); ok {
		pairs := findSAMLIdPRoleValues(role)
		for _, pair := range pairs {
			idpRole := strings.Split(pair, ",")
			idp := idpRole[0]
			if _, found := result[idp]; !found {
				result[idp] = []string{}
			}

			if len(idpRole) == 1 {
				continue
			}

			roles := result[idp]
			role := idpRole[1]
			roles = append(roles, role)
			result[idp] = roles
		}
	}
	return result, nil
}

// GetSAMLAssertion Gets the SAML assertion from Okta API /login/token/sso
func (s *SessionToken) GetSAMLAssertion(at *AuthToken) (string, error) {
	params := url.Values{"token": {at.AccessToken}}
	apiURL := fmt.Sprintf("https://%s/login/token/sso?%s", s.config.OrgDomain, params.Encode())

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Accept", "text/html")
	req.Header.Add("User-Agent", agent.NewUserAgent(config.Version).String())

	resp, err := s.config.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GetSAMLAssertion received API response %q", resp.Status)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	doc, err := html.Parse(strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", err
	}

	if assertion, ok := findSAMLResponse(doc); ok {
		return assertion, nil
	}
	return "", fmt.Errorf("could not find SAML assertion in API call %q", apiURL)
}

// GetSSOToken see:
// https://developer.okta.com/docs/reference/api/oidc/#token
func (s *SessionToken) GetSSOToken(at *AuthToken) (*AuthToken, error) {
	apiURL := fmt.Sprintf("https://%s/oauth2/v1/token", s.config.OrgDomain)

	data := url.Values{
		"client_id":            {s.config.OIDCAppID},
		"actor_token":          {at.AccessToken},
		"actor_token_type":     {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {at.IDToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:id_token"},
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:okta:oauth:token-type:web_sso_token"},
		"audience":             {fmt.Sprintf("urn:okta:apps:%s", s.config.FedAppID)},
	}
	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest(http.MethodPost, apiURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", agent.NewUserAgent(config.Version).String())

	resp, err := s.config.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetSSOToken received API response %q", resp.Status)
	}

	var respAt AuthToken
	bodyBytes, _ := io.ReadAll(resp.Body)
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&respAt)
	if err != nil {
		return nil, err
	}

	return &respAt, nil
}

// PromptAuthentication UX to display activation URL and code.
func (s *SessionToken) PromptAuthentication(da *DeviceAuthorization) {
	var qrBuf []byte
	qrCode := ""

	if s.config.QRCode {
		qrBuf = make([]byte, 4096)
		buf := bytes.NewBufferString("")
		qrterminal.GenerateHalfBlock(da.VerificationURIComplete, qrterminal.L, buf)
		buf.Read(qrBuf)
		qrCode = fmt.Sprintf("%s\n", qrBuf)
	}

	prompt := `Open the following URL to begin Okta device authorization for the AWS CLI.

%s%s

`

	fmt.Fprintf(os.Stderr, prompt, qrCode, da.VerificationURIComplete)
}

func apiErr(bodyBytes []byte) (*apiError, error) {
	var ae apiError
	err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&ae)
	if err != nil {
		return nil, err
	}

	return &ae, nil
}

// GetAccessToken see:
// https://developer.okta.com/docs/reference/api/oidc/#token
func (s *SessionToken) GetAccessToken(deviceAuth *DeviceAuthorization) (*AuthToken, error) {
	apiURL := fmt.Sprintf("https://%s/oauth2/v1/token", s.config.OrgDomain)

	req, err := http.NewRequest(http.MethodPost, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", agent.NewUserAgent(config.Version).String())

	var bodyBytes []byte

	// keep polling if Status Code is 400 and apiError.Error == "authorization_pending"
	// done if status code is 200
	// else error
	poll := func() error {
		data := url.Values{
			"client_id":   {s.config.OIDCAppID},
			"device_code": {deviceAuth.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}
		body := strings.NewReader(data.Encode())
		req.Body = io.NopCloser(body)

		resp, err := s.config.HTTPClient.Do(req)
		bodyBytes, _ = io.ReadAll(resp.Body)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("GetAccessToken polling received API err %+v", err))
		}
		if resp.StatusCode == http.StatusOK {
			// done
			return nil
		}
		if resp.StatusCode == http.StatusBadRequest {
			// continue polling if status code is 400 and "error" is "authorization_pending"
			apiErr, err := apiErr(bodyBytes)
			if err != nil {
				return backoff.Permanent(fmt.Errorf("GetAccessToken polling received unexpected API error body %q", string(bodyBytes)))
			}
			if apiErr.Error != "authorization_pending" {
				return backoff.Permanent(fmt.Errorf("GetAccessToken polling received unexpected API polling error %q - %q", apiErr.Error, apiErr.ErrorDescription))
			}

			return errors.New("continue polling")
		}

		return backoff.Permanent(fmt.Errorf("GetAccessToken polling received unexpected API status %q %q", resp.Status, string(bodyBytes)))
	}

	bOff := boff.NewBackoff(context.Background())
	err = backoff.Retry(poll, bOff)
	if err != nil {
		return nil, err
	}

	var at AuthToken
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&at)
	if err != nil {
		return nil, err
	}

	return &at, nil
}

// Authorize see:
// https://developer.okta.com/docs/reference/api/oidc/#device-authorize
func (s *SessionToken) Authorize() (*DeviceAuthorization, error) {
	apiURL := fmt.Sprintf("https://%s/oauth2/v1/device/authorize", s.config.OrgDomain)
	data := url.Values{
		"client_id": {s.config.OIDCAppID},
		"scope":     {"openid okta.apps.sso"},
	}
	body := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, apiURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", agent.NewUserAgent(config.Version).String())

	resp, err := s.config.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Authorize received API response %q", resp.Status)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return nil, fmt.Errorf("Authorize non-JSON API response content type %q", ct)
	}

	var da DeviceAuthorization
	bodyBytes, _ := io.ReadAll(resp.Body)
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&da)
	if err != nil {
		return nil, err
	}

	return &da, nil
}

func findSAMLResponse(n *html.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		found := false
		var val string
		for _, a := range n.Attr {
			if a.Key == "name" && a.Val == "SAMLResponse" {
				found = true
			}
			if a.Key == "value" {
				val = a.Val
			}
		}
		if found {
			return val, true
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if v, ok := findSAMLResponse(c); ok {
			return v, ok
		}
	}
	return "", false
}

func findSAMLIdPRoleValues(n *html.Node) []string {
	result := []string{}
	if n == nil {
		return result
	}
	if n.Type == html.ElementNode && n.Data == "saml2:attribute" {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.FirstChild != nil {
				result = append(result, c.FirstChild.Data)
			}
		}
	}
	return result
}

func findSAMLRoleAttibute(n *html.Node) (*html.Node, bool) {
	if n == nil {
		return nil, false
	}
	if n.Type == html.ElementNode && n.Data == "saml2:attribute" {
		for _, a := range n.Attr {
			if a.Key == "name" && a.Val == "https://aws.amazon.com/SAML/Attributes/Role" {
				return n, true
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found, ok := findSAMLRoleAttibute(c); ok {
			return found, ok
		}
	}
	return nil, false
}
