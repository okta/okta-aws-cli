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
	brwsr "github.com/pkg/browser"
	"golang.org/x/net/html"

	"github.com/okta/okta-aws-cli/internal/agent"
	oaws "github.com/okta/okta-aws-cli/internal/aws"
	boff "github.com/okta/okta-aws-cli/internal/backoff"
	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/output"
	pstr "github.com/okta/okta-aws-cli/pkg/strings"
)

const (
	amazonAWS               = "amazon_aws"
	accept                  = "Accept"
	applicationJSON         = "application/json"
	applicationXWwwForm     = "application/x-www-form-urlencoded"
	contentType             = "Content-Type"
	userAgent               = "User-Agent"
	nameKey                 = "name"
	saml2Attribute          = "saml2:attribute"
	samlAttributesRole      = "https://aws.amazon.com/SAML/Attributes/Role"
	oauthV1TokenEndpointFmt = "https://%s/oauth2/v1/token"
)

// SessionToken Encapsulates the work of getting an AWS Session Token
type SessionToken struct {
	config *config.Config
}

// accessToken Encapsulates an Okta access token
// https://developer.okta.com/docs/reference/api/oidc/#token
type accessToken struct {
	AccessToken  string `json:"access_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	DeviceSecret string `json:"device_secret,omitempty"`
}

// deviceAuthorization Encapsulates Okta API result to
// /oauth2/v1/device/authorize call
type deviceAuthorization struct {
	UserCode                string `json:"user_code,omitempty"`
	DeviceCode              string `json:"device_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}

// oktaApplication Okta API application object
// See: https://developer.okta.com/docs/reference/api/apps/#application-object
type oktaApplication struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Settings struct {
		App struct {
			IdentityProviderARN string `json:"identityProviderArn"`
			WebSSOClientID      string `json:"webSSOAllowedClient"`
		} `json:"app"`
	} `json:"settings"`
}

type assertionArtifact struct {
	fedApp   *oktaApplication
	fedAppID string
	idpARN   string
}

// apiError Wrapper for Okta API error
type apiError struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// idpAndRole IdP and role pairs
type idpAndRole struct {
	idp  string
	role string
}

var stderrIsOutAskOpt = func(options *survey.AskOptions) error {
	options.Stdio = terminal.Stdio{
		In:  os.Stdin,
		Out: os.Stderr,
		Err: os.Stderr,
	}
	return nil
}

// NewSessionToken Creates a new session token.
func NewSessionToken() (token *SessionToken, err error) {
	config := config.NewConfig()
	err = config.CheckConfig()
	if err != nil {
		return nil, err
	}
	token = &SessionToken{
		config: config,
	}
	return token, nil
}

// EstablishToken Template method of the steps to establish an AWS session
// token.
func (s *SessionToken) EstablishToken() error {
	clientID := s.config.OIDCAppID
	deviceAuth, err := s.authorize(clientID)
	if err != nil {
		return err
	}

	s.promptAuthentication(deviceAuth)

	at, err := s.fetchAccessToken(clientID, deviceAuth)
	if err != nil {
		return err
	}

	apps, err := s.listFedApps(clientID, at)
	if err != nil {
		return err
	}

	if len(apps) == 0 && s.config.FedAppID != "" {

		// Alternate path where operator's OIDC app doesn't have okta.apps.read grant

		return s.establishTokenWithFedAppID(clientID, at)
	}
	if len(apps) == 0 {
		return fmt.Errorf("there aren't any AWS Federation Applications associated with OIDC App %q, check if it has %q scope and is the allowed web SSO client for an AWS Federation app", clientID, "okta.apps.read")
	}

	artifacts := make([]*assertionArtifact, len(apps))
	for i, app := range apps {
		artifact := assertionArtifact{
			fedApp:   app,
			fedAppID: app.ID,
			idpARN:   app.Settings.App.IdentityProviderARN,
		}

		artifacts[i] = &artifact
	}

	artifact, err := s.promptForIdp(artifacts)
	if err != nil {
		return err
	}

	iar, assertion, err := s.promptForRole(clientID, artifact, at)
	if err != nil {
		return err
	}

	ac, err := s.fetchAWSCredentialWithSAMLRole(iar, assertion)
	if err != nil {
		return err
	}

	err = s.renderCredential(ac)
	if err != nil {
		return err
	}

	return nil
}

func (s *SessionToken) establishTokenWithFedAppID(clientID string, at *accessToken) error {
	at, err := s.fetchSSOWebToken(clientID, s.config.FedAppID, at)
	if err != nil {
		return err
	}

	assertion, err := s.fetchSAMLAssertion(at)
	if err != nil {
		return err
	}

	idpRolesMap, err := s.extractIDPAndRolesMapFromAssertion(assertion)
	if err != nil {
		return err
	}

	iar, err := s.promptForIdpAndRole(idpRolesMap)
	if err != nil {
		return err
	}

	ac, err := s.fetchAWSCredentialWithSAMLRole(iar, assertion)
	if err != nil {
		return err
	}

	err = s.renderCredential(ac)
	if err != nil {
		return err
	}

	return nil
}

// renderCredential Renders the credentials in the prescribed format.
func (s *SessionToken) renderCredential(ac *oaws.Credential) error {
	var o output.Outputter
	switch s.config.Format {
	case pstr.AWSCredentials:
		o = output.NewAWSCredentialsFile()
	default:
		o = output.NewEnvVar()
		fmt.Fprintf(os.Stderr, "\n")
	}

	return o.Output(s.config, ac)
}

// fetchAWSCredentialWithSAMLRole Get AWS Credentials with an STS Assume Role With SAML AWS
// API call.
func (s *SessionToken) fetchAWSCredentialWithSAMLRole(iar *idpAndRole, assertion string) (credential *oaws.Credential, err error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	svc := sts.New(sess)
	input := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int64(s.config.AWSSessionDuration),
		PrincipalArn:    aws.String(iar.idp),
		RoleArn:         aws.String(iar.role),
		SAMLAssertion:   aws.String(assertion),
	}
	svcResp, err := svc.AssumeRoleWithSAML(input)
	if err != nil {
		return nil, err
	}

	credential = &oaws.Credential{
		AccessKeyID:     *svcResp.Credentials.AccessKeyId,
		SecretAccessKey: *svcResp.Credentials.SecretAccessKey,
		SessionToken:    *svcResp.Credentials.SessionToken,
	}
	return credential, nil
}

// promptForIdp UX to prompt operator for the AWS idp ARN and return the associated assertion artifact
func (s *SessionToken) promptForIdp(artifacts []*assertionArtifact) (artifact *assertionArtifact, err error) {
	idps := make([]string, len(artifacts))
	for i, a := range artifacts {
		idps[i] = a.idpARN
	}

	if len(idps) == 0 {
		return nil, errors.New("no IdPs to choose from")
	}

	var idp string
	prompt := &survey.Select{
		Message: "Choose an IdP:",
		Options: idps,
	}
	if s.config.AWSIAMIdP != "" {
		prompt.Default = s.config.AWSIAMIdP
	}

	err = survey.AskOne(prompt, &idp, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
	if err != nil {
		return nil, fmt.Errorf("error asking for IdP selection: %w", err)
	}
	if idp == "" {
		return nil, errors.New("failed to select IdP value")
	}

	for _, artifact = range artifacts {
		if artifact.idpARN == idp {
			return artifact, nil
		}
	}
	return nil, errors.New("failed to set artifact")
}

func (s *SessionToken) promptForRole(clientID string, artifact *assertionArtifact, at *accessToken) (iar *idpAndRole, assertion string, err error) {

	swt, err := s.fetchSSOWebToken(clientID, artifact.fedAppID, at)
	if err != nil {
		return
	}

	assertion, err = s.fetchSAMLAssertion(swt)
	if err != nil {
		return
	}

	idpRolesMap, err := s.extractIDPAndRolesMapFromAssertion(assertion)
	if err != nil {
		return
	}
	idp := artifact.idpARN

	roles := idpRolesMap[idp]
	if len(roles) == 0 {
		return nil, assertion, fmt.Errorf("provider %q has no roles to choose from", idp)
	}

	var role string
	// survey for role
	prompt := &survey.Select{
		Message: "Choose a Role:",
		Options: roles,
	}
	if s.config.AWSIAMRole != "" {
		prompt.Default = s.config.AWSIAMRole
	}
	err = survey.AskOne(prompt, &role, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
	if err != nil {
		return nil, assertion, fmt.Errorf("error asking for role selection: %w", err)
	}
	if role == "" {
		return nil, assertion, fmt.Errorf("no roles chosen for provider %q", idp)
	}

	iar = &idpAndRole{
		idp:  idp,
		role: role,
	}
	return
}

// promptForIdpAndRole UX to prompt operator for the AWS role whose credentials
// will be utilized.
func (s *SessionToken) promptForIdpAndRole(idpRoles map[string][]string) (iar *idpAndRole, err error) {
	idps := make([]string, 0, len(idpRoles))
	for idp := range idpRoles {
		idps = append(idps, idp)
	}

	if len(idps) == 0 {
		return nil, errors.New("no IdPs to choose from")
	}

	var idp string

	if s.config.AWSIAMIdP != "" {
		idp = s.config.AWSIAMIdP
	} else if len(idps) == 1 {
		idp = idps[0]
	} else {
		prompt := &survey.Select{
			Message: "Choose an IdP:",
			Options: idps,
		}

		err = survey.AskOne(prompt, &idp, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
		if err != nil {
			return nil, fmt.Errorf("error asking for IdP selection: %w", err)
		}
		if idp == "" {
			return nil, errors.New("failed to select IdP value")
		}
	}

	roles := idpRoles[idp]
	if len(roles) == 0 {
		return nil, fmt.Errorf("provider %q has no roles to choose from", idp)
	}

	var role string
	// survey for role

	if s.config.AWSIAMRole != "" {
		role = s.config.AWSIAMRole
	} else if len(roles) == 1 {
		role = roles[0]
	} else {
		prompt := &survey.Select{
			Message: "Choose a Role:",
			Options: roles,
		}
		err = survey.AskOne(prompt, &role, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
		if err != nil {
			return nil, fmt.Errorf("error asking for role selection: %w", err)
		}
		if role == "" {
			return nil, fmt.Errorf("no roles chosen for provider %q", idp)
		}
	}

	iar = &idpAndRole{
		idp:  idp,
		role: role,
	}
	return iar, nil
}

// extractIDPAndRolesMapFromAssertion Get AWS IdP and Roles from SAML assertion. Result
// a map string string slice keyed by the IdP ARN value and slice of ARN role
// values.
func (s *SessionToken) extractIDPAndRolesMapFromAssertion(encoded string) (irmap map[string][]string, err error) {
	assertion, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	doc, err := html.Parse(strings.NewReader(string(assertion)))
	if err != nil {
		return nil, err
	}

	irmap = make(map[string][]string)
	if role, ok := findSAMLRoleAttibute(doc); ok {
		pairs := findSAMLIdPRoleValues(role)
		for _, pair := range pairs {
			idpRole := strings.Split(pair, ",")
			idp := idpRole[0]
			if _, found := irmap[idp]; !found {
				irmap[idp] = []string{}
			}

			if len(idpRole) == 1 {
				continue
			}

			roles := irmap[idp]
			role := idpRole[1]
			roles = append(roles, role)
			irmap[idp] = roles
		}
	}
	return irmap, nil
}

// fetchSAMLAssertion Gets the SAML assertion from Okta API /login/token/sso
func (s *SessionToken) fetchSAMLAssertion(at *accessToken) (assertion string, err error) {
	params := url.Values{"token": {at.AccessToken}}
	apiURL := fmt.Sprintf("https://%s/login/token/sso?%s", s.config.OrgDomain, params.Encode())

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return assertion, err
	}
	req.Header.Add(accept, "text/html")
	req.Header.Add(userAgent, agent.NewUserAgent(config.Version).String())

	resp, err := s.config.HTTPClient.Do(req)

	if err != nil {
		return assertion, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching SAML assertion received API response %q - %q", resp.Status, string(bodyBytes))
	}

	doc, err := html.Parse(strings.NewReader(string(bodyBytes)))
	if err != nil {
		return assertion, err
	}

	if assertion, ok := findSAMLResponse(doc); ok {
		return assertion, nil
	}
	return assertion, fmt.Errorf("could not find SAML assertion in API call %q", apiURL)
}

// fetchSSOWebToken see:
// https://developer.okta.com/docs/reference/api/oidc/#token
func (s *SessionToken) fetchSSOWebToken(clientID, awsFedAppID string, at *accessToken) (token *accessToken, err error) {
	apiURL := fmt.Sprintf(oauthV1TokenEndpointFmt, s.config.OrgDomain)

	data := url.Values{
		"client_id":            {clientID},
		"actor_token":          {at.AccessToken},
		"actor_token_type":     {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {at.IDToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:id_token"},
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:okta:oauth:token-type:web_sso_token"},
		"audience":             {fmt.Sprintf("urn:okta:apps:%s", awsFedAppID)},
	}
	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest(http.MethodPost, apiURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(accept, applicationJSON)
	req.Header.Add(contentType, applicationXWwwForm)
	req.Header.Add(userAgent, agent.NewUserAgent(config.Version).String())

	resp, err := s.config.HTTPClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching SSO web token received API response %q - %q", resp.Status, string(bodyBytes))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	token = &accessToken{}
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(token)
	if err != nil {
		return nil, err
	}

	return
}

// promptAuthentication UX to display activation URL and code.
func (s *SessionToken) promptAuthentication(da *deviceAuthorization) {
	var qrBuf []byte
	qrCode := ""

	if s.config.QRCode {
		qrBuf = make([]byte, 4096)
		buf := bytes.NewBufferString("")
		qrterminal.GenerateHalfBlock(da.VerificationURIComplete, qrterminal.L, buf)
		if _, err := buf.Read(qrBuf); err == nil {
			qrCode = fmt.Sprintf("%s\n", qrBuf)
		}
	}

	prompt := `Open the following URL to begin Okta device authorization for the AWS CLI.

%s%s

`

	fmt.Fprintf(os.Stderr, prompt, qrCode, da.VerificationURIComplete)

	if s.config.OpenBrowser {
		if err := brwsr.OpenURL(da.VerificationURIComplete); err != nil {
			fmt.Printf("Failed to open activation URL with system browser: %v\n", err)
		}
	}
}

// ListFedApp Lists Okta AWS Fed Apps that are active. Errors after that occur
// after getting anything other than a 403 on /api/v1/apps will be wrapped as as
// an error that is related having multiple fed apps available -
// hasMultipleFedApps. Requires assoicated OIDC app has been granted
// okta.apps.read to its scope.
func (s *SessionToken) listFedApps(clientID string, at *accessToken) (apps []*oktaApplication, err error) {
	apiURL, err := url.Parse(fmt.Sprintf("https://%s/api/v1/apps", s.config.OrgDomain))
	if err != nil {
		return apps, err
	}
	params := url.Values{}
	params.Add("limit", "200")
	params.Add("q", amazonAWS)
	params.Add("filter", `status eq "ACTIVE"`)
	apiURL.RawQuery = params.Encode()
	req, err := http.NewRequest(http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return apps, err
	}

	req.Header.Add(accept, applicationJSON)
	req.Header.Add(contentType, applicationJSON)
	req.Header.Add(userAgent, agent.NewUserAgent(config.Version).String())
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", at.TokenType, at.AccessToken))
	resp, err := s.config.HTTPClient.Do(req)

	if err != nil {
		return apps, newMultipleFedAppsError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return apps, err
	}

	// Any errors after this point should be considered related to having multiple fed apps
	if resp.StatusCode != http.StatusOK {
		return apps, newMultipleFedAppsError(err)
	}

	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		return apps, newMultipleFedAppsError(err)
	}

	var oktaApps []oktaApplication

	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&oktaApps)
	if err != nil {
		return apps, newMultipleFedAppsError(err)
	}

	apps = make([]*oktaApplication, 0)
	for i, app := range oktaApps {
		if app.Name != amazonAWS {
			continue
		}
		if app.Status != "ACTIVE" {
			continue
		}
		if app.Settings.App.WebSSOClientID != clientID {
			continue
		}
		oa := oktaApps[i]
		apps = append(apps, &oa)
	}

	return
}

// fetchAccessToken see:
// https://developer.okta.com/docs/reference/api/oidc/#token
func (s *SessionToken) fetchAccessToken(clientID string, deviceAuth *deviceAuthorization) (at *accessToken, err error) {
	apiURL := fmt.Sprintf(oauthV1TokenEndpointFmt, s.config.OrgDomain)

	req, err := http.NewRequest(http.MethodPost, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(accept, applicationJSON)
	req.Header.Add(contentType, applicationXWwwForm)
	req.Header.Add(userAgent, agent.NewUserAgent(config.Version).String())

	var bodyBytes []byte

	// keep polling if Status Code is 400 and apiError.Error == "authorization_pending"
	// done if status code is 200
	// else error
	poll := func() error {
		data := url.Values{
			"client_id":   {clientID},
			"device_code": {deviceAuth.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}
		body := strings.NewReader(data.Encode())
		req.Body = io.NopCloser(body)

		resp, err := s.config.HTTPClient.Do(req)

		if err != nil {
			return backoff.Permanent(fmt.Errorf("fetching access token polling received API err %w", err))
		}

		defer resp.Body.Close()
		bodyBytes, _ = io.ReadAll(resp.Body)

		if resp.StatusCode == http.StatusOK {
			// done
			return nil
		}
		if resp.StatusCode == http.StatusBadRequest {
			// continue polling if status code is 400 and "error" is "authorization_pending"
			apiErr, err := apiErr(bodyBytes)
			if err != nil {
				return backoff.Permanent(fmt.Errorf("fetching access token polling received unexpected API error body %q", string(bodyBytes)))
			}
			if apiErr.Error != "authorization_pending" {
				return backoff.Permanent(fmt.Errorf("fetching access token polling received unexpected API polling error %q - %q", apiErr.Error, apiErr.ErrorDescription))
			}

			return errors.New("continue polling")
		}

		return backoff.Permanent(fmt.Errorf("fetching access token polling received unexpected API status %q %q", resp.Status, string(bodyBytes)))

	}

	bOff := boff.NewBackoff(context.Background())
	err = backoff.Retry(poll, bOff)
	if err != nil {
		return nil, err
	}

	at = &accessToken{}
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(at)
	if err != nil {
		return nil, err
	}

	return
}

// authorize see:
// https://developer.okta.com/docs/reference/api/oidc/#device-authorize
func (s *SessionToken) authorize(clientID string) (*deviceAuthorization, error) {
	apiURL := fmt.Sprintf("https://%s/oauth2/v1/device/authorize", s.config.OrgDomain)
	data := url.Values{
		"client_id": {clientID},
		"scope":     {"openid okta.apps.sso okta.apps.read"},
	}
	body := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, apiURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(accept, applicationJSON)
	req.Header.Add(contentType, applicationXWwwForm)
	req.Header.Add(userAgent, agent.NewUserAgent(config.Version).String())

	resp, err := s.config.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorize received API response %q - %q", resp.Status, string(bodyBytes))
	}

	ct := resp.Header.Get(contentType)
	if !strings.Contains(ct, applicationJSON) {
		return nil, fmt.Errorf("authorize non-JSON API response content type %q", ct)
	}

	var da deviceAuthorization

	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&da)
	if err != nil {
		return nil, err
	}

	return &da, nil
}

func findSAMLResponse(n *html.Node) (val string, found bool) {
	if n == nil {
		return
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, a := range n.Attr {
			if a.Key == nameKey && a.Val == "SAMLResponse" {
				found = true
			}
			if a.Key == "value" {
				val = a.Val
			}
		}
		if found {
			return
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if val, found = findSAMLResponse(c); found {
			return
		}
	}
	return
}

func findSAMLIdPRoleValues(n *html.Node) []string {
	if n == nil {
		return nil
	}
	values := []string{}
	if n.Type == html.ElementNode && n.Data == saml2Attribute {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.FirstChild != nil {
				values = append(values, c.FirstChild.Data)
			}
		}
	}
	return values
}

func findSAMLRoleAttibute(n *html.Node) (node *html.Node, found bool) {
	if n == nil {
		return
	}
	if n.Type == html.ElementNode && n.Data == saml2Attribute {
		for _, a := range n.Attr {
			if a.Key == nameKey && a.Val == samlAttributesRole {
				return n, true
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if node, found = findSAMLRoleAttibute(c); found {
			return
		}
	}
	return nil, false
}

func apiErr(bodyBytes []byte) (ae *apiError, err error) {
	ae = &apiError{}
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(ae)
	return
}
