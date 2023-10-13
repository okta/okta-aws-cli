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
	osexec "os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/core"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/shlex"
	"github.com/mdp/qrterminal"
	brwsr "github.com/pkg/browser"
	"golang.org/x/net/html"

	oaws "github.com/okta/okta-aws-cli/internal/aws"
	boff "github.com/okta/okta-aws-cli/internal/backoff"
	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/exec"
	"github.com/okta/okta-aws-cli/internal/okta"
	"github.com/okta/okta-aws-cli/internal/output"
	"github.com/okta/okta-aws-cli/internal/utils"
)

const (
	amazonAWS                = "amazon_aws"
	accept                   = "Accept"
	nameKey                  = "name"
	saml2Attribute           = "saml2:attribute"
	samlAttributesRole       = "https://aws.amazon.com/SAML/Attributes/Role"
	askIDPError              = "error asking for IdP selection: %w"
	noRoleError              = "provider %q has no roles to choose from"
	noIDPsError              = "no IdPs to choose from"
	idpValueNotSelectedError = "failed to select IdP value"
	askRoleError             = "error asking for role selection: %w"
	noRolesError             = "no roles chosen for provider %q"
	chooseIDP                = "Choose an IdP:"
	chooseRole               = "Choose a Role:"
	idpSelectedTemplate      = `  {{color "default+hb"}}IdP: {{color "reset"}}{{color "cyan"}}{{ .IDP }}{{color "reset"}}`
	roleSelectedTemplate     = `  {{color "default+hb"}}Role: {{color "reset"}}{{color "cyan"}}{{ .Role }}{{color "reset"}}`
	dotOktaDir               = ".okta"
	tokenFileName            = "awscli-access-token.json"
	arnLabelPrintFmt         = "      %q: %q\n"
	arnPrintFmt              = "    %q\n"
)

type idpTemplateData struct {
	IDP string
}
type roleTemplateData struct {
	Role string
}

// WebSSOAuthentication Encapsulates the work of getting temporary IAM
// credentials through Okta's Web SSO authentication with an Okta AWS Federation
// Application.
//
// The overall API interactions are as follows:
// - CLI starts device authorization at /oauth2/v1/device/authorize
// - CLI polls for access token from device auth at /oauth2/v1/token
//   - Access token granted by Okta once user is authorized
//
// - CLI presents access token to Okta AWS Fed app for a SAML assertion at /login/token/sso
// - CLI presents SAML assertion to AWS STS for temporary AWS IAM creds
type WebSSOAuthentication struct {
	config                *config.Config
	fedAppAlreadySelected bool
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

// NewWebSSOAuthentication New Web SSO Authentication constructor
func NewWebSSOAuthentication(cfg *config.Config) (token *WebSSOAuthentication, err error) {
	token = &WebSSOAuthentication{
		config: cfg,
	}
	if token.isClassicOrg() {
		return nil, fmt.Errorf("%q is a Classic org, okta-aws-cli is an-OIE only tool", cfg.OrgDomain())
	}
	if cfg.IsProcessCredentialsFormat() {
		if cfg.AWSIAMIdP() == "" || cfg.AWSIAMRole() == "" || !cfg.OpenBrowser() {
			return nil, fmt.Errorf("arguments --%s , --%s , and --%s must be set for %q format", config.AWSIAMIdPFlag, config.AWSIAMRoleFlag, config.OpenBrowserFlag, cfg.Format())
		}
	}

	// Check if exec arg is present and that there are args for it before doing any work
	if cfg.Exec() {
		if _, err := exec.NewExec(); err != nil {
			return nil, err
		}
	}

	return token, nil
}

// EstablishIAMCredentials Steps to establish an AWS session token.
func (w *WebSSOAuthentication) EstablishIAMCredentials() error {
	clientID := w.config.OIDCAppID()
	var at *okta.AccessToken
	var apps []*okta.Application
	var err error
	at = w.cachedAccessToken()

	// If there is a cached okta access token, and it isn't expired, but the API
	// 401s redo the authorize step.
	for attempt := 1; attempt <= 2; attempt++ {
		err = nil
		if at == nil {
			deviceAuth, err := w.authorize()
			if err != nil {
				return err
			}

			w.promptAuthentication(deviceAuth)

			at, err = w.accessToken(deviceAuth)
			if err != nil {
				return err
			}
			at.Expiry = time.Now().Add(time.Duration(at.ExpiresIn) * time.Second).Format(time.RFC3339)
			w.cacheAccessToken(at)
		}
		if w.config.FedAppID() != "" {
			// Alternate path when operator knows their AWS Fed app ID
			err = w.establishTokenWithFedAppID(clientID, w.config.FedAppID(), at)
			if at != nil && err != nil {
				// possible bad cached access token, retry
				at = nil
				continue
			}
			return err
		}

		apps, err = w.listFedApps(clientID, at)
		if at != nil && err != nil {
			// possible bad cached access token, retry
			at = nil
			continue
		}
		break
	}

	if err != nil {
		return err
	}
	if len(apps) == 0 {
		errMsg := `
There aren't any AWS Federation Applications associated with OIDC App %q.
Check if it has %q scope and is the allowed web SSO client for an AWS
Federation app. Or, invoke okta-aws-cli including the client ID of the
AWS Federation App with --aws-acct-fed-app-id FED_APP_ID
		`
		return fmt.Errorf(errMsg, clientID, "okta.apps.read")
	}

	var fedAppID string
	if len(apps) == 1 {
		// only one app, we don't need to prompt selection of idp / fed app
		fedAppID = apps[0].ID
	} else if w.config.AllProfiles() {
		// special case, we're going to run the table and get all profiles for all apps
		errArr := []error{}
		for _, app := range apps {
			if err = w.establishTokenWithFedAppID(clientID, app.ID, at); err != nil {
				errArr = append(errArr, err)
			}
		}

		return errors.Join(errArr...)
	} else {
		// Here, we do want to prompt for selection of the Fed App.
		// If the app is making use of "Role value pattern" on AWS settings we
		// won't get the real ARN until we establish the web sso token.
		w.fedAppAlreadySelected = true
		fedAppID, err = w.selectFedApp(apps)
		if err != nil {
			return err
		}
	}

	return w.establishTokenWithFedAppID(clientID, fedAppID, at)
}

// choiceFriendlyLabelIDP returns a friendly choice for pretty printing IDP
// labels.  alternative value is the default value to return if a friendly
// determination can not be made.
func (w *WebSSOAuthentication) choiceFriendlyLabelIDP(alt, arn string, idps map[string]string) string {
	if idps == nil {
		return alt
	}

	if label, ok := idps[arn]; ok {
		if w.config.Debug() {
			w.consolePrint("  found IdP ARN %q having friendly label %q\n", arn, label)
		}
		return label
	}
	// treat ARN values as regexps
	for arnRegexp, label := range idps {
		if ok, _ := regexp.MatchString(arnRegexp, arn); ok {
			return label
		}
	}

	if w.config.Debug() {
		w.consolePrint("  did not find friendly label for IdP ARN\n")
		w.consolePrint(arnPrintFmt, arn)
		w.consolePrint("    in okta.yaml awscli.idps map:\n")
		for arn, label := range idps {
			w.consolePrint(arnLabelPrintFmt, arn, label)
		}
	}
	return alt
}

func (w *WebSSOAuthentication) selectFedApp(apps []*okta.Application) (string, error) {
	idps := make(map[string]*okta.Application)
	choices := make([]string, len(apps))
	var selected string
	var configIDPs map[string]string
	oktaConfig, err := w.config.OktaConfig()
	if err == nil {
		configIDPs = oktaConfig.AWSCLI.IDPS
	}

	for i, app := range apps {
		choiceLabel := w.choiceFriendlyLabelIDP(app.Label, app.Settings.App.IdentityProviderARN, configIDPs)

		// when OKTA_AWSCLI_IAM_IDP / --aws-iam-idp is set
		if w.config.AWSIAMIdP() == app.Settings.App.IdentityProviderARN {
			if !w.config.IsProcessCredentialsFormat() {
				idpData := idpTemplateData{
					IDP: choiceLabel,
				}
				rich, _, err := core.RunTemplate(idpSelectedTemplate, idpData)
				if err != nil {
					return "", err
				}
				fmt.Fprintln(os.Stderr, rich)
			}

			return app.ID, nil
		}

		choices[i] = choiceLabel
		idps[choiceLabel] = app
	}

	prompt := &survey.Select{
		Message: chooseIDP,
		Options: choices,
	}
	err = survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
	if err != nil {
		return "", fmt.Errorf(askIDPError, err)
	}
	if selected == "" {
		return "", errors.New(idpValueNotSelectedError)
	}

	return idps[selected].ID, nil
}

func (w *WebSSOAuthentication) establishTokenWithFedAppID(clientID, fedAppID string, at *okta.AccessToken) error {
	at, err := w.fetchSSOWebToken(clientID, fedAppID, at)
	if err != nil {
		return err
	}

	assertion, err := w.fetchSAMLAssertion(at)
	if err != nil {
		return err
	}

	idpRolesMap, err := w.extractIDPAndRolesMapFromAssertion(assertion)
	if err != nil {
		return err
	}

	if !w.config.AllProfiles() {
		iar, err := w.promptForIdpAndRole(idpRolesMap)
		if err != nil {
			return err
		}

		cc, err := w.awsAssumeRoleWithSAML(iar, assertion)
		if err != nil {
			return err
		}

		err = output.RenderAWSCredential(w.config, cc)
		if err != nil {
			return err
		}

		if w.config.Exec() {
			exe, _ := exec.NewExec()
			if err := exe.Run(cc); err != nil {
				return err
			}
		}
	} else {
		ccch := w.fetchAllAWSCredentialsWithSAMLRole(idpRolesMap, assertion)
		if err != nil {
			return err
		}
		for cc := range ccch {
			err = output.RenderAWSCredential(w.config, cc)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to render credential %s: %s\n", cc.Profile, err)
				continue
			}
		}

	}

	return nil
}

// awsAssumeRoleWithSAML Get AWS Credentials with an STS Assume Role With SAML AWS
// API call.
func (w *WebSSOAuthentication) awsAssumeRoleWithSAML(iar *idpAndRole, assertion string) (cc *oaws.CredentialContainer, err error) {
	awsCfg := aws.NewConfig().WithHTTPClient(w.config.HTTPClient())
	sess, err := session.NewSession(awsCfg)
	if err != nil {
		return
	}
	svc := sts.New(sess)
	input := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int64(w.config.AWSSessionDuration()),
		PrincipalArn:    aws.String(iar.idp),
		RoleArn:         aws.String(iar.role),
		SAMLAssertion:   aws.String(assertion),
	}
	svcResp, err := svc.AssumeRoleWithSAML(input)
	if err != nil {
		return
	}

	cc = &oaws.CredentialContainer{
		AccessKeyID:     *svcResp.Credentials.AccessKeyId,
		SecretAccessKey: *svcResp.Credentials.SecretAccessKey,
		SessionToken:    *svcResp.Credentials.SessionToken,
		Expiration:      svcResp.Credentials.Expiration,
	}
	if !w.config.AllProfiles() && w.config.Profile() != "" {
		cc.Profile = w.config.Profile()
		return cc, nil
	}

	var profileName, idpName, roleName string
	if _, after, found := strings.Cut(iar.idp, "/"); found {
		idpName = after
	}
	if _, after, found := strings.Cut(iar.role, "/"); found {
		roleName = after
	}
	sessCopy := sess.Copy(&aws.Config{
		Credentials: credentials.NewStaticCredentials(
			cc.AccessKeyID,
			cc.SecretAccessKey,
			cc.SessionToken,
		),
	})
	if p, err := w.fetchAWSAccountAlias(sessCopy); err != nil {
		org := "org"
		fmt.Fprintf(os.Stderr, "unable to determine account alias, setting alias name to %q\n", org)
		profileName = org
	} else {
		profileName = p
	}
	cc.Profile = fmt.Sprintf("%s-%s-%s", profileName, idpName, roleName)

	return cc, nil
}

// choiceFriendlyLabelRole returns a friendly choice for pretty printing Role
// labels.  The ARN default value to return if a friendly determination can not
// be made.
func (w *WebSSOAuthentication) choiceFriendlyLabelRole(arn string, roles map[string]string) string {
	if roles == nil {
		return arn
	}

	if label, ok := roles[arn]; ok {
		if w.config.Debug() {
			w.consolePrint("  found Role ARN %q having friendly label %q\n", arn, label)
		}
		return label
	}

	// treat ARN values as regexps
	for arnRegexp, label := range roles {
		if ok, _ := regexp.MatchString(arnRegexp, arn); ok {
			return label
		}
	}

	if w.config.Debug() {
		w.consolePrint("  did not find friendly label for Role ARN\n")
		w.consolePrint(arnPrintFmt, arn)
		w.consolePrint("    in okta.yaml awscli.roles map:\n")
		for arn, label := range roles {
			w.consolePrint(arnLabelPrintFmt, arn, label)
		}
	}
	return arn
}

// promptForRole prompt operator for the AWS Role ARN given a slice of Role ARNs
func (w *WebSSOAuthentication) promptForRole(idp string, roleARNs []string) (roleARN string, err error) {
	oktaConfig, err := w.config.OktaConfig()
	var configRoles map[string]string
	if err == nil {
		configRoles = oktaConfig.AWSCLI.ROLES
	}

	if len(roleARNs) == 1 || w.config.AWSIAMRole() != "" {
		roleARN = w.config.AWSIAMRole()
		if len(roleARNs) == 1 {
			roleARN = roleARNs[0]
		}
		roleLabel := w.choiceFriendlyLabelRole(roleARN, configRoles)
		roleData := roleTemplateData{
			Role: roleLabel,
		}
		if !w.config.IsProcessCredentialsFormat() {
			rich, _, err := core.RunTemplate(roleSelectedTemplate, roleData)
			if err != nil {
				return "", err
			}
			fmt.Fprintln(os.Stderr, rich)
		}
		return roleARN, nil
	}

	promptRoles := []string{}
	labelsARNs := map[string]string{}
	for _, arn := range roleARNs {
		roleLabel := w.choiceFriendlyLabelRole(arn, configRoles)
		promptRoles = append(promptRoles, roleLabel)
		labelsARNs[roleLabel] = arn
	}

	prompt := &survey.Select{
		Message: chooseRole,
		Options: promptRoles,
	}
	var selected string
	err = survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
	if err != nil {
		return "", fmt.Errorf(askRoleError, err)
	}

	roleARN = labelsARNs[selected]
	if roleARN == "" {
		return "", fmt.Errorf(noRolesError, idp)
	}

	return roleARN, nil
}

// promptForIDP prompt operator for the AWS IdP ARN given a slice of IdP ARNs.
// If the fedApp has already been selected via an ask one survey we don't need
// to pretty print out the IdP name again.
func (w *WebSSOAuthentication) promptForIDP(idpARNs []string) (idpARN string, err error) {
	oktaConfig, _ := w.config.OktaConfig()
	var configIDPs map[string]string
	if err == nil {
		configIDPs = oktaConfig.AWSCLI.IDPS
	}

	if len(idpARNs) == 0 {
		return idpARN, errors.New(noIDPsError)
	}

	if len(idpARNs) == 1 || w.config.AWSIAMIdP() != "" {
		idpARN = w.config.AWSIAMIdP()
		if len(idpARNs) == 1 {
			idpARN = idpARNs[0]
		}
		if w.fedAppAlreadySelected {
			return idpARN, nil
		}

		idpLabel := w.choiceFriendlyLabelIDP(idpARN, idpARN, configIDPs)
		idpData := idpTemplateData{
			IDP: idpLabel,
		}
		rich, _, err := core.RunTemplate(idpSelectedTemplate, idpData)
		if err != nil {
			return "", err
		}
		fmt.Fprintln(os.Stderr, rich)
		return idpARN, nil
	}

	idpChoices := make(map[string]string, len(idpARNs))
	idpChoiceLabels := make([]string, len(idpARNs))
	for i, arn := range idpARNs {
		idpLabel := w.choiceFriendlyLabelIDP(arn, arn, configIDPs)
		idpChoices[idpLabel] = arn
		idpChoiceLabels[i] = idpLabel
	}

	var idpChoice string
	prompt := &survey.Select{
		Message: chooseIDP,
		Options: idpChoiceLabels,
	}
	err = survey.AskOne(prompt, &idpChoice, survey.WithValidator(survey.Required), stderrIsOutAskOpt)
	if err != nil {
		return idpARN, fmt.Errorf(askIDPError, err)
	}
	idpARN = idpChoices[idpChoice]
	if idpARN == "" {
		return idpARN, errors.New(idpValueNotSelectedError)
	}

	return idpARN, nil
}

// promptForIdpAndRole UX to prompt operator for the AWS role whose credentials
// will be utilized.
func (w *WebSSOAuthentication) promptForIdpAndRole(idpRoles map[string][]string) (iar *idpAndRole, err error) {
	idps := make([]string, 0, len(idpRoles))
	for idp := range idpRoles {
		idps = append(idps, idp)
	}
	idp, err := w.promptForIDP(idps)
	if err != nil {
		return nil, err
	}

	roles := idpRoles[idp]
	role, err := w.promptForRole(idp, roles)
	if err != nil {
		return nil, err
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
func (w *WebSSOAuthentication) extractIDPAndRolesMapFromAssertion(encoded string) (irmap map[string][]string, err error) {
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
func (w *WebSSOAuthentication) fetchSAMLAssertion(at *okta.AccessToken) (assertion string, err error) {
	params := url.Values{"token": {at.AccessToken}}
	apiURL := fmt.Sprintf("https://%s/login/token/sso?%s", w.config.OrgDomain(), params.Encode())

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return assertion, err
	}
	req.Header.Add(accept, "text/html")
	req.Header.Add(utils.UserAgentHeader, config.UserAgentValue)
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)

	resp, err := w.config.HTTPClient().Do(req)
	if err != nil {
		return assertion, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching SAML assertion received API response %q", resp.Status)
	}
	doc, err := html.Parse(resp.Body)
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
func (w *WebSSOAuthentication) fetchSSOWebToken(clientID, awsFedAppID string, at *okta.AccessToken) (token *okta.AccessToken, err error) {
	apiURL := fmt.Sprintf(okta.OAuthV1TokenEndpointFormat, w.config.OrgDomain())

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
	req.Header.Add(accept, utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
	req.Header.Add(utils.UserAgentHeader, config.UserAgentValue)
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)

	resp, err := w.config.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		baseErrStr := "fetching SSO web token received API response %q"
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

	token = &okta.AccessToken{}
	err = json.NewDecoder(resp.Body).Decode(token)
	if err != nil {
		return nil, err
	}

	return
}

// promptAuthentication UX to display activation URL and code.
func (w *WebSSOAuthentication) promptAuthentication(da *okta.DeviceAuthorization) {
	var qrBuf []byte
	qrCode := ""

	if w.config.QRCode() {
		qrBuf = make([]byte, 4096)
		buf := bytes.NewBufferString("")
		qrterminal.GenerateHalfBlock(da.VerificationURIComplete, qrterminal.L, buf)
		if _, err := buf.Read(qrBuf); err == nil {
			qrCode = fmt.Sprintf(utils.PassThroughStringNewLineFMT, qrBuf)
		}
	}

	prompt := `%s the following URL to begin Okta device authorization for the AWS CLI

%s%s

`
	openMsg := "Open"
	if w.config.OpenBrowser() {
		openMsg = "Web browser will open"
	}

	w.consolePrint(prompt, openMsg, qrCode, da.VerificationURIComplete)

	if w.config.OpenBrowserCommand() != "" {
		bCmd := w.config.OpenBrowserCommand()
		if bCmd != "" {
			bArgs, err := splitArgs(bCmd)
			if err != nil {
				w.consolePrint("Browser command %q is invalid: %v\n", bCmd, err)
				return
			}
			bArgs = append(bArgs, da.VerificationURIComplete)
			cmd := osexec.Command(bArgs[0], bArgs[1:]...)
			out, err := cmd.Output()
			if _, ok := err.(*osexec.ExitError); ok {
				w.consolePrint("Failed to open activation URL with given browser: %v\n", err)
				w.consolePrint("  %s\n", strings.Join(bArgs, " "))
			}
			if len(out) > 0 {
				w.consolePrint("browser output:\n%s\n", string(out))
			}
		}

	} else if w.config.OpenBrowser() {
		brwsr.Stdout = os.Stderr
		if err := brwsr.OpenURL(da.VerificationURIComplete); err != nil {
			w.consolePrint("Failed to open activation URL with system browser: %v\n", err)
		}
	}
}

// ListFedApp Lists Okta AWS Fed Apps that are active. Errors after that occur
// after getting anything other than a 403 on /api/v1/apps will be wrapped as as
// an error that is related having multiple fed apps available.  Requires
// assoicated OIDC app has been granted okta.apps.read to its scope.
func (w *WebSSOAuthentication) listFedApps(clientID string, at *okta.AccessToken) (apps []*okta.Application, err error) {
	apiURL, err := url.Parse(fmt.Sprintf("https://%s/api/v1/apps", w.config.OrgDomain()))
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Add("limit", "200")
	params.Add("q", amazonAWS)
	params.Add("filter", `status eq "ACTIVE"`)
	apiURL.RawQuery = params.Encode()
	req, err := http.NewRequest(http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add(accept, utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationJSON)
	req.Header.Add(utils.UserAgentHeader, config.UserAgentValue)
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", at.TokenType, at.AccessToken))
	resp, err := w.config.HTTPClient().Do(req)
	if resp.StatusCode == http.StatusForbidden {
		return nil, err
	}

	// Any errors after this point should be considered related to when the OIDC
	// app can read multiple fed apps
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, newMultipleFedAppsError(err)
	}

	var oktaApps []okta.Application
	err = json.NewDecoder(resp.Body).Decode(&oktaApps)
	if err != nil {
		return nil, newMultipleFedAppsError(err)
	}

	apps = make([]*okta.Application, 0)
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

// accessToken see:
// https://developer.okta.com/docs/reference/api/oidc/#token
func (w *WebSSOAuthentication) accessToken(deviceAuth *okta.DeviceAuthorization) (at *okta.AccessToken, err error) {
	clientID := w.config.OIDCAppID()
	apiURL := fmt.Sprintf(okta.OAuthV1TokenEndpointFormat, w.config.OrgDomain())

	req, err := http.NewRequest(http.MethodPost, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(accept, utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
	req.Header.Add(utils.UserAgentHeader, config.UserAgentValue)
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)

	var bodyBytes []byte

	// Keep polling if Status Code is 400 and apiError.Error ==
	// "authorization_pending". Done if status code is 200. Else error.
	poll := func() error {
		data := url.Values{
			"client_id":   {clientID},
			"device_code": {deviceAuth.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}
		body := strings.NewReader(data.Encode())
		req.Body = io.NopCloser(body)

		resp, err := w.config.HTTPClient().Do(req)
		bodyBytes, _ = io.ReadAll(resp.Body)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("fetching access token polling received API err %w", err))
		}
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

	at = &okta.AccessToken{}
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(at)
	if err != nil {
		return nil, err
	}

	return
}

// authorize see:
// https://developer.okta.com/docs/reference/api/oidc/#device-authorize
func (w *WebSSOAuthentication) authorize() (*okta.DeviceAuthorization, error) {
	clientID := w.config.OIDCAppID()
	apiURL := fmt.Sprintf("https://%s/oauth2/v1/device/authorize", w.config.OrgDomain())
	data := url.Values{
		"client_id": {clientID},
		"scope":     {"openid okta.apps.sso okta.apps.read"},
	}
	body := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, apiURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(accept, utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
	req.Header.Add(utils.UserAgentHeader, config.UserAgentValue)
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)

	resp, err := w.config.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorize received API response %q", resp.Status)
	}

	ct := resp.Header.Get(utils.ContentType)
	if !strings.Contains(ct, utils.ApplicationJSON) {
		return nil, fmt.Errorf("authorize non-JSON API response content type %q", ct)
	}

	var da okta.DeviceAuthorization
	err = json.NewDecoder(resp.Body).Decode(&da)
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

func apiErr(bodyBytes []byte) (ae *okta.APIError, err error) {
	ae = &okta.APIError{}
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(ae)
	return
}

// isClassicOrg Conduct simple check of well known endpoint to determine if the
// org is a classic org. Will soft fail on errors.
func (w *WebSSOAuthentication) isClassicOrg() bool {
	apiURL := fmt.Sprintf("https://%s/.well-known/okta-organization", w.config.OrgDomain())
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return false
	}
	req.Header.Add(accept, utils.ApplicationJSON)
	req.Header.Add(utils.UserAgentHeader, config.UserAgentValue)
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)

	resp, err := w.config.HTTPClient().Do(req)
	if err != nil {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	org := &okta.Organization{}
	err = json.NewDecoder(resp.Body).Decode(org)
	if err != nil {
		return false
	}

	// v1 == Classic, idx == OIE
	if org.Pipeline == "v1" {
		return true
	}

	return false
}

// cachedAccessToken will returned the cached access token if it exists and is
// not expired.
func (w *WebSSOAuthentication) cachedAccessToken() (at *okta.AccessToken) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	configPath := filepath.Join(homeDir, dotOktaDir, tokenFileName)
	atJSON, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	_at := okta.AccessToken{}
	err = json.Unmarshal(atJSON, &_at)
	if err != nil {
		return
	}

	expiry, err := time.Parse(time.RFC3339, _at.Expiry)
	if err != nil {
		return
	}
	if expiry.Before(time.Now()) {
		// expiry is in the past
		return
	}

	return &_at
}

// cacheAccessToken will cache the access token for later use if enabled. Silent
// if fails.
func (w *WebSSOAuthentication) cacheAccessToken(at *okta.AccessToken) {
	if !w.config.CacheAccessToken() {
		return
	}

	cUser, err := user.Current()
	if err != nil {
		return
	}
	if cUser.HomeDir == "" {
		return
	}

	oktaDir := filepath.Join(cUser.HomeDir, dotOktaDir)
	// noop if dir exists
	err = os.MkdirAll(oktaDir, 0o700)
	if err != nil {
		return
	}

	atJSON, err := json.Marshal(at)
	if err != nil {
		return
	}

	configPath := filepath.Join(cUser.HomeDir, dotOktaDir, tokenFileName)
	_ = os.WriteFile(configPath, atJSON, 0o600)
}

func (w *WebSSOAuthentication) consolePrint(format string, a ...any) {
	if w.config.IsProcessCredentialsFormat() {
		return
	}

	fmt.Fprintf(os.Stderr, format, a...)
}

// fetchAllAWSCredentialsWithSAMLRole Gets all AWS Credentials with an STS Assume Role with SAML AWS API call.
func (w *WebSSOAuthentication) fetchAllAWSCredentialsWithSAMLRole(idpRolesMap map[string][]string, assertion string) <-chan *oaws.CredentialContainer {
	ccch := make(chan *oaws.CredentialContainer)
	var wg sync.WaitGroup

	for idp, roles := range idpRolesMap {
		for _, role := range roles {
			iar := &idpAndRole{idp, role}
			wg.Add(1)
			go func() {
				defer wg.Done()
				cc, err := w.awsAssumeRoleWithSAML(iar, assertion)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to fetch AWS creds IdP %q, and Role %q, error:\n%+v\n", iar.idp, iar.role, err)
					return
				}
				ccch <- cc
			}()
		}
	}

	go func() {
		wg.Wait()
		close(ccch)
	}()

	return ccch
}

func (w *WebSSOAuthentication) fetchAWSAccountAlias(sess *session.Session) (string, error) {
	svc := iam.New(sess)
	input := &iam.ListAccountAliasesInput{}
	svcResp, err := svc.ListAccountAliases(input)
	if err != nil {
		return "", err
	}
	if len(svcResp.AccountAliases) < 1 {
		return "", fmt.Errorf("no alias configured for account")
	}
	return *svcResp.AccountAliases[0], nil
}

func splitArgs(args string) ([]string, error) {
	return shlex.Split(args)
}
