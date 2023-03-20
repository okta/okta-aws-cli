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

package config

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// Version app version
	Version = "0.3.0"

	// AWSCredentialsFormat format const
	AWSCredentialsFormat = "aws-credentials"
	// EnvVarFormat format const
	EnvVarFormat = "env-var"

	// AWSAcctFedAppIDFlag cli flag const
	AWSAcctFedAppIDFlag = "aws-acct-fed-app-id"
	// AWSCredentialsFlag cli flag const
	AWSCredentialsFlag = "aws-credentials"
	// AWSIAMIdPFlag cli flag const
	AWSIAMIdPFlag = "aws-iam-idp"
	// AWSIAMRoleFlag cli flag const
	AWSIAMRoleFlag = "aws-iam-role"
	// DebugAPICallsFlag cli flag const
	DebugAPICallsFlag = "debug-api-calls"
	// FormatFlag cli flag const
	FormatFlag = "format"
	// OIDCClientIDFlag cli flag const
	OIDCClientIDFlag = "oidc-client-id"
	// OpenBrowserFlag cli flag const
	OpenBrowserFlag = "open-browser"
	// OrgDomainFlag cli flag const
	OrgDomainFlag = "org-domain"
	// ProfileFlag cli flag const
	ProfileFlag = "profile"
	// QRCodeFlag cli flag const
	QRCodeFlag = "qr-code"
	// SessionDurationFlag cli flag const
	SessionDurationFlag = "session-duration"
	// WriteAWSCredentialsFlag cli flag const
	WriteAWSCredentialsFlag = "write-aws-credentials"
	// LegacyAWSVariablesFlag cli flag const
	LegacyAWSVariablesFlag = "legacy-aws-variables"

	// AWSCredentialsEnvVar env var const
	AWSCredentialsEnvVar = "AWS_CREDENTIALS"
	// AWSIAMIdPEnvVar env var const
	AWSIAMIdPEnvVar = "AWS_IAM_IDP"
	// AWSIAMRoleEnvVar env var const
	AWSIAMRoleEnvVar = "AWS_IAM_ROLE"
	// AWSSessionDurationEnvVar env var const
	AWSSessionDurationEnvVar = "AWS_SESSION_DURATION"
	// FormatEnvVar env var const
	FormatEnvVar = "FORMAT"
	// OktaOIDCClientIDEnvVar env var const
	OktaOIDCClientIDEnvVar = "OKTA_OIDC_CLIENT_ID"
	// OktaOrgDomainEnvVar env var const
	OktaOrgDomainEnvVar = "OKTA_ORG_DOMAIN"
	// OktaAWSAccountFederationAppIDEnvVar env var const
	OktaAWSAccountFederationAppIDEnvVar = "OKTA_AWS_ACCOUNT_FEDERATION_APP_ID"
	// OpenBrowserEnvVar env var const
	OpenBrowserEnvVar = "OPEN_BROWSER"
	// ProfileEnvVar env var const
	ProfileEnvVar = "PROFILE"
	// QRCodeEnvVar env var const
	QRCodeEnvVar = "QR_CODE"
	// WriteAWSCredentialsEnvVar env var const
	WriteAWSCredentialsEnvVar = "WRITE_AWS_CREDENTIALS"
	// DebugAPICallsEnvVar env var const
	DebugAPICallsEnvVar = "DEBUG_API_CALLS"
	// LegacyAWSVariablesEnvVar env var const
	LegacyAWSVariablesEnvVar = "LEGACY_AWS_VARIABLES"
)

// Config A config object for the CLI
type Config struct {
	orgDomain           string
	oidcAppID           string
	fedAppID            string
	awsIAMIdP           string
	awsIAMRole          string
	awsSessionDuration  int64
	format              string
	profile             string
	qrCode              bool
	awsCredentials      string
	writeAWSCredentials bool
	openBrowser         bool
	debugAPICalls       bool
	legacyAWSVariables  bool
	httpClient          *http.Client
}

type ConfigAttributes struct {
	OrgDomain           string
	OIDCAppID           string
	FedAppID            string
	AWSIAMIdP           string
	AWSIAMRole          string
	AWSSessionDuration  int64
	Format              string
	Profile             string
	QRCode              bool
	AWSCredentials      string
	WriteAWSCredentials bool
	OpenBrowser         bool
	DebugAPICalls       bool
	LegacyAWSVariables  bool
}

// NewConfig Creates a new config gathering values in this order of precedence:
//  1. CLI flags
//  2. ENV variables
//  3. .env file
func CreateConfig() (*Config, error) {
	cfgAttrs, err := readConfig()
	if err != nil {
		return nil, err
	}
	return NewConfig(cfgAttrs)
}

func NewConfig(attrs ConfigAttributes) (*Config, error) {
	var err error
	cfg := &Config{
		fedAppID:            attrs.FedAppID,
		awsIAMIdP:           attrs.AWSIAMIdP,
		awsIAMRole:          attrs.AWSIAMRole,
		format:              attrs.Format,
		profile:             attrs.Profile,
		qrCode:              attrs.QRCode,
		awsCredentials:      attrs.AWSCredentials,
		writeAWSCredentials: attrs.WriteAWSCredentials,
		openBrowser:         attrs.OpenBrowser,
		debugAPICalls:       attrs.DebugAPICalls,
		legacyAWSVariables:  attrs.LegacyAWSVariables,
	}
	err = cfg.SetOrgDomain(attrs.OrgDomain)
	if err != nil {
		return nil, err
	}
	err = cfg.SetOIDCAppID(attrs.OIDCAppID)
	if err != nil {
		return nil, err
	}
	err = cfg.SetAWSSessionDuration(attrs.AWSSessionDuration)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: newConfigTransport(cfg.DebugAPICalls()),
		Timeout:   time.Second * time.Duration(60),
	}
	err = cfg.SetHTTPClient(client)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func readConfig() (ConfigAttributes, error) {
	attrs := ConfigAttributes{
		AWSCredentials:      viper.GetString(AWSCredentialsFlag),
		AWSIAMIdP:           viper.GetString(AWSIAMIdPFlag),
		AWSIAMRole:          viper.GetString(AWSIAMRoleFlag),
		AWSSessionDuration:  viper.GetInt64(SessionDurationFlag),
		DebugAPICalls:       viper.GetBool(DebugAPICallsFlag),
		FedAppID:            viper.GetString(AWSAcctFedAppIDFlag),
		Format:              viper.GetString(FormatFlag),
		LegacyAWSVariables:  viper.GetBool(LegacyAWSVariablesFlag),
		OIDCAppID:           viper.GetString(OIDCClientIDFlag),
		OpenBrowser:         viper.GetBool(OpenBrowserFlag),
		OrgDomain:           viper.GetString(OrgDomainFlag),
		Profile:             viper.GetString(ProfileFlag),
		QRCode:              viper.GetBool(QRCodeFlag),
		WriteAWSCredentials: viper.GetBool(WriteAWSCredentialsFlag),
	}
	if attrs.Format == "" {
		attrs.Format = EnvVarFormat
	}
	if attrs.Profile == "" {
		attrs.Profile = "default"
	}

	// Viper binds ENV VARs to a lower snake version, set the configs with them
	// if they haven't already been set by cli flag binding.
	if attrs.OrgDomain == "" {
		attrs.OrgDomain = viper.GetString(downCase(OktaOrgDomainEnvVar))
	}
	if attrs.OIDCAppID == "" {
		attrs.OIDCAppID = viper.GetString(downCase(OktaOIDCClientIDEnvVar))
	}
	if attrs.FedAppID == "" {
		attrs.FedAppID = viper.GetString(downCase(OktaAWSAccountFederationAppIDEnvVar))
	}
	if attrs.AWSIAMIdP == "" {
		attrs.AWSIAMIdP = viper.GetString(downCase(AWSIAMIdPEnvVar))
	}
	if attrs.AWSIAMRole == "" {
		attrs.AWSIAMRole = viper.GetString(downCase(AWSIAMRoleEnvVar))
	}
	// duration has a default of 3600 from CLI flags, but if the env var version
	// is not 0 then prefer it
	duration := viper.GetInt64(downCase(AWSSessionDurationEnvVar))
	if duration != 0 {
		attrs.AWSSessionDuration = duration
	}
	if !attrs.QRCode {
		attrs.QRCode = viper.GetBool(downCase(QRCodeEnvVar))
	}

	// correct org domain if it's in admin form
	orgDomain := strings.Replace(attrs.OrgDomain, "-admin", "", -1)
	if orgDomain != attrs.OrgDomain {
		fmt.Printf("WARNING: proactively correcting org domain %q to non-admin form %q.\n\n", attrs.OrgDomain, orgDomain)
		attrs.OrgDomain = orgDomain
	}
	if strings.HasPrefix(attrs.OrgDomain, "http") {
		u, err := url.Parse(attrs.OrgDomain)
		// try to help correct org domain value if parsing occurs correctly,
		// else let the CLI error out else where
		if err == nil {
			orgDomain = u.Hostname()
			fmt.Printf("WARNING: proactively correcting URL format org domain %q value to hostname only form %q.\n\n", attrs.OrgDomain, orgDomain)
			attrs.OrgDomain = orgDomain
		}
	}
	if strings.HasSuffix(attrs.OrgDomain, "/") {
		orgDomain = string([]byte(attrs.OrgDomain)[0 : len(attrs.OrgDomain)-1])
		// try to help correct malformed org domain value
		fmt.Printf("WARNING: proactively correcting malformed org domain %q value to hostname only form %q.\n\n", attrs.OrgDomain, orgDomain)
		attrs.OrgDomain = orgDomain
	}

	// There is always a default aws credentials path set in root.go's init
	// function so overwrite the config value if the operator is attempting to
	// set it by ENV VAR value.
	if viper.GetString(downCase(AWSCredentialsEnvVar)) != "" {
		attrs.AWSCredentials = viper.GetString(downCase(AWSCredentialsEnvVar))
	}
	if !attrs.WriteAWSCredentials {
		attrs.WriteAWSCredentials = viper.GetBool(downCase(WriteAWSCredentialsEnvVar))
	}
	// TODU
	if attrs.WriteAWSCredentials {
		// writing aws creds option implies "aws-credentials" format
		attrs.Format = AWSCredentialsFormat
	}
	if !attrs.OpenBrowser {
		attrs.OpenBrowser = viper.GetBool(downCase(OpenBrowserEnvVar))
	}
	if !attrs.DebugAPICalls {
		attrs.DebugAPICalls = viper.GetBool(downCase(DebugAPICallsEnvVar))
	}
	if !attrs.LegacyAWSVariables {
		attrs.LegacyAWSVariables = viper.GetBool(downCase(LegacyAWSVariablesEnvVar))
	}
	return attrs, nil
}

// downCase ToLower all alpha chars e.g. HELLO_WORLD -> hello_world
func downCase(s string) string {
	return strings.ToLower(s)
}

func (c *Config) OrgDomain() string {
	return c.orgDomain
}

func (c *Config) SetOrgDomain(domain string) error {
	if domain == "" {
		return NewValidationError("Org Domain", "cannot be blank")
	}
	if !(strings.Contains(domain, "okta.com") || strings.Contains(domain, "oktapreview.com")) {
		return NewValidationError("Org Domain", "is not from Okta")
	}
	c.orgDomain = domain
	return nil
}

func (c *Config) OIDCAppID() string {
	return c.oidcAppID
}

func (c *Config) SetOIDCAppID(appID string) error {
	if appID == "" {
		return NewValidationError("OIDC App ID", "cannot be blank")
	}
	c.oidcAppID = appID
	return nil
}

func (c *Config) FedAppID() string {
	return c.fedAppID
}

func (c *Config) SetFedAppID(appID string) error {
	c.fedAppID = appID
	return nil
}

func (c *Config) AWSIAMIdP() string {
	return c.awsIAMIdP
}

func (c *Config) SetAWSIAMIdP(idp string) error {
	c.awsIAMIdP = idp
	return nil
}

func (c *Config) AWSIAMRole() string {
	return c.awsIAMRole
}

func (c *Config) SetAWSIAMRole(role string) error {
	c.awsIAMRole = role
	return nil
}

func (c *Config) AWSSessionDuration() int64 {
	return c.awsSessionDuration
}

func (c *Config) SetAWSSessionDuration(duration int64) error {
	if duration < 60 || duration > 43200 {
		return NewValidationError("AWS Session Duration", "must be between 60 and 43200")
	}
	c.awsSessionDuration = duration
	return nil
}

func (c *Config) Format() string {
	return c.format
}

func (c *Config) SetFormat(format string) error {
	c.format = format
	return nil
}

func (c *Config) Profile() string {
	return c.profile
}

func (c *Config) SetProfile(profile string) error {
	c.profile = profile
	return nil
}

func (c *Config) QRCode() bool {
	return c.qrCode
}

func (c *Config) SetQRCode(qrCode bool) error {
	c.qrCode = qrCode
	return nil
}

func (c *Config) AWSCredentials() string {
	return c.awsCredentials
}

func (c *Config) SetAWSCredentials(credentials string) error {
	c.awsCredentials = credentials
	return nil
}

func (c *Config) WriteAWSCredentials() bool {
	return c.writeAWSCredentials
}

func (c *Config) SetWriteAWSCredentials(writeCredentials bool) error {
	c.writeAWSCredentials = writeCredentials
	return nil
}

func (c *Config) OpenBrowser() bool {
	return c.openBrowser
}

func (c *Config) SetOpenBrowser(openBrowser bool) error {
	c.openBrowser = openBrowser
	return nil
}

func (c *Config) DebugAPICalls() bool {
	return c.debugAPICalls
}

func (c *Config) SetDebugAPICalls(debugAPICalls bool) error {
	c.debugAPICalls = debugAPICalls
	return nil
}

func (c *Config) LegacyAWSVariables() bool {
	return c.legacyAWSVariables
}

func (c *Config) SetLegacyAWSVariables(legacyAWSVariables bool) error {
	c.legacyAWSVariables = legacyAWSVariables
	return nil
}

func (c *Config) HTTPClient() *http.Client {
	return c.httpClient
}

func (c *Config) SetHTTPClient(client *http.Client) error {
	c.httpClient = client
	return nil
}
