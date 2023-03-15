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
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// Version app version
	Version = "0.2.1"

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
	HTTPClient          *http.Client
}

// NewConfig Creates a new config gathering values in this order of precedence:
//  1. CLI flags
//  2. ENV variables
//  3. .env file
func NewConfig() *Config {
	cfg := Config{
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
	if cfg.Format == "" {
		cfg.Format = EnvVarFormat
	}
	if cfg.Profile == "" {
		cfg.Profile = "default"
	}

	// Viper binds ENV VARs to a lower snake version, set the configs with them
	// if they haven't already been set by cli flag binding.
	if cfg.OrgDomain == "" {
		cfg.OrgDomain = viper.GetString(downCase(OktaOrgDomainEnvVar))
	}
	if cfg.OIDCAppID == "" {
		cfg.OIDCAppID = viper.GetString(downCase(OktaOIDCClientIDEnvVar))
	}
	if cfg.FedAppID == "" {
		cfg.FedAppID = viper.GetString(downCase(OktaAWSAccountFederationAppIDEnvVar))
	}
	if cfg.AWSIAMIdP == "" {
		cfg.AWSIAMIdP = viper.GetString(downCase(AWSIAMIdPEnvVar))
	}
	if cfg.AWSIAMRole == "" {
		cfg.AWSIAMRole = viper.GetString(downCase(AWSIAMRoleEnvVar))
	}
	// duration has a default of 3600 from CLI flags, but if the env var version
	// is not 0 then prefer it
	duration := viper.GetInt64(downCase(AWSSessionDurationEnvVar))
	if duration != 0 {
		cfg.AWSSessionDuration = duration
	}
	if !cfg.QRCode {
		cfg.QRCode = viper.GetBool(downCase(QRCodeEnvVar))
	}
	// correct org domain if it's in admin form
	orgDomain := strings.Replace(cfg.OrgDomain, "-admin", "", -1)
	if orgDomain != cfg.OrgDomain {
		fmt.Printf("Warning: proactively correcting org domain %q to non-admin form %q.\n\n", cfg.OrgDomain, orgDomain)
		cfg.OrgDomain = orgDomain
	}

	// There is always a default aws credentials path set in root.go's init
	// function so overwrite the config value if the operator is attempting to
	// set it by ENV VAR value.
	if viper.GetString(downCase(AWSCredentialsEnvVar)) != "" {
		cfg.AWSCredentials = viper.GetString(downCase(AWSCredentialsEnvVar))
	}
	if !cfg.WriteAWSCredentials {
		cfg.WriteAWSCredentials = viper.GetBool(downCase(WriteAWSCredentialsEnvVar))
	}
	if cfg.WriteAWSCredentials {
		// writing aws creds option implies "aws-credentials" format
		cfg.Format = AWSCredentialsFormat
	}
	if !cfg.OpenBrowser {
		cfg.OpenBrowser = viper.GetBool(downCase(OpenBrowserEnvVar))
	}
	if !cfg.DebugAPICalls {
		cfg.DebugAPICalls = viper.GetBool(downCase(DebugAPICallsEnvVar))
	}
	if !cfg.LegacyAWSVariables {
		cfg.LegacyAWSVariables = viper.GetBool(downCase(LegacyAWSVariablesEnvVar))
	}
	httpClient := &http.Client{
		Transport: newConfigTransport(cfg.DebugAPICalls),
		Timeout:   time.Second * time.Duration(60),
	}
	cfg.HTTPClient = httpClient

	return &cfg
}

// CheckConfig Checks that required configuration variables are set.
func (c *Config) CheckConfig() error {
	var errors []string
	if c.OrgDomain == "" {
		errors = append(errors, "  Okta Org Domain value is not set")
	}
	if c.OIDCAppID == "" {
		errors = append(errors, "  OIDC App ID value is not set")
	}
	if c.AWSSessionDuration < 60 || c.AWSSessionDuration > 43200 {
		errors = append(errors, "  AWS Session Duration must be between 60 and 43200")
	}
	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "\n"))
	}

	return nil
}

// downCase ToLower all alpha chars e.g. HELLO_WORLD -> hello_world
func downCase(s string) string {
	return strings.ToLower(s)
}
