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
	// Version The version of the CLI
	Version      = "0.0.4"
	awsCrentials = "aws_credentials"
)

// Config A config object for the CLI
type Config struct {
	OrgDomain          string
	OIDCAppID          string
	FedAppID           string
	AWSIAMIdP          string
	AWSIAMRole         string
	AWSSessionDuration int64
	Format             string
	Profile            string
	QRCode             bool
	AWSCredentials     string
	OpenBrowser        bool
	HTTPClient         *http.Client
}

// NewConfig Creates a new config gathering values in this order of precedence:
//  1. CLI flags
//  2. ENV variables
//  3. .env file
func NewConfig() *Config {
	cfg := Config{
		OrgDomain:          viper.GetString("org-domain"),
		OIDCAppID:          viper.GetString("oidc-client-id"),
		FedAppID:           viper.GetString("aws-acct-fed-app-id"),
		AWSIAMIdP:          viper.GetString("aws-iam-idp"),
		AWSIAMRole:         viper.GetString("aws-iam-role"),
		AWSSessionDuration: viper.GetInt64("session-duration"),
		Format:             viper.GetString("format"),
		Profile:            viper.GetString("profile"),
		QRCode:             viper.GetBool("qr-code"),
		OpenBrowser:        viper.GetBool("open-browser"),
		AWSCredentials:     viper.GetString("aws-credentials"),
	}
	if cfg.Format == "" {
		cfg.Format = "env-var"
	}
	if cfg.Profile == "" {
		cfg.Profile = "default"
	}

	// Viper binds ENV VARs to a lower snake version, set the configs with them
	// if they haven't already been set by cli flag binding.
	if cfg.OrgDomain == "" {
		cfg.OrgDomain = viper.GetString("okta_org_domain")
	}
	if cfg.OIDCAppID == "" {
		cfg.OIDCAppID = viper.GetString("okta_oidc_client_id")
	}
	if cfg.FedAppID == "" {
		cfg.FedAppID = viper.GetString("okta_aws_account_federation_app_id")
	}
	if cfg.AWSIAMIdP == "" {
		cfg.AWSIAMIdP = viper.GetString("aws_iam_idp")
	}
	if cfg.AWSIAMRole == "" {
		cfg.AWSIAMRole = viper.GetString("aws_iam_role")
	}
	if cfg.AWSSessionDuration == 0 {
		cfg.AWSSessionDuration = viper.GetInt64("session_duration")
	}
	if !cfg.QRCode {
		cfg.QRCode = viper.GetBool("qr_code")
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
	if viper.GetString(awsCrentials) != "" {
		cfg.AWSCredentials = viper.GetString(awsCrentials)
	}

	tr := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
	}
	httpClient := &http.Client{
		Transport: tr,
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
