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

// Version The version of the CLI
var Version = "0.0.2"

// Config A config object for the CLI
type Config struct {
	OrgDomain      string
	OIDCAppID      string
	FedAppID       string
	AWSIAMIdP      string
	AWSIAMRole     string
	Format         string
	Profile        string
	QRCode         bool
	AWSCredentials string
	HTTPClient     *http.Client
}

// NewConfig Creates a new config gathering values in this order of precedence:
//  1. CLI flags
//  2. ENV variables
//  3. .env file
func NewConfig() *Config {
	cfg := Config{
		OrgDomain:      viper.GetString("org-domain"),
		OIDCAppID:      viper.GetString("oidc-client-id"),
		FedAppID:       viper.GetString("aws-acct-fed-app-id"),
		AWSIAMIdP:      viper.GetString("aws-iam-idp"),
		AWSIAMRole:     viper.GetString("aws-iam-role"),
		Format:         viper.GetString("format"),
		Profile:        viper.GetString("profile"),
		QRCode:         viper.GetBool("qr-code"),
		AWSCredentials: viper.GetString("aws-credentials"),
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
	if !cfg.QRCode {
		cfg.QRCode = viper.GetBool("qr_code")
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
	if c.FedAppID == "" {
		errors = append(errors, "  AWS Account Federation App ID value is not set")
	}
	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "\n"))
	}

	return nil
}
