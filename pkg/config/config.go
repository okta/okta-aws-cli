/**
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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joeshaw/envdecode"
	"github.com/joho/godotenv"

	"github.com/spf13/cobra"
)

// Version The version of the CLI
var Version = "0.0.2"

// Config A config object for the CLI
type Config struct {
	OrgDomain  string `env:"OKTA_ORG_DOMAIN"`
	OIDCAppID  string `env:"OKTA_OIDC_CLIENT_ID"`
	FedAppID   string `env:"OKTA_AWS_ACCOUNT_FEDERATION_APP_ID"`
	AWSIAMIdP  string `env:"AWS_IAM_IDP"`
	AWSIAMRole string `env:"AWS_IAM_ROLE"`
	Format     string `env:"FORMAT,default=env-var"`
	Profile    string `env:"PROFILE,default=default"`
	QRCode     bool   `env:"QR_CODE"`
	HTTPClient *http.Client
}

// NewConfig Creates a new config gathering values in this order:
//  1. .env file
//  2. ENV variables
//
// Consumers of the config, like the root command, may then overwrite values
// given CLI args and flags.
func NewConfig(envFiles ...string) (*Config, error) {
	err := godotenv.Load(envFiles...)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	var cfg Config
	err = envdecode.Decode(&cfg)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Second * time.Duration(60),
	}
	cfg.HTTPClient = httpClient

	return &cfg, nil
}

// OverrideIfSet Override the corresponding config value if it is set a CLI flag
func (c *Config) OverrideIfSet(cmd *cobra.Command, name string) {
	flag := cmd.Flag(name)
	if flag.Value == nil || flag.Value.String() == "" {
		return
	}

	val := flag.Value.String()
	switch name {
	case "org-domain":
		c.OrgDomain = val
	case "oidc-client-id":
		c.OIDCAppID = val
	case "aws-acct-fed-app-id":
		c.FedAppID = val
	case "format":
		c.Format = val
	case "aws-iam-idp":
		c.AWSIAMIdP = val
	case "aws-iam-role":
		c.AWSIAMRole = val
	case "qr-code":
		c.QRCode = (val == "true")
	case "profile":
		c.Profile = val
	}
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
