/*
 * Copyright (c) 2023-Present, Okta, Inc.
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

package web

import (
	"github.com/spf13/cobra"

	"github.com/okta/okta-aws-cli/internal/config"
	cliFlag "github.com/okta/okta-aws-cli/internal/flag"
	"github.com/okta/okta-aws-cli/internal/webssoauth"
)

var (
	flags = []cliFlag.Flag{
		{
			Name:   config.AWSAcctFedAppIDFlag,
			Short:  "a",
			Value:  "",
			Usage:  "AWS Account Federation app ID",
			EnvVar: config.OktaAWSAccountFederationAppIDEnvVar,
		},
		{
			Name:   config.AWSIAMIdPFlag,
			Short:  "i",
			Value:  "",
			Usage:  "Preset IAM Identity Provider ARN",
			EnvVar: config.AWSIAMIdPEnvVar,
		},
		{
			Name:   config.QRCodeFlag,
			Short:  "q",
			Value:  false,
			Usage:  "Print QR Code of activation URL",
			EnvVar: config.QRCodeEnvVar,
		},
		{
			Name:   config.OpenBrowserFlag,
			Short:  "b",
			Value:  false,
			Usage:  "Automatically open the activation URL with the system web browser",
			EnvVar: config.OpenBrowserEnvVar,
		},
		{
			Name:   config.OpenBrowserCommandFlag,
			Short:  "m",
			Value:  "",
			Usage:  "Automatically open the activation URL with the given web browser command",
			EnvVar: config.OpenBrowserCommandEnvVar,
		},
		{
			Name:   config.AllProfilesFlag,
			Short:  "k",
			Value:  false,
			Usage:  "Collect all profiles for a given IdP (implies aws-credentials file output format)",
			EnvVar: config.AllProfilesEnvVar,
		},
	}
	requiredFlags = []string{"org-domain", "oidc-client-id"}
)

// NewWebCommand Sets up the web cobra sub command
func NewWebCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Human oriented authentication and device authorization",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := config.EvaluateSettings()
			if err != nil {
				return err
			}
			err = cliFlag.CheckRequiredFlags(requiredFlags)
			if err != nil {
				return err
			}

			wsa, err := webssoauth.NewWebSSOAuthentication(config)
			if err != nil {
				return err
			}
			return wsa.EstablishIAMCredentials()
		},
	}

	cliFlag.MakeFlagBindings(cmd, flags, false)

	return cmd
}
