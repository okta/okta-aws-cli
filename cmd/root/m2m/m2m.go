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

package m2m

import (
	"github.com/spf13/cobra"

	"github.com/okta/okta-aws-cli/internal/config"
	cliFlag "github.com/okta/okta-aws-cli/internal/flag"
	"github.com/okta/okta-aws-cli/internal/m2mauth"
)

var (
	flags = []cliFlag.Flag{
		{
			Name:   config.KeyIDFlag,
			Short:  "i",
			Value:  "",
			Usage:  "Key ID",
			EnvVar: config.KeyIDEnvVar,
		},
		{
			Name:   config.PrivateKeyFlag,
			Short:  "k",
			Value:  "",
			Usage:  "Private Key",
			EnvVar: config.PrivateKeyEnvVar,
		},
		{
			Name:   config.CustomScopeFlag,
			Short:  "m",
			Value:  "okta-aws-cli",
			Usage:  "Custom Scope",
			EnvVar: config.CustomScopeEnvVar,
		},
		{
			Name:   config.AuthzIDFlag,
			Short:  "u",
			Value:  "",
			Usage:  "Custom Authorization Server ID",
			EnvVar: config.AuthzIDEnvVar,
		},
	}
	requiredFlags = []string{"org-domain", "oidc-client-id", "aws-iam-role", "key-id", "private-key", "authz-id"}
)

// NewM2MCommand Sets up the m2m cobra sub command
func NewM2MCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "m2m",
		Short: "Machine to machine / headless authorization",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := config.EvaluateSettings()
			if err != nil {
				return err
			}

			err = cliFlag.CheckRequiredFlags(requiredFlags)
			if err != nil {
				return err
			}

			m2ma, err := m2mauth.NewM2MAuthentication(config)
			if err != nil {
				return err
			}
			return m2ma.EstablishIAMCredentials()
		},
	}

	cliFlag.MakeFlagBindings(cmd, flags, false)

	return cmd
}
