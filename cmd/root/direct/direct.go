/*
 * Copyright (c) 2026-Present, Okta, Inc.
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

package direct

import (
	"github.com/spf13/cobra"

	"github.com/okta/okta-aws-cli/v2/internal/config"
	"github.com/okta/okta-aws-cli/v2/internal/directauth"
	cliFlag "github.com/okta/okta-aws-cli/v2/internal/flag"
)

var (
	flags = []cliFlag.Flag{
		{
			Name:   config.UsernameFlag,
			Short:  "a",
			Value:  "",
			Usage:  "Username",
			EnvVar: config.UsernameEnvVar,
		},
		{
			Name:   config.PasswordFlag,
			Short:  "b",
			Value:  "",
			Usage:  "Password",
			EnvVar: config.PasswordEnvVar,
		},
		{
			Name:   config.AuthzIDFlag,
			Short:  "u",
			Value:  "",
			Usage:  "Custom Authorization Server ID",
			EnvVar: config.AuthzIDEnvVar,
		},
		{
			Name:   config.AWSSTSRoleSessionNameFlag,
			Short:  "q",
			Value:  "okta-aws-cli",
			Usage:  "STS Role Session Name",
			EnvVar: config.AWSSTSRoleSessionNameEnvVar,
		},
	}
	requiredFlags = []interface{}{"org-domain", "oidc-client-id", "aws-iam-role", []string{"username", "password"}}
)

// NewDirectCommand Sets up the direct cobra sub command
func NewDirectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "direct",
		Short: "Direct authorization with multifactor out-of-band flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := config.NewEvaluatedConfig()
			if err != nil {
				return err
			}

			err = cliFlag.CheckRequiredFlags(requiredFlags)
			if err != nil {
				return err
			}

			da, err := directauth.NewDirectAuthentication(config)
			if err != nil {
				return err
			}
			return da.EstablishIAMCredentials()
		},
	}

	cliFlag.MakeFlagBindings(cmd, flags, false)

	return cmd
}
