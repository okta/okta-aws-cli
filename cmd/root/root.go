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

package root

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/okta/okta-aws-cli/pkg/config"
	"github.com/okta/okta-aws-cli/pkg/sessiontoken"
)

var rootCmd = &cobra.Command{
	Version: config.Version,
	Use:     "okta-aws-cli",
	Short:   "okta-aws-cli - Okta federated identity for AWS CLI",
	Long: `okta-aws-cli - Okta federated identity for AWS CLI

Okta authentication for federated identity providers in support of AWS CLI.
okta-aws-cli handles authentication to the IdP and token exchange with AWS STS 
to collect a proper IAM role for the AWS CLI operator.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		c := config.NewConfig(
			cmd.Flag("org-domain"),
			cmd.Flag("oidc-client-id"),
			cmd.Flag("aws-acct-fed-app-id"),
			cmd.Flag("format"),
			cmd.Flag("profile"))
		st := sessiontoken.NewSessionToken(c)
		return st.EstablishToken()
	},
}

type flag struct {
	name     string
	short    string
	value    string
	usage    string
	required bool
}

var flags = []flag{
	{
		name:     "org-domain",
		short:    "o",
		value:    "",
		usage:    "Org Domain",
		required: true,
	},
	{
		name:     "oidc-client-id",
		short:    "c",
		value:    "",
		usage:    "OIDC Client ID",
		required: true,
	},
	{
		name:     "aws-acct-fed-app-id",
		short:    "a",
		value:    "",
		usage:    "AWS Account Federation app ID",
		required: true,
	},
	{
		name:     "format",
		short:    "f",
		value:    "env-var",
		usage:    "Output format",
		required: false,
	},
	{
		name:     "profile",
		short:    "p",
		value:    "default",
		usage:    "AWS Profile",
		required: false,
	},
}

func init() {
	for _, f := range flags {
		rootCmd.Flags().StringP(f.name, f.short, f.value, f.usage)
		if f.required {
			rootCmd.MarkFlagRequired(f.name)
		}

	}
}

// Execute executes the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "okta-aws-cli experienced the following error '%s'", err)
		os.Exit(1)
	}
}
