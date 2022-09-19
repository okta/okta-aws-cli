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

type flag struct {
	name  string
	short string
	value string
	usage string
}

var flags = []flag{
	{
		name:  "org-domain",
		short: "o",
		value: "",
		usage: "Okta Org Domain",
	},
	{
		name:  "oidc-client-id",
		short: "c",
		value: "",
		usage: "OIDC Client ID",
	},
	{
		name:  "aws-acct-fed-app-id",
		short: "a",
		value: "",
		usage: "AWS Account Federation app ID",
	},
	{
		name:  "format",
		short: "f",
		value: "env-var",
		usage: "Output format",
	},
	{
		name:  "profile",
		short: "p",
		value: "default",
		usage: "AWS Profile",
	},
}

func buildRootCommand(c *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Version: config.Version,
		Use:     "okta-aws-cli",
		Short:   "okta-aws-cli - Okta federated identity for AWS CLI",
		Long: `okta-aws-cli - Okta federated identity for AWS CLI

Okta authentication for federated identity providers in support of AWS CLI.
okta-aws-cli handles authentication to the IdP and token exchange with AWS STS 
to collect a proper IAM role for the AWS CLI operator.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			st := sessiontoken.NewSessionToken(c)
			return st.EstablishToken()
		},
	}

	for _, f := range flags {
		cmd.Flags().StringP(f.name, f.short, f.value, f.usage)
	}

	return cmd
}

// Execute executes the root command
func Execute(c *config.Config) {
	cmd := buildRootCommand(c)
	c.OverrideIfSet(cmd, "org-domain")
	c.OverrideIfSet(cmd, "oidc-client-id")
	c.OverrideIfSet(cmd, "aws-acct-fed-app-id")
	c.OverrideIfSet(cmd, "format")
	c.OverrideIfSet(cmd, "profile")

	if err := c.CheckConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "okta-aws-cli experienced the following error(s):\n%s\n\n", err)
		cmd.Help()
		os.Exit(1)
	}

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "okta-aws-cli experienced the following error '%s'", err)
		os.Exit(1)
	}
}
