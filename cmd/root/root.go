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

	"github.com/okta/okta-aws-cli/pkg/ansi"
	"github.com/okta/okta-aws-cli/pkg/config"
	"github.com/okta/okta-aws-cli/pkg/sessiontoken"
)

type flag struct {
	name  string
	short string
	value interface{}
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
		name:  "aws-iam-idp",
		short: "i",
		value: "",
		usage: "IAM Identity Provider ARN",
	},
	{
		name:  "aws-iam-role",
		short: "r",
		value: "",
		usage: "IAM Role ARN",
	},
	{
		name:  "qr-code",
		short: "q",
		value: false,
		usage: "Print QR Code",
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
		if val, ok := f.value.(string); ok {
			cmd.PersistentFlags().StringP(f.name, f.short, val, f.usage)
		}
		if val, ok := f.value.(bool); ok {
			cmd.PersistentFlags().BoolP(f.name, f.short, val, f.usage)
		}
	}

	cmd.SetUsageTemplate(resourceUsageTemplate())

	return cmd
}

// Execute executes the root command
func Execute(c *config.Config) {
	cmd := buildRootCommand(c)
	c.OverrideIfSet(cmd, "org-domain")
	c.OverrideIfSet(cmd, "oidc-client-id")
	c.OverrideIfSet(cmd, "aws-acct-fed-app-id")
	c.OverrideIfSet(cmd, "format")
	c.OverrideIfSet(cmd, "aws-iam-idp")
	c.OverrideIfSet(cmd, "aws-iam-role")
	c.OverrideIfSet(cmd, "qr-code")
	c.OverrideIfSet(cmd, "profile")

	if err := c.CheckConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "okta-aws-cli experienced the following error(s):\n%s\n\n", err)
		cmd.Help()
		os.Exit(1)
	}

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "okta-aws-cli experienced the following error '%s'\n", err)
		os.Exit(1)
	}
}

func resourceUsageTemplate() string {
	return fmt.Sprintf(`%s:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

%s
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

%s
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}
  
%s{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}
  
%s
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}
  
%s
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}
  
%s{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}
  
Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`,
		ansi.Faint("Usage:"),
		ansi.Faint("Aliases:"),
		ansi.Faint("Examples:"),
		ansi.Faint("Available Commands:"),
		ansi.Faint("Flags:"),
		ansi.Faint("Global Flags:"),
		ansi.Faint("Additional help topics:"),
	)
}
