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

package root

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/okta/okta-aws-cli/internal/ansi"
	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/sessiontoken"
	pstr "github.com/okta/okta-aws-cli/pkg/strings"
)

const (
	dotEnvFilename = ".env"
)

type flag struct {
	name   string
	short  string
	value  interface{}
	usage  string
	envVar string
}

var flags []flag

func init() {
	var awsCredentialsFilename string
	if home, err := os.UserHomeDir(); err == nil {
		awsCredentialsFilename = filepath.Join(home, ".aws", "credentials")
	}

	flags = []flag{
		{
			name:   "org-domain",
			short:  "o",
			value:  "",
			usage:  "Okta Org Domain",
			envVar: "OKTA_ORG_DOMAIN",
		},
		{
			name:   "oidc-client-id",
			short:  "c",
			value:  "",
			usage:  "OIDC Client ID",
			envVar: "OKTA_OIDC_CLIENT_ID",
		},
		{
			name:   "aws-acct-fed-app-id",
			short:  "a",
			value:  "",
			usage:  "AWS Account Federation app ID",
			envVar: "OKTA_AWS_ACCOUNT_FEDERATION_APP_ID",
		},
		{
			name:   "aws-iam-idp",
			short:  "i",
			value:  "",
			usage:  "IAM Identity Provider ARN",
			envVar: "AWS_IAM_IDP",
		},
		{
			name:   "aws-iam-role",
			short:  "r",
			value:  "",
			usage:  "IAM Role ARN",
			envVar: "AWS_IAM_ROLE",
		},
		{
			name:   "session-duration",
			short:  "s",
			value:  "3600",
			usage:  "Session duration for role.",
			envVar: "AWS_SESSION_DURATION",
		},
		{
			name:   "profile",
			short:  "p",
			value:  "default",
			usage:  "AWS Profile",
			envVar: "PROFILE",
		},
		{
			name:   "format",
			short:  "f",
			value:  "env-var",
			usage:  "Output format. [env-var|aws-credentials]",
			envVar: "FORMAT",
		},
		{
			name:   "qr-code",
			short:  "q",
			value:  false,
			usage:  "Print QR Code of activation URL",
			envVar: "QR_CODE",
		},
		{
			name:   "aws-credentials",
			short:  "w",
			value:  awsCredentialsFilename,
			usage:  fmt.Sprintf("Path to AWS credentials file, only valid with format %q", pstr.AWSCredentials),
			envVar: "AWS_CREDENTIALS",
		},
		{
			name:   "open-browser",
			short:  "b",
			value:  false,
			usage:  "Automatically open the activation URL with the system web browser",
			envVar: "OPEN_BROWSER",
		},
	}
}

func buildRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Version: config.Version,
		Use:     "okta-aws-cli",
		Short:   "okta-aws-cli - Okta federated identity for AWS CLI",
		Long: `okta-aws-cli - Okta federated identity for AWS CLI
 
Okta authentication for federated identity providers in support of AWS CLI.
okta-aws-cli handles authentication to the IdP and token exchange with AWS STS 
to collect a proper IAM role for the AWS CLI operator.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := sessiontoken.NewSessionToken()
			if err != nil {
				return err
			}
			return st.EstablishToken()
		},
	}

	// bind env vars
	for _, f := range flags {
		_ = viper.BindEnv(f.envVar, f.name)
	}
	// bind env vars via dotenv if it exists
	path, _ := os.Getwd()
	dotEnv := filepath.Join(path, dotEnvFilename)
	if _, err := os.Stat(dotEnv); err == nil || !errors.Is(err, os.ErrNotExist) {
		viper.AddConfigPath(path)
		viper.SetConfigName(dotEnvFilename)
		viper.SetConfigType("dotenv")

		_ = viper.ReadInConfig()
	}
	viper.AutomaticEnv()

	// bind cli flags
	for _, f := range flags {
		if val, ok := f.value.(string); ok {
			cmd.PersistentFlags().StringP(f.name, f.short, val, f.usage)
		}
		if val, ok := f.value.(bool); ok {
			cmd.PersistentFlags().BoolP(f.name, f.short, val, f.usage)
		}

		_ = viper.BindPFlag(f.name, cmd.PersistentFlags().Lookup(f.name))
	}

	cmd.SetUsageTemplate(resourceUsageTemplate())
	return cmd
}

// Execute executes the root command
func Execute() {
	cmd := buildRootCommand()
	if err := cmd.Execute(); err != nil {
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
