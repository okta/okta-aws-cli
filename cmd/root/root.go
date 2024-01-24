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
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/okta/okta-aws-cli/internal/ansi"
	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/sessiontoken"
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
			name:   config.OrgDomainFlag,
			short:  "o",
			value:  "",
			usage:  "Okta Org Domain",
			envVar: config.OktaOrgDomainEnvVar,
		},
		{
			name:   config.OIDCClientIDFlag,
			short:  "c",
			value:  "",
			usage:  "OIDC Client ID",
			envVar: config.OktaOIDCClientIDEnvVar,
		},
		{
			name:   config.AWSAcctFedAppIDFlag,
			short:  "a",
			value:  "",
			usage:  "AWS Account Federation app ID",
			envVar: config.OktaAWSAccountFederationAppIDEnvVar,
		},
		{
			name:   config.AWSIAMIdPFlag,
			short:  "i",
			value:  "",
			usage:  "Preset IAM Identity Provider ARN",
			envVar: config.AWSIAMIdPEnvVar,
		},
		{
			name:   config.AWSIAMRoleFlag,
			short:  "r",
			value:  "",
			usage:  "Preset IAM Role ARN",
			envVar: config.AWSIAMRoleEnvVar,
		},
		{
			name:   config.AWSRegionFlag,
			short:  "",
			value:  "",
			usage:  "Preset AWS Region",
			envVar: config.AWSRegionEnvVar,
		},
		{
			name:   config.SessionDurationFlag,
			short:  "s",
			value:  "",
			usage:  "Session duration for role.",
			envVar: config.AWSSessionDurationEnvVar,
		},
		{
			name:   config.ProfileFlag,
			short:  "p",
			value:  "",
			usage:  "AWS Profile",
			envVar: config.ProfileEnvVar,
		},
		{
			name:   config.FormatFlag,
			short:  "f",
			value:  "",
			usage:  "Output format. [env-var|aws-credentials]",
			envVar: config.FormatEnvVar,
		},
		{
			name:   config.QRCodeFlag,
			short:  "q",
			value:  false,
			usage:  "Print QR Code of activation URL",
			envVar: config.QRCodeEnvVar,
		},
		{
			name:   config.AWSCredentialsFlag,
			short:  "w",
			value:  awsCredentialsFilename,
			usage:  fmt.Sprintf("Path to AWS credentials file, only valid with format %q", config.AWSCredentialsFormat),
			envVar: config.AWSCredentialsEnvVar,
		},
		{
			name:   config.OpenBrowserFlag,
			short:  "b",
			value:  false,
			usage:  "Automatically open the activation URL with the system web browser",
			envVar: config.OpenBrowserEnvVar,
		},
		{
			name:   config.WriteAWSCredentialsFlag,
			short:  "z",
			value:  false,
			usage:  fmt.Sprintf("Write the created/updated profile to the %q file. WARNING: This can inadvertently remove dangling comments and extraneous formatting from the creds file.", awsCredentialsFilename),
			envVar: config.WriteAWSCredentialsEnvVar,
		},
		{
			name:   config.LegacyAWSVariablesFlag,
			short:  "l",
			value:  false,
			usage:  "Emit deprecated AWS Security Token value. WARNING: AWS CLI deprecated this value in November 2014 and is no longer documented",
			envVar: config.LegacyAWSVariablesEnvVar,
		},
		{
			name:   config.ExpiryAWSVariablesFlag,
			short:  "x",
			value:  false,
			usage:  "Emit x_security_token_expires value in profile block of AWS credentials file",
			envVar: config.ExpiryAWSVariablesEnvVar,
		},
		{
			name:   config.CacheAccessTokenFlag,
			short:  "e",
			value:  false,
			usage:  "Cache Okta access token to reduce need for opening grant URL",
			envVar: config.CacheAccessTokenEnvVar,
		},
		{
			name:   config.DebugFlag,
			short:  "g",
			value:  false,
			usage:  "Print operational information to the screen for debugging purposes",
			envVar: config.DebugEnvVar,
		},
		{
			name:   config.DebugAPICallsFlag,
			short:  "d",
			value:  false,
			usage:  "Verbosely print all API calls/responses to the screen",
			envVar: config.DebugAPICallsEnvVar,
		},
		{
			name:   config.DebugConfigFlag,
			short:  "k",
			value:  false,
			usage:  "Inspect current okta.yaml configuration and exit",
			envVar: config.DebugConfigEnvVar,
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
			config, err := config.CreateConfig()
			if err == nil && config.DebugConfig() {
				checkErr := config.RunConfigChecks()
				fmt.Fprintf(os.Stderr, "debugging okta-aws-cli config $HOME/.okta/okta.yaml is complete\n")
				return checkErr
			}
			if err != nil {
				return err
			}

			st, err := sessiontoken.NewSessionToken(config)
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

		// After viper reads in the dotenv file check if AWS_REGION is set
		// there. The value will be keyed by lower case name. If it is, set
		// AWS_REGION as an ENV VAR if it hasn't already been.
		awsRegionEnvVar := "AWS_REGION"
		vipAwsRegion := viper.GetString(strings.ToLower(awsRegionEnvVar))
		if vipAwsRegion != "" && os.Getenv(awsRegionEnvVar) == "" {
			_ = os.Setenv(awsRegionEnvVar, vipAwsRegion)
		}
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
	return fmt.Sprintf(`%s{{if .Runnable}}
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
