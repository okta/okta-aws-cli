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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	debugCmd "github.com/okta/okta-aws-cli/cmd/root/debug"
	"github.com/okta/okta-aws-cli/cmd/root/m2m"
	"github.com/okta/okta-aws-cli/cmd/root/web"
	"github.com/okta/okta-aws-cli/internal/ansi"
	"github.com/okta/okta-aws-cli/internal/config"
	cliFlag "github.com/okta/okta-aws-cli/internal/flag"
)

var (
	flags   []cliFlag.Flag
	rootCmd *cobra.Command
)

func init() {
	var awsCredentialsFilename string
	if home, err := os.UserHomeDir(); err == nil {
		awsCredentialsFilename = filepath.Join(home, ".aws", "credentials")
	}

	flags = []cliFlag.Flag{
		{
			Name:   config.OrgDomainFlag,
			Short:  "o",
			Value:  "",
			Usage:  "Okta Org Domain",
			EnvVar: config.OktaOrgDomainEnvVar,
		},
		{
			Name:   config.OIDCClientIDFlag,
			Short:  "c",
			Value:  "",
			Usage:  "OIDC Client ID - web: OIDC native application, m2m: API service application",
			EnvVar: config.OktaOIDCClientIDEnvVar,
		},
		{
			Name:   config.AWSIAMRoleFlag,
			Short:  "r",
			Value:  "",
			Usage:  "Preset IAM Role ARN",
			EnvVar: config.AWSIAMRoleEnvVar,
		},
		{
			Name:   config.SessionDurationFlag,
			Short:  "s",
			Value:  "",
			Usage:  "Session duration for role.",
			EnvVar: config.AWSSessionDurationEnvVar,
		},
		{
			Name:   config.ProfileFlag,
			Short:  "p",
			Value:  "default",
			Usage:  "AWS Profile",
			EnvVar: config.ProfileEnvVar,
		},
		{
			Name:   config.FormatFlag,
			Short:  "f",
			Value:  "",
			Usage:  "Output format. [aws-credentials|env-var|noop|process-credentials]",
			EnvVar: config.FormatEnvVar,
		},
		{
			Name:   config.AWSRegionFlag,
			Short:  "n",
			Value:  "",
			Usage:  "Preset AWS Region",
			EnvVar: config.AWSRegionEnvVar,
		},
		{
			Name:   config.AWSCredentialsFlag,
			Short:  "w",
			Value:  awsCredentialsFilename,
			Usage:  fmt.Sprintf("Path to AWS credentials file, only valid with format %q", config.AWSCredentialsFormat),
			EnvVar: config.AWSCredentialsEnvVar,
		},
		{
			Name:   config.WriteAWSCredentialsFlag,
			Short:  "z",
			Value:  false,
			Usage:  fmt.Sprintf("Write the created/updated profile to the %q file. WARNING: This can inadvertently remove dangling comments and extraneous formatting from the creds file.", awsCredentialsFilename),
			EnvVar: config.WriteAWSCredentialsEnvVar,
		},
		{
			Name:   config.LegacyAWSVariablesFlag,
			Short:  "l",
			Value:  false,
			Usage:  "Emit deprecated AWS Security Token value. WARNING: AWS CLI deprecated this value in November 2014 and is no longer documented",
			EnvVar: config.LegacyAWSVariablesEnvVar,
		},
		{
			Name:   config.ExpiryAWSVariablesFlag,
			Short:  "x",
			Value:  false,
			Usage:  "Emit x_security_token_expires value in profile block of AWS credentials file",
			EnvVar: config.ExpiryAWSVariablesEnvVar,
		},
		{
			Name:   config.CacheAccessTokenFlag,
			Short:  "e",
			Value:  false,
			Usage:  "Cache Okta access token to reduce need for opening grant URL",
			EnvVar: config.CacheAccessTokenEnvVar,
		},
		{
			Name:   config.DebugFlag,
			Short:  "g",
			Value:  false,
			Usage:  "Print operational information to the screen for debugging purposes",
			EnvVar: config.DebugEnvVar,
		},
		{
			Name:   config.DebugAPICallsFlag,
			Short:  "d",
			Value:  false,
			Usage:  "Verbosely print all API calls/responses to the screen",
			EnvVar: config.DebugAPICallsEnvVar,
		},
		{
			Name:   config.ExecFlag,
			Short:  "j",
			Value:  false,
			Usage:  "Execute any shell commands after the '--' CLI arguments termination",
			EnvVar: config.ExecEnvVar,
		},
	}

	rootCmd = NewRootCommand()
	webCmd := web.NewWebCommand()
	rootCmd.AddCommand(webCmd)
	m2mCmd := m2m.NewM2MCommand()
	rootCmd.AddCommand(m2mCmd)
	debugCfgCmd := debugCmd.NewDebugCommand()
	rootCmd.AddCommand(debugCfgCmd)
}

// NewRootCommand Sets up the root cobra command
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Version: config.Version,
		Use:     "okta-aws-cli",
		Short:   "Okta federated identity for AWS CLI",
		Long: `Okta federated identity for AWS CLI

Okta authentication in support of AWS CLI.  okta-aws-cli handles authentication
with Okta and token exchange with AWS STS to collect temporary IAM credentials
associated with a given IAM Role for the AWS CLI operator.`,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	cmd.SetUsageTemplate(resourceUsageTemplate())
	cliFlag.MakeFlagBindings(cmd, flags, true)

	return cmd
}

// Execute executes the root command
func Execute(defaultCommand string) {
	// cmdFound is used to determine if we were called without a subcommand
	// argument, and if so, treat the default command as if it was called as a
	// sub command.
	var cmdFound bool

	// If the sub command is registered we don't need to alias the default
	// command with an append below.
	for _, cmd := range rootCmd.Commands() {
		for _, arg := range os.Args[1:] {
			if cmd.Name() == arg {
				cmdFound = true
				break
			}
		}
	}

	// Also, consider the command found if our args is just a bare help so help
	// for both sub commands is printed.
	if len(os.Args) == 1 {
		cmdFound = true
	}
	if len(os.Args) >= 2 {
		if arg := os.Args[1]; arg == "--help" || arg == "-h" || arg == "help" || arg == "--version" || arg == "-v" {
			cmdFound = true
		}
	}
	if !cmdFound {
		args := append([]string{defaultCommand}, os.Args[1:]...)
		rootCmd.SetArgs(args)
	}

	// Get to work ...
	if err := rootCmd.Execute(); err != nil {
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
