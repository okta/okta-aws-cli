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

package flag

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const dotEnvFilename = ".env"

var altFlagNames map[string]string

func init() {
	altFlagNames = map[string]string{
		"org-domain":     "okta_awscli_org_domain",
		"oidc-client-id": "okta_awscli_oidc_client_id",
		"aws-iam-role":   "okta_awscli_iam_role",
		"key-id":         "okta_awscli_key_id",
		"private-key":    "okta_awscli_private_key",
		"authz-id":       "okta_awscli_authz_id",
	}
}

// Flag Convenience struct for Viper flag parameters
type Flag struct {
	Name   string
	Short  string
	Value  interface{}
	Usage  string
	EnvVar string
}

// MakeFlagBindings Bind flags to the command setting them by hard flags from
// the CLI, .env values, and environment variable values.  Make the flags
// persistent for the command that needs to propagate them to subcommands; for
// instance the global flags on the root command.
//
// https://github.com/spf13/cobra/blob/main/site/content/user_guide.md#working-with-flags
func MakeFlagBindings(cmd *cobra.Command, flags []Flag, persistent bool) {
	// bind env vars
	for _, f := range flags {
		_ = viper.BindEnv(f.EnvVar, f.Name)
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
		if val, ok := f.Value.(string); ok {
			if persistent {
				cmd.PersistentFlags().StringP(f.Name, f.Short, val, f.Usage)
			} else {
				cmd.Flags().StringP(f.Name, f.Short, val, f.Usage)
			}
		}
		if val, ok := f.Value.(bool); ok {
			if persistent {
				cmd.PersistentFlags().BoolP(f.Name, f.Short, val, f.Usage)
			} else {
				cmd.Flags().BoolP(f.Name, f.Short, val, f.Usage)
			}
		}

		if persistent {
			_ = viper.BindPFlag(f.Name, cmd.PersistentFlags().Lookup(f.Name))
		} else {
			_ = viper.BindPFlag(f.Name, cmd.Flags().Lookup(f.Name))
		}
	}
}

// CheckRequiredFlags Checks if flags in the list are all set in Viper
func CheckRequiredFlags(flags []string) error {
	unsetFlags := []string{}
	for _, f := range flags {
		altName := altFlagName(f)
		if !viper.GetViper().IsSet(f) && !viper.GetViper().IsSet(altName) {
			unsetFlags = append(unsetFlags, fmt.Sprintf("  --%s", f))
		}
	}
	if len(unsetFlags) > 0 {
		return fmt.Errorf("missing flags:\n%s", strings.Join(unsetFlags, "\n"))
	}
	return nil
}

// altFlagName Helper function for looking up viper values as it key CLI flag
// and ENV VAR name items differently For example	as a CLI flag the PK key name
// would be h"private-key" and "okta_awscli_private_key" as an ENV VAR.
func altFlagName(name string) string {
	if alt, ok := altFlagNames[name]; ok {
		return alt
	}
	return name
}
