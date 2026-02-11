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

package profileslist

import (
	"github.com/spf13/cobra"

	"github.com/okta/okta-aws-cli/v2/internal/config"
)

// NewProfilesListCommand Sets up the debug cobra sub command
func NewProfilesListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-profiles",
		Short: "Lists profile names in ~/.okta/okta.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := config.NewEvaluatedConfig()
			if err != nil {
				return err
			}

			config.Logger.Info("Profiles:\n")

			keys, err := config.ReadConfigProfileKeys()
			if err != nil {
				return err
			}

			for _, key := range keys {
				config.Logger.Info(" %s\n", key)
			}

			return nil
		},
	}

	return cmd
}
