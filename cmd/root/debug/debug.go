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

package debug

import (
	"github.com/spf13/cobra"

	"github.com/okta/okta-aws-cli/v2/internal/config"
)

// NewDebugCommand Sets up the debug cobra sub command
func NewDebugCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Simple debug of okta.yaml and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := config.NewEvaluatedConfig()
			if err != nil {
				return err
			}
			err = config.RunConfigChecks()
			// NOTE: still print out the done message, even if there was an error it will get printed as well
			config.Logger.Warn("debugging okta-aws-cli config $HOME/.okta/okta.yaml is complete\n")
			if err != nil {
				return err
			}
			return nil
		},
	}

	return cmd
}
