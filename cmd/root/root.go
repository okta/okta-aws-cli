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

	"github.com/okta/okta-aws-cli/pkg/work"
)

var rootCmd = &cobra.Command{
	Use:   "okta-aws",
	Short: "okta-aws - Okta federated identity for AWS CLI",
	Long: `okta-aws - Okta federated identity for AWS CLI

Okta authentication for federated identity providers in support of AWS CLI.
okta-aws handles authentication to the IdP and token exchange with AWS STS to
collect a proper IAM role for the AWS CLI operator.`,
	Run: func(cmd *cobra.Command, args []string) {
		work.Work()
	},
}

// Execute Execute the roote aws-cli command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "aws-cli experienced the following error '%s'", err)
		os.Exit(1)
	}
}
