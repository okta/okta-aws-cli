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

package output

import (
	"fmt"

	"github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/config"
)

// EnvVar Environment Variable output formatter
type EnvVar struct{}

// NewEnvVar Creates a new EnvVar
func NewEnvVar() *EnvVar {
	return &EnvVar{}
}

// Output Satisfies the Outputter interface and outputs AWS credentials as shell
// export statements to STDOUT
func (e *EnvVar) Output(c *config.Config, ac *aws.Credential) error {
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", ac.AccessKeyID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", ac.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=%s\n", ac.SessionToken)
	return nil
}
