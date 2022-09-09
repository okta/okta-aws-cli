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

package output

import (
	"fmt"

	"github.com/okta/okta-aws-cli/pkg/aws"
	"github.com/okta/okta-aws-cli/pkg/config"
)

type EnvVar struct{}

func NewEnvVar() *EnvVar {
	return &EnvVar{}
}

func (e *EnvVar) Output(c *config.Config, ac *aws.Credential) {
	fmt.Printf("export AWS_PROFILE=%s\n", c.Profile)
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", ac.AccessKeyId)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", ac.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=%s\n", ac.SessionToken)
}
