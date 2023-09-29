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
	"os"
	"time"

	"github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/config"
)

// Outputter Interface to output AWS credentials in different formats.
type Outputter interface {
	Output(c *config.Config, ac *aws.Credential) error
}

// RenderAWSCredential Renders the credentials in the prescribed format.
func RenderAWSCredential(cfg *config.Config, ac *aws.Credential) error {
	var o Outputter
	switch cfg.Format() {
	case config.AWSCredentialsFormat:
		expiry := time.Now().Add(time.Duration(cfg.AWSSessionDuration()) * time.Second).Format(time.RFC3339)
		o = NewAWSCredentialsFile(cfg.LegacyAWSVariables(), cfg.ExpiryAWSVariables(), expiry)
	default:
		o = NewEnvVar(cfg.LegacyAWSVariables())
		fmt.Fprintf(os.Stderr, "\n")
	}

	return o.Output(cfg, ac)
}
