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

	oaws "github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/config"
)

// Outputter Interface to output AWS credentials in different formats.
type Outputter interface {
	Output(c *config.Config, oc oaws.Credential) error
}

// RenderAWSCredential Renders the credentials in the prescribed format.
func RenderAWSCredential(cfg *config.Config, cc *oaws.CredentialContainer) error {
	var o Outputter
	switch cfg.Format() {
	case config.AWSCredentialsFormat:
		expiry := time.Now().Add(time.Duration(cfg.AWSSessionDuration()) * time.Second).Format(time.RFC3339)
		o = NewAWSCredentialsFile(cfg.LegacyAWSVariables(), cfg.ExpiryAWSVariables(), expiry)
		cfc := &oaws.CredsFileCredential{
			AccessKeyID:     cc.AccessKeyID,
			SecretAccessKey: cc.SecretAccessKey,
			SessionToken:    cc.SessionToken,
		}
		cfc.SetProfile(cc.Profile)
		return o.Output(cfg, cfc)
	case config.ProcessCredentialsFormat:
		o = NewProcessCredentials()
		pc := &oaws.ProcessCredential{
			AccessKeyID:     cc.AccessKeyID,
			SecretAccessKey: cc.SecretAccessKey,
			SessionToken:    cc.SessionToken,
			Expiration:      cc.Expiration,
			// See AWS docs: "Note As of this writing, the Version key must be set to 1.
			// This might increment over time as the structure evolves."
			Version: 1,
		}
		return o.Output(cfg, pc)
	case config.NoopFormat:
		o = NewNoopCredentials()
		nc := &oaws.NoopCredential{}
		return o.Output(cfg, nc)
	default:
		o = NewEnvVar(cfg.LegacyAWSVariables())
		fmt.Fprintf(os.Stderr, "\n")
		evc := &oaws.EnvVarCredential{
			AccessKeyID:     cc.AccessKeyID,
			SecretAccessKey: cc.SecretAccessKey,
			SessionToken:    cc.SessionToken,
		}
		return o.Output(cfg, evc)
	}
}
