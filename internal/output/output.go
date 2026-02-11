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

package output

import (
	"time"

	oaws "github.com/okta/okta-aws-cli/v2/internal/aws"
	"github.com/okta/okta-aws-cli/v2/internal/config"
)

// Outputter Interface to output AWS credentials in different formats.
type Outputter interface {
	Output(c *config.Config, cc *oaws.CredentialContainer) error
}

// RenderAWSCredential Renders the credentials in the prescribed format.
func RenderAWSCredential(cfg *config.Config, cc *oaws.CredentialContainer) error {
	expiry := time.Now().Add(time.Duration(cfg.AWSSessionDuration()) * time.Second).Format(time.RFC3339)
	var o Outputter
	switch cfg.Format() {
	case config.AWSCredentialsFormat:
		o = NewAWSCredentialsFile(cfg.LegacyAWSVariables(), cfg.ExpiryAWSVariables(), expiry)
	case config.ProcessCredentialsFormat:
		o = NewProcessCredentials()

		// check special case where we are running in process credentials
		// format but we also need to write to the credentials file e.g. in
		// ~/.aws/credentials:
		//
		// [default]
		// credential_process = okta-aws-cli web --format process-credentials --oidc-client-id abc123 --org-domain test.okta.com --aws-iam-idp arn:aws:iam::123:saml-provider/ForOkta --aws-iam-role arn:aws:iam::123:role/S3_Read --open-browser --write-aws-credentials
		//
		if cfg.WriteAWSCredentials() {
			// attempt to write the creds first
			credsOut := NewAWSCredentialsFile(cfg.LegacyAWSVariables(), cfg.ExpiryAWSVariables(), expiry)
			if err := credsOut.Output(cfg, cc); err != nil {
				return err
			}
		}
	case config.NoopFormat:
		o = NewNoopCredentials()
	default:
		o = NewEnvVar(cfg.LegacyAWSVariables())
	}
	return o.Output(cfg, cc)
}
