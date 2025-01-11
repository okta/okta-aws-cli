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

package output

import (
	"encoding/json"

	oaws "github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/config"
)

// ProcessCredentials AWS CLI Process Credentials output formatter
// https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html
type ProcessCredentials struct{}

// NewProcessCredentials Creates a new ProcessCredentials
func NewProcessCredentials() *ProcessCredentials {
	return &ProcessCredentials{}
}

// Output Satisfies the Outputter interface and outputs AWS credentials as JSON
// to STDOUT
func (p *ProcessCredentials) Output(c *config.Config, cc *oaws.CredentialContainer) error {
	pc := &oaws.ProcessCredential{
		AccessKeyID:     cc.AccessKeyID,
		SecretAccessKey: cc.SecretAccessKey,
		SessionToken:    cc.SessionToken,
		Expiration:      cc.Expiration,
		// See AWS docs: "Note As of this writing, the Version key must be set to 1.
		// This might increment over time as the structure evolves."
		Version: 1,
	}

	credJSON, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		return err
	}

	c.Logger.Info("%s", credJSON)
	return nil
}
