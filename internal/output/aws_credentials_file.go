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

	"github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/config"
)

// AWSCredentialsFile AWS credentials file output formatter
type AWSCredentialsFile struct{}

// NewAWSCredentialsFile Creates a new
func NewAWSCredentialsFile() *AWSCredentialsFile {
	return &AWSCredentialsFile{}
}

// Output Satisfies the Outputter interface and appends AWS credentials to
// credentials file.
func (e *AWSCredentialsFile) Output(c *config.Config, ac *aws.Credential) error {
	f, err := os.OpenFile(c.AWSCredentials, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	creds := `
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s
aws_session_token = %s

`
	creds = fmt.Sprintf(creds, c.Profile, ac.AccessKeyID, ac.SecretAccessKey, ac.SessionToken)
	_, err = f.WriteString(creds)
	if err != nil {
		return err
	}
	_ = f.Sync()

	fmt.Fprintf(os.Stderr, "Wrote profile %q to %s\n", c.Profile, c.AWSCredentials)

	return nil
}
