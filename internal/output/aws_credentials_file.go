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
	"path/filepath"
	"strings"

	"github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/pkg/errors"
	"gopkg.in/ini.v1"
)

// ensureConfigExists verify that the config file exists
func ensureConfigExists(filename string, profile string) error {
	if _, err := os.Stat(filename); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			dir := filepath.Dir(filename)

			// create the aws config dir
			err = os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return errors.Wrapf(err, "unable to create AWS credentials directory %q", dir)
			}

			// create an base config file
			err = os.WriteFile(filename, []byte("["+profile+"]"), 0o600)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Created credentials file %q with profile %q.\n", filename, profile)
			return nil
		}
		return err
	}
	return nil
}

func saveProfile(filename, profile string, awsCreds *aws.Credential, legacyVars bool) error {
	config, err := updateConfig(filename, profile, awsCreds, legacyVars)
	if err != nil {
		return err
	}

	err = config.SaveTo(filename)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Updated profile %q in credentials file %q.\n", profile, filename)
	return nil
}

func updateConfig(filename, profile string, awsCreds *aws.Credential, legacyVars bool) (config *ini.File, err error) {
	config, err = ini.Load(filename)
	if err != nil {
		return
	}

	iniProfile, err := config.NewSection(profile)
	if err != nil {
		return
	}
	var creds interface{}
	if legacyVars {
		creds = &aws.LegacyCredential{
			AccessKeyID:     awsCreds.AccessKeyID,
			SecretAccessKey: awsCreds.SecretAccessKey,
			SessionToken:    awsCreds.SessionToken,
			SecurityToken:   awsCreds.SessionToken,
		}
	} else {
		creds = awsCreds
	}
	err = iniProfile.ReflectFrom(creds)
	if err != nil {
		return
	}

	return updateINI(config, profile, legacyVars)
}

// updateIni will comment out any keys that are not "aws_access_key_id",
// "aws_secret_access_key", or "aws_session_token"
func updateINI(config *ini.File, profile string, legacyVars bool) (*ini.File, error) {
	ignore := []string{
		"aws_access_key_id",
		"aws_secret_access_key",
		"aws_session_token",
	}
	if legacyVars {
		ignore = append(ignore, "aws_security_token")
	}
	section := config.Section(profile)
	comments := []string{}
	for _, name := range section.KeyStrings() {
		if contains(ignore, name) {
			continue
		}
		if len(name) > 0 && string(name[0]) == "#" {
			continue
		}

		key, err := section.GetKey(name)
		if err != nil {
			continue
		}

		// The named key is in the profile but it's not utilized by
		// okta-aws-cli. Therefore comment it out but do not delete.
		_, _ = section.NewKey(fmt.Sprintf("# %s", name), key.Value())
		section.DeleteKey(name)
		comments = append(comments, name)
	}
	if len(comments) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: Commented out %q profile keys \"%s\". Uncomment if third party tools use these values.\n", profile, strings.Join(comments, "\", \""))
	}
	if legacyVars {
		fmt.Fprintf(os.Stderr, "WARNING: %q includes legacy variable \"aws_security_token\". Update tools making use of this deprecated value.", profile)
	}

	return config, nil
}

// AWSCredentialsFile AWS credentials file output formatter
type AWSCredentialsFile struct {
	LegacyAWSVariables bool
}

// NewAWSCredentialsFile Creates a new
func NewAWSCredentialsFile(legacyVars bool) *AWSCredentialsFile {
	return &AWSCredentialsFile{
		LegacyAWSVariables: legacyVars,
	}
}

// Output Satisfies the Outputter interface and appends AWS credentials to
// credentials file.
func (e *AWSCredentialsFile) Output(c *config.Config, ac *aws.Credential) error {
	if c.WriteAWSCredentials {
		return e.writeConfig(c, ac)
	}

	return e.appendConfig(c, ac)
}

func (e *AWSCredentialsFile) appendConfig(c *config.Config, ac *aws.Credential) error {
	f, err := os.OpenFile(c.AWSCredentials, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	var creds string

	if e.LegacyAWSVariables {
		creds = `
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s
aws_session_token = %s
aws_security_token = %s
`
		creds = fmt.Sprintf(creds, c.Profile, ac.AccessKeyID, ac.SecretAccessKey, ac.SessionToken, ac.SessionToken)
	} else {
		creds = `
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s
aws_session_token = %s
`
		creds = fmt.Sprintf(creds, c.Profile, ac.AccessKeyID, ac.SecretAccessKey, ac.SessionToken)
	}
	_, err = f.WriteString(creds)
	if err != nil {
		return err
	}
	_ = f.Sync()

	fmt.Fprintf(os.Stderr, "Appended profile %q to %s\n", c.Profile, c.AWSCredentials)

	return nil
}

func (e *AWSCredentialsFile) writeConfig(c *config.Config, ac *aws.Credential) error {
	filename := c.AWSCredentials
	profile := c.Profile

	err := ensureConfigExists(filename, profile)
	if err != nil {
		return err
	}

	return saveProfile(filename, profile, ac, e.LegacyAWSVariables)
}

func contains(ignore []string, name string) bool {
	for _, v := range ignore {
		if v == name {
			return true
		}
	}

	return false
}
