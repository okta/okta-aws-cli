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
			fmt.Fprintf(os.Stderr, "Created credentials file %q\n", filename)
			return nil
		}
		return err
	}
	return nil
}

func saveProfile(filename, profile string, awsCreds *aws.Credential) error {
	config, err := ini.Load(filename)
	if err != nil {
		return err
	}
	iniProfile, err := config.NewSection(profile)
	if err != nil {
		return err
	}

	err = iniProfile.ReflectFrom(awsCreds)
	if err != nil {
		return err
	}

	err = config.SaveTo(filename)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Updated credentials file %q\n", filename)
	return nil
}

// AWSCredentialsFile AWS credentials file output formatter
type AWSCredentialsFile struct{}

// NewAWSCredentialsFile Creates a new
func NewAWSCredentialsFile() *AWSCredentialsFile {
	return &AWSCredentialsFile{}
}

// Output Satisfies the Outputter interface and appends AWS credentials to
// credentials file.
func (e *AWSCredentialsFile) Output(c *config.Config, ac *aws.Credential) error {
	filename := c.AWSCredentials
	profile := c.Profile

	err := ensureConfigExists(filename, profile)
	if err != nil {
		return err
	}

	return saveProfile(filename, profile, ac)
}
