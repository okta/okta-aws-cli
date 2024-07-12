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
	"reflect"
	"strings"

	dynamicstruct "github.com/ompluscator/dynamic-struct"
	"github.com/pkg/errors"
	"gopkg.in/ini.v1"

	oaws "github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/utils"
)

const (

	// ExpirationField --
	ExpirationField = "Expiration"
	// SecurityTokenField --
	SecurityTokenField = "SecurityToken"
)

// ensureConfigExists verify that the config file exists
func ensureConfigExists(filename, profile string) error {
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

func saveProfile(filename, profile string, cfc *oaws.CredsFileCredential, legacyVars, expiryVars bool, expiry, regionVar string) error {
	config, err := updateConfig(filename, profile, cfc, legacyVars, expiryVars, expiry, regionVar)
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

func updateConfig(filename, profile string, cfc *oaws.CredsFileCredential, legacyVars, expiryVars bool, expiry, region string) (config *ini.File, err error) {
	config, err = ini.Load(filename)
	if err != nil {
		return
	}

	iniProfile, err := config.NewSection(profile)
	if err != nil {
		return
	}

	builder := dynamicstruct.NewStruct().
		AddField(utils.AccessKeyID, "", `ini:"aws_access_key_id"`).
		AddField(utils.SecretAccessKey, "", `ini:"aws_secret_access_key"`).
		AddField(utils.SessionToken, "", `ini:"aws_session_token"`)

	if expiryVars {
		builder.AddField(ExpirationField, "", `ini:"x_security_token_expires"`)
	}
	if legacyVars {
		builder.AddField(SecurityTokenField, "", `ini:"aws_security_token"`)
	}
	if region != "" {
		builder.AddField(utils.Region, "", `ini:"region"`)
	}

	instance := builder.Build().New()
	reflect.ValueOf(instance).Elem().FieldByName(utils.AccessKeyID).SetString(cfc.AccessKeyID)
	reflect.ValueOf(instance).Elem().FieldByName(utils.SecretAccessKey).SetString(cfc.SecretAccessKey)
	reflect.ValueOf(instance).Elem().FieldByName(utils.SessionToken).SetString(cfc.SessionToken)
	if region != "" {
		reflect.ValueOf(instance).Elem().FieldByName(utils.Region).SetString(region)
	}

	if expiryVars {
		reflect.ValueOf(instance).Elem().FieldByName(ExpirationField).SetString(expiry)
	}
	if legacyVars {
		reflect.ValueOf(instance).Elem().FieldByName(SecurityTokenField).SetString(cfc.SessionToken)
	}

	err = iniProfile.ReflectFrom(instance)
	if err != nil {
		return
	}

	return updateINI(config, profile, legacyVars, expiryVars, region)
}

// updateIni will comment out any keys that are not "aws_access_key_id",
// "aws_secret_access_key", "aws_session_token", "credential_process"
func updateINI(config *ini.File, profile string, legacyVars, expiryVars bool, region string) (*ini.File, error) {
	ignore := []string{
		"aws_access_key_id",
		"aws_secret_access_key",
		"aws_session_token",
		"credential_process",
	}
	if legacyVars {
		ignore = append(ignore, "aws_security_token")
	}
	if expiryVars {
		ignore = append(ignore, "x_security_token_expires")
	}
	if region != "" {
		ignore = append(ignore, "region")
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

	return config, nil
}

// AWSCredentialsFile AWS credentials file output formatter
type AWSCredentialsFile struct {
	LegacyAWSVariables bool
	ExpiryAWSVariables bool
	Expiry             string
	Region             string
}

// NewAWSCredentialsFile Creates a new
func NewAWSCredentialsFile(legacyVars, expiryVars bool, expiry string) *AWSCredentialsFile {
	return &AWSCredentialsFile{
		LegacyAWSVariables: legacyVars,
		ExpiryAWSVariables: expiryVars,
		Expiry:             expiry,
	}
}

// Output Satisfies the Outputter interface and appends AWS credentials to
// credentials file.
func (a *AWSCredentialsFile) Output(c *config.Config, cc *oaws.CredentialContainer) error {
	cfc := &oaws.CredsFileCredential{
		AccessKeyID:     cc.AccessKeyID,
		SecretAccessKey: cc.SecretAccessKey,
		SessionToken:    cc.SessionToken,
	}
	cfc.SetProfile(cc.Profile)
	if c.WriteAWSCredentials() {
		return a.writeConfig(c, cfc)
	}

	return a.appendConfig(c, cfc)
}

func (a *AWSCredentialsFile) appendConfig(c *config.Config, cfc *oaws.CredsFileCredential) error {
	f, err := os.OpenFile(c.AWSCredentials(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	profile := cfc.Profile()
	if profile == "" {
		profile = c.Profile()
	}

	creds := `
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s
aws_session_token = %s
`
	credArgs := []interface{}{profile, cfc.AccessKeyID, cfc.SecretAccessKey, cfc.SessionToken}

	if a.LegacyAWSVariables {
		creds = fmt.Sprintf("%saws_security_token = %%s\n", creds)
		credArgs = append(credArgs, cfc.SessionToken)
	}

	if a.ExpiryAWSVariables {
		creds = fmt.Sprintf("%sx_security_token_expires = %%s\n", creds)
		credArgs = append(credArgs, a.Expiry)
	}

	if c.AWSRegion() != "" {
		creds = fmt.Sprintf("%sregion = %%s\n", creds)
		credArgs = append(credArgs, c.AWSRegion())
	}

	creds = fmt.Sprintf(creds, credArgs...)

	_, err = f.WriteString(creds)
	if err != nil {
		return err
	}
	_ = f.Sync()

	fmt.Fprintf(os.Stderr, "Appended profile %q to %s\n", profile, c.AWSCredentials())

	return nil
}

func (a *AWSCredentialsFile) writeConfig(c *config.Config, cfc *oaws.CredsFileCredential) error {
	filename := c.AWSCredentials()
	profile := cfc.Profile()
	if profile == "" {
		profile = c.Profile()
	}

	err := ensureConfigExists(filename, profile)
	if err != nil {
		return err
	}

	return saveProfile(filename, profile, cfc, a.LegacyAWSVariables, a.ExpiryAWSVariables, a.Expiry, c.AWSRegion())
}

func contains(ignore []string, name string) bool {
	for _, v := range ignore {
		if v == name {
			return true
		}
	}

	return false
}
