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

package aws

import (
	"encoding/json"
	"time"
)

// CredentialContainer denormalized struct of all the values can be presented in
// the different credentials formats
type CredentialContainer struct {
	AccessKeyID     string
	Region          string
	SecretAccessKey string
	SessionToken    string
	Expiration      *time.Time
	Version         int
	Profile         string
}

// EnvVarCredential representation of an AWS credential for environment
// variables
type EnvVarCredential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// CredsFileCredential representation of an AWS credential for the AWS
// credentials file
type CredsFileCredential struct {
	AccessKeyID     string `ini:"aws_access_key_id"`
	Region          string `ini:"region"`
	SecretAccessKey string `ini:"aws_secret_access_key"`
	SessionToken    string `ini:"aws_session_token"`

	profile string
}

// SetProfile sets the profile name associated with this AWS credential.
func (c *CredsFileCredential) SetProfile(p string) { c.profile = p }

// Profile returns the profile name associated with this AWS credential.
func (c CredsFileCredential) Profile() string { return c.profile }

// ProcessCredential Convenience representation of an AWS credential used for
// process credential format.
type ProcessCredential struct {
	AccessKeyID     string     `json:"AccessKeyId,omitempty"`
	SecretAccessKey string     `json:"SecretAccessKey,omitempty"`
	SessionToken    string     `json:"SessionToken,omitempty"`
	Expiration      *time.Time `json:"Expiration,omitempty"`
	Version         int        `json:"Version,omitempty"`
}

// MarshalJSON ensure Expiration date time is formatted RFC 3339 format.
func (c *ProcessCredential) MarshalJSON() ([]byte, error) {
	type Alias ProcessCredential
	var exp string
	if c.Expiration != nil {
		exp = c.Expiration.Format(time.RFC3339)
	}

	obj := &struct {
		*Alias
		Expiration string `json:"Expiration"`
	}{
		Alias: (*Alias)(c),
	}
	if exp != "" {
		obj.Expiration = exp
	}
	return json.Marshal(obj)
}
