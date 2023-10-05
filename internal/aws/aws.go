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

// Credential Convenience representation of an AWS credential.
type Credential struct {
	AccessKeyID     string `ini:"aws_access_key_id"     json:"AccessKeyId,omitempty"`
	SecretAccessKey string `ini:"aws_secret_access_key" json:"SecretAccessKey,omitempty"`
	SessionToken    string `ini:"aws_session_token"     json:"SessionToken,omitempty"`
}

// ProcessCredential Convenience representation of an AWS credential used for process credential format.
type ProcessCredential struct {
	Credential
	Version    int        `json:"Version,omitempty"`
	Expiration *time.Time `json:"Expiration,omitempty"`
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
