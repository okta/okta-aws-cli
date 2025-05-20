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

package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/okta/okta-aws-cli/internal/config"
	"github.com/okta/okta-aws-cli/internal/okta"
)

const (
	// ContentType http header content type
	ContentType = "Content-Type"
	// ApplicationJSON  content value for json
	ApplicationJSON = "application/json"
	// ApplicationXFORM content type value for web form
	ApplicationXFORM = "application/x-www-form-urlencoded"
	// UserAgentHeader user agent header
	UserAgentHeader = "User-Agent"
	// XOktaAWSCLIOperationHeader the okta aws cli header
	XOktaAWSCLIOperationHeader = "X-Okta-Aws-Cli-Operation"
	// XOktaAWSCLIDirectOperation direct op value for the x okta aws cli header
	XOktaAWSCLIDirectOperation = "direct"
	// XOktaAWSCLIWebOperation web op value for the x okta aws cli header
	XOktaAWSCLIWebOperation = "web"
	// XOktaAWSCLIM2MOperation m2m op value for the x okta aws cli header
	XOktaAWSCLIM2MOperation = "m2m"
	// PassThroughStringNewLineFMT string formatter to make lint happy
	PassThroughStringNewLineFMT = "%s\n"

	// AccessKeyID AWS creds access key ID
	AccessKeyID = "AccessKeyID"
	// Region region
	Region = "Region"
	// SecretAccessKey AWS creds secret access key
	SecretAccessKey = "SecretAccessKey"
	// SessionToken AWS creds session token
	SessionToken = "SessionToken"

	// DefaultAuthzID The default authorization server id
	DefaultAuthzID = "default"
	// Accept HTTP Accept header
	Accept = "Accept"
	// DotOktaDir The dot dirctory for Okta apps
	DotOktaDir = ".okta"
	// AccessTokenFileName file name of where the cached access token is places
	AccessTokenFileName = "awscli-access-token.json"
)

// CachedAccessTokenPath Path to the cached access token in $HOME/.okta/awscli-access-token.json
func CachedAccessTokenPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, DotOktaDir, AccessTokenFileName), nil
}

// CacheAccessToken will cache the access token for later use if enabled. Silent
// if fails.
func CacheAccessToken(cfg *config.Config, at *okta.AccessToken) {
	if !cfg.CacheAccessToken() {
		return
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	oktaDir := filepath.Join(homeDir, DotOktaDir)
	// noop if dir exists
	err = os.MkdirAll(oktaDir, 0o700)
	if err != nil {
		return
	}

	atJSON, err := json.Marshal(at)
	if err != nil {
		return
	}

	configPath := filepath.Join(homeDir, DotOktaDir, AccessTokenFileName)
	_ = os.WriteFile(configPath, atJSON, 0o600)
}

// CachedAccessToken will returned the cached access token if it exists and is
// not expired and --cached-access-token is enabled.
func CachedAccessToken(cfg *config.Config) (at *okta.AccessToken) {
	if !cfg.CacheAccessToken() {
		return
	}

	accessTokenPath, err := CachedAccessTokenPath()
	if err != nil {
		return
	}
	atJSON, err := os.ReadFile(accessTokenPath)
	if err != nil {
		return
	}

	_at := okta.AccessToken{}
	err = json.Unmarshal(atJSON, &_at)
	if err != nil {
		return
	}

	expiry, err := time.Parse(time.RFC3339, _at.Expiry)
	if err != nil {
		return
	}
	if expiry.Before(time.Now()) {
		// expiry is in the past
		return
	}

	return &_at
}
