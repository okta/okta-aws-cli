/**
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

package config

import (
	"net/http"
	"time"

	flag "github.com/spf13/pflag"
)

// Version The version of the CLI
var Version = "0.0.1"

// Config A config object for the CLI
type Config struct {
	OrgDomain  string
	OidcAppID  string
	FedAppID   string
	Format     string
	Profile    string
	HTTPClient *http.Client
}

// NewConfig Creates a new config
func NewConfig(orgDomain, oidcAppID, fedAppID, format *flag.Flag, profile *flag.Flag) *Config {
	tr := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Second * time.Duration(60),
	}

	return &Config{
		OrgDomain:  orgDomain.Value.String(),
		OidcAppID:  oidcAppID.Value.String(),
		FedAppID:   fedAppID.Value.String(),
		Format:     format.Value.String(),
		Profile:    profile.Value.String(),
		HTTPClient: httpClient,
	}
}
