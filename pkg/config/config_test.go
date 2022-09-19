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
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfigVariables(t *testing.T) {
	tests := []struct {
		testName      string
		envVar        bool
		dotEnv        bool
		envVarValue   string
		dotEnvValue   string
		expectedValue string
	}{
		{
			testName:      "env-var only",
			envVar:        true,
			envVarValue:   "test1-env-var.okta.com",
			expectedValue: "test1-env-var.okta.com",
		},
		{
			testName:      ".env file only",
			dotEnv:        true,
			dotEnvValue:   "test2-dot-env.okta.com",
			expectedValue: "test2-dot-env.okta.com",
		},
		{
			testName:      ".env defers to existing env-var",
			envVar:        true,
			envVarValue:   "test3-env-var.okta.com",
			dotEnv:        true,
			dotEnvValue:   "test3-dot-env.okta.com",
			expectedValue: "test3-env-var.okta.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			beforeValue := os.Getenv("OKTA_ORG_DOMAIN")
			os.Unsetenv("OKTA_ORG_DOMAIN")
			if tt.envVar {
				os.Setenv("OKTA_ORG_DOMAIN", tt.envVarValue)
			}

			var c *Config
			var err error

			if tt.dotEnv {
				f, err := os.CreateTemp("", "test")
				require.NoError(t, err)
				defer os.Remove(f.Name())

				_, err = f.Write([]byte(fmt.Sprintf("OKTA_ORG_DOMAIN=%s", tt.dotEnvValue)))
				require.NoError(t, err)

				c, err = NewConfig(f.Name())
				require.NoError(t, err)
			}
			if tt.envVar {
				c, err = NewConfig()
				require.NoError(t, err)
			}

			require.Equal(t, tt.expectedValue, c.OrgDomain)

			if tt.envVar {
				os.Setenv("OKTA_ORG_DOMAIN", beforeValue)
			}
		})
	}
}
