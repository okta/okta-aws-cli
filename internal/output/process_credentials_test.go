/*
 * Copyright (c) 2026-Present, Okta, Inc.
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
	"testing"
	"time"

	"github.com/okta/okta-aws-cli/v2/internal/aws"
	"github.com/stretchr/testify/require"
)

func TestProcessCredentials(t *testing.T) {
	credsJSON := `
{
	"Version": 1,
	"AccessKeyId": "an AWS access key",
	"SecretAccessKey": "your AWS secret access key",
	"SessionToken": "the AWS session token for temporary credentials", 
	"Expiration": "2009-11-10T23:00:00Z"
}`
	result := aws.ProcessCredential{}
	err := json.Unmarshal([]byte(credsJSON), &result)
	require.NoError(t, err)
	require.Equal(t, "an AWS access key", result.AccessKeyID)
	require.Equal(t, "your AWS secret access key", result.SecretAccessKey)
	require.Equal(t, "the AWS session token for temporary credentials", result.SessionToken)
	when := time.Time(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC))
	require.Equal(t, &when, result.Expiration)
}
