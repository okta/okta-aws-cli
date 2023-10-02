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

package aws

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCredentialJSON(t *testing.T) {
	hbtGo := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	c := Credential{
		Expiration: &hbtGo,
	}
	credStr, err := json.Marshal(c)
	require.NoError(t, err)
	require.Equal(t, `{"Expiration":"2009-11-10T23:00:00Z"}`, string(credStr))
}
