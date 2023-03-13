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
	"testing"

	"github.com/okta/okta-aws-cli/internal/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

// TestINIFormatCredentialsContent provides a litmus test on how well
// gopkg.in/ini.v1 package renders updates to an aws credential file
// representation. The test won't fail but output a diff as a skip if our
// expections are not met.
//
// At the time this test was written the INI package would trim out extra new
// lines and dangling comments.
func TestINIFormatCredentialsContent(t *testing.T) {
	have, err := credsTemplate([]interface{}{"A", "B", "C", "D", "E", "F"})
	assert.NoError(t, err)
	want, err := credsTemplate([]interface{}{"A", "B", "C", "d", "e", "f"})
	assert.NoError(t, err)

	f, err := os.CreateTemp("", "test")
	filename := f.Name()
	defer func() {
		_ = os.Remove(filename)
	}()
	assert.NoError(t, err)
	_, err = f.Write([]byte(have))
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)

	awsCreds := &aws.Credential{
		AccessKeyID:     "d",
		SecretAccessKey: "e",
		SessionToken:    "f",
	}
	config, err := updateConfig(filename, "test", awsCreds)
	assert.NoError(t, err)

	err = config.SaveTo(filename)
	assert.NoError(t, err)
	result, err := os.ReadFile(filename)
	assert.NoError(t, err)

	got := string(result)
	if got != want {
		hr := "-------------------------"
		t.Skipf("INI package modified reflected creds beyond our expections.\nExpected:\n%s%s%s\n\nGot:\n%s\n%s%s", hr, want, hr, hr, got, hr)
	}
}

func TestINIComments(t *testing.T) {
	tests := []struct {
		name    string
		section string
		config  []byte
		want    map[string]string
	}{
		{
			name:    "default",
			section: "default",
			config: []byte(`
[default]
aws_session_token     = abc
aws_access_key_id     = def
aws_secret_access_key = ghi
`),
			want: map[string]string{
				"aws_session_token":     "abc",
				"aws_access_key_id":     "def",
				"aws_secret_access_key": "ghi",
			},
		},
		{
			name:    "obsolete variables",
			section: "default",
			config: []byte(`
[default]
aws_session_token     = abc
aws_access_key_id     = def
aws_secret_access_key = ghi
aws_security_token    = jkl
`),
			want: map[string]string{
				"aws_session_token":     "abc",
				"aws_access_key_id":     "def",
				"aws_secret_access_key": "ghi",
				"# aws_security_token":  "jkl",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := ini.Load(test.config)
			require.NoError(t, err)
			ini, err := updateINI(config, "default")
			require.NoError(t, err)
			section := ini.Section(test.section)
			require.Equal(t, len(test.want), len(section.KeyStrings()))
			for k := range test.want {
				val, err := section.GetKey(k)
				require.NoError(t, err)
				require.Equal(t, test.want[k], val.Value())
			}
		})
	}
}

func credsTemplate(vars []any) (string, error) {
	if len(vars) != 6 {
		return "", fmt.Errorf("expected 6 vars got %d", len(vars))
	}

	template := `
# comment 1

# comment 2
[default]
aws_access_key_id     = %s
# comment 3 
aws_secret_access_key = %s
aws_session_token     = %s


[test]
aws_access_key_id     = %s
aws_secret_access_key = %s
aws_session_token     = %s


# comment 4
`
	template = fmt.Sprintf(template, vars...)

	return template, nil
}
