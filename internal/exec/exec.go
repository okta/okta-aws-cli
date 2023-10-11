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

package exec

import (
	"fmt"
	"os"
	osexec "os/exec"
	"strings"

	oaws "github.com/okta/okta-aws-cli/internal/aws"
	"github.com/okta/okta-aws-cli/internal/utils"
)

// Exec is a executor / a process runner
type Exec struct {
	name string
	args []string
}

// NewExec Create a new executor
func NewExec() (*Exec, error) {
	args := []string{}
	foundArgs := false
	for _, arg := range os.Args {
		if arg == "--" {
			foundArgs = true
			continue
		}
		if !foundArgs {
			continue
		}

		args = append(args, arg)
	}

	if len(args) < 1 {
		return nil, fmt.Errorf("there must be at least one additional argument after the '--' CLI argument terminator")
	}

	name := args[0]
	args = args[1:]
	ex := &Exec{
		name: name,
		args: args,
	}

	return ex, nil
}

// Run Run the executor
func (e *Exec) Run(cc *oaws.CredentialContainer) error {
	pairs := map[string]string{}
	// pre-populate pairs with any existing env var starting with "AWS_"
	for _, kv := range os.Environ() {
		pair := strings.SplitN(kv, "=", 2)
		k := pair[0]
		if strings.HasPrefix(k, "AWS_") {
			pairs[k] = pair[1]
		}
	}
	// add creds env var names to pairs
	pairs["AWS_ACCESS_KEY_ID"] = cc.AccessKeyID
	pairs["AWS_SECRET_ACCESS_KEY"] = cc.SecretAccessKey
	pairs["AWS_SESSION_TOKEN"] = cc.SessionToken

	cmd := osexec.Command(e.name, e.args...)
	for k, v := range pairs {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	out, err := cmd.Output()
	if ee, ok := err.(*osexec.ExitError); ok {
		fmt.Fprintf(os.Stderr, "error running process\n")
		fmt.Fprintf(os.Stderr, "%s %s\n", e.name, strings.Join(e.args, " "))
		fmt.Fprintf(os.Stderr, utils.PassThroughStringNewLineFMT, ee.Stderr)
	}
	if err != nil {
		return err
	}

	fmt.Printf("%s", string(out))
	return nil
}
