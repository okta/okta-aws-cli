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
	"os"
	"runtime"

	oaws "github.com/okta/okta-aws-cli/v2/internal/aws"
	"github.com/okta/okta-aws-cli/v2/internal/config"
)

// EnvVar Environment Variable output formatter
type EnvVar struct {
	LegacyAWSVariables bool
}

// NewEnvVar Creates a new EnvVar
func NewEnvVar(legacyVars bool) *EnvVar {
	return &EnvVar{
		LegacyAWSVariables: legacyVars,
	}
}

// Output Satisfies the Outputter interface and outputs AWS credentials as shell
// export statements to STDOUT
func (e *EnvVar) Output(c *config.Config, cc *oaws.CredentialContainer) error {
	evc := &oaws.EnvVarCredential{
		AccessKeyID:     cc.AccessKeyID,
		SecretAccessKey: cc.SecretAccessKey,
		SessionToken:    cc.SessionToken,
	}
	c.Logger.Warn("\n")
	if os.Getenv("PSModulePath") != "" {
		// we're on powershell.
		c.Logger.Info("$Env:AWS_ACCESS_KEY_ID = \"%s\"\n", evc.AccessKeyID)
		c.Logger.Info("$Env:AWS_SECRET_ACCESS_KEY = \"%s\"\n", evc.SecretAccessKey)
		c.Logger.Info("$Env:AWS_SESSION_TOKEN = \"%s\"\n", evc.SessionToken)
		if e.LegacyAWSVariables {
			c.Logger.Info("$Env:AWS_SECURITY_TOKEN = \"%s\"\n", evc.SessionToken)
		}
	} else if runtime.GOOS == "windows" {
		c.Logger.Info("setx AWS_ACCESS_KEY_ID %s\n", evc.AccessKeyID)
		c.Logger.Info("setx AWS_SECRET_ACCESS_KEY %s\n", evc.SecretAccessKey)
		c.Logger.Info("setx AWS_SESSION_TOKEN %s\n", evc.SessionToken)
		if e.LegacyAWSVariables {
			c.Logger.Info("setx AWS_SECURITY_TOKEN %s\n", evc.SessionToken)
		}
	} else {
		c.Logger.Info("export AWS_ACCESS_KEY_ID=%s\n", evc.AccessKeyID)
		c.Logger.Info("export AWS_SECRET_ACCESS_KEY=%s\n", evc.SecretAccessKey)
		c.Logger.Info("export AWS_SESSION_TOKEN=%s\n", evc.SessionToken)
		if e.LegacyAWSVariables {
			c.Logger.Info("export AWS_SECURITY_TOKEN=%s\n", evc.SessionToken)
		}
	}

	return nil
}
