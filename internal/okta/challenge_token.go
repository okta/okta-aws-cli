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

package okta

// ChallengeToken Encapsulates Okta API response for the OOB MFA Challenge
// Response Token from /oauth2/{authzID}/v1/challenge
// https://developer.okta.com/docs/guides/configure-direct-auth-grants/dmfaoobov/main/#challenge-response
type ChallengeToken struct {
	ChallengeType string `json:"challenge_type"`
	OOBCode       string `json:"oob_code"`
	ExpiresIn     int    `json:"expires_in"`
	Interval      int    `json:"interval"`
	Channel       string `json:"push"`
	BindingMethod string `json:"binding_method"`
	BindingCode   string `json:"binding_code"`
}
