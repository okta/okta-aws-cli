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

package okta

import (
	"gopkg.in/square/go-jose.v2/jwt"
)

// ClientAssertionClaims Okta Client Assertion Claims model
type ClientAssertionClaims struct {
	Issuer   string           `json:"iss,omitempty"`
	Subject  string           `json:"sub,omitempty"`
	Audience string           `json:"aud,omitempty"`
	Expiry   *jwt.NumericDate `json:"exp,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
	ID       string           `json:"jti,omitempty"`
}
