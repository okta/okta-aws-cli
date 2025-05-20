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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	// APIErrorMessageBase base API error message
	APIErrorMessageBase = "Okta API returned an unknown error"
	// APIErrorMessageWithErrorDescription API error message with description
	APIErrorMessageWithErrorDescription = "Okta API returned an error: %s"
	// APIErrorMessageWithErrorSummary API error message with summary
	APIErrorMessageWithErrorSummary = "Okta API returned an error: %s"
	// HTTPHeaderWwwAuthenticate Www-Authenticate header
	HTTPHeaderWwwAuthenticate = "Www-Authenticate"

	// AuthorizationPendingErrorType --
	AuthorizationPendingErrorType = "authorization_pending"
	// SlowDownErrorType --
	SlowDownErrorType = "slow_down"
)

// APIError Wrapper for Okta API error
type APIError struct {
	ErrorType        string                   `json:"error"`
	ErrorDescription string                   `json:"error_description"`
	ErrorCode        string                   `json:"errorCode,omitempty"`
	ErrorSummary     string                   `json:"errorSummary,omitempty" toml:"error_description"`
	ErrorLink        string                   `json:"errorLink,omitempty"`
	ErrorID          string                   `json:"errorId,omitempty"`
	ErrorCauses      []map[string]interface{} `json:"errorCauses,omitempty"`
}

// Error String-ify the Error
func (e *APIError) Error() string {
	formattedErr := APIErrorMessageBase
	if e.ErrorDescription != "" {
		formattedErr = fmt.Sprintf(APIErrorMessageWithErrorDescription, e.ErrorDescription)
	} else if e.ErrorSummary != "" {
		formattedErr = fmt.Sprintf(APIErrorMessageWithErrorSummary, e.ErrorSummary)
	}
	if len(e.ErrorCauses) > 0 {
		var causes []string
		for _, cause := range e.ErrorCauses {
			for key, val := range cause {
				causes = append(causes, fmt.Sprintf("%s: %v", key, val))
			}
		}
		formattedErr = fmt.Sprintf("%s. Causes: %s", formattedErr, strings.Join(causes, ", "))
	}
	return formattedErr
}

// NewAPIError Constructor for Okta API error, will return nil if the response
// is not an error.
func NewAPIError(resp *http.Response) error {
	statusCode := resp.StatusCode
	if statusCode >= http.StatusOK && statusCode < http.StatusBadRequest {
		return nil
	}
	e := APIError{}
	if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) &&
		strings.Contains(resp.Header.Get(HTTPHeaderWwwAuthenticate), "Bearer") {
		for _, v := range strings.Split(resp.Header.Get(HTTPHeaderWwwAuthenticate), ", ") {
			if strings.Contains(v, "error_description") {
				_, err := toml.Decode(v, &e)
				if err != nil {
					e.ErrorSummary = "unauthorized"
				}
				return &e
			}
		}
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	copyBodyBytes := make([]byte, len(bodyBytes))
	copy(copyBodyBytes, bodyBytes)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	_ = json.NewDecoder(bytes.NewReader(copyBodyBytes)).Decode(&e)
	if statusCode == http.StatusInternalServerError {
		e.ErrorSummary += fmt.Sprintf(", x-okta-request-id=%s", resp.Header.Get("x-okta-request-id"))
	}
	return &e
}

// APIErr helper function to create and APIError pointer from a slice of bytes
func APIErr(bodyBytes []byte) (ae *APIError, err error) {
	ae = &APIError{}
	err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(ae)
	return
}
