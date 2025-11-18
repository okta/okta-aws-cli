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

package testutils

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/okta/okta-aws-cli/v2/internal/config"
	"github.com/okta/okta-aws-cli/v2/internal/utils"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

const (
	// TestDomainName Fake domain name for tests / recordings
	TestDomainName = "test.dne-okta.com"
	// ClientAssertionNameValueRE client assertion regular expression format
	ClientAssertionNameValueRE = "client_assertion=[^&]+"
	// ClientAssertionNameValueValue client asserver name and value url encoded format
	ClientAssertionNameValueValue = "client_assertion=abc123"
)

// TestClock Is a test clock of the Clock interface
type TestClock struct{}

// Now The test clock's now
func (TestClock) Now() time.Time { return time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC) }

// NewTestClock New test clock constructor
func NewTestClock() config.Clock {
	return &TestClock{}
}

// VCROktaAPIRequestHook Modifies VCR recordings.
func VCROktaAPIRequestHook(i *cassette.Interaction) error {
	// need to scrub Okta org strings and rewrite as test.dne-okta.com so that
	// HTTP requests that escape VCR are bad.

	// test.dne-okta.com
	vcrHostname := TestDomainName
	// example.okta.com
	orgHostname := os.Getenv("OKTA_AWSCLI_ORG_DOMAIN")

	// save disk space, clean up what gets written to disk
	i.Request.Headers.Del("User-Agent")
	deleteResponseHeaders := []string{
		"Cache-Control",
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"duration",
		"Expect-Ct",
		"Expires",
		"P3p",
		"Pragma",
		"Public-Key-Pins-Report-Only",
		"Server",
		"Set-Cookie",
		"Strict-Transport-Security",
		"Vary",
	}
	for _, header := range deleteResponseHeaders {
		i.Response.Headers.Del(header)
	}
	for name := range i.Response.Headers {
		// delete all X-headers
		if strings.HasPrefix(name, "X-") {
			i.Response.Headers.Del(name)
			continue
		}
	}

	// scrub client assertion out of token requests
	m := regexp.MustCompile(ClientAssertionNameValueRE)
	i.Request.URL = m.ReplaceAllString(i.Request.URL, ClientAssertionNameValueValue)

	// %s/example.okta.com/test.dne-okta.com/
	i.Request.Host = strings.ReplaceAll(i.Request.Host, orgHostname, vcrHostname)

	// %s/example.okta.com/test.dne-okta.com/
	i.Request.URL = strings.ReplaceAll(i.Request.URL, orgHostname, vcrHostname)

	// %s/example.okta.com/test.dne-okta.com/
	i.Request.Body = strings.ReplaceAll(i.Request.Body, orgHostname, vcrHostname)

	// %s/example.okta.com/test.dne-okta.com/
	i.Response.Body = strings.ReplaceAll(i.Response.Body, orgHostname, vcrHostname)

	return nil
}

// VCROktaAPIRequestMatcher Defines how VCR will match requests to responses.
func VCROktaAPIRequestMatcher(r *http.Request, i cassette.Request) bool {
	// scrub access token for lookup
	if r.URL.RawQuery != "" {
		m := regexp.MustCompile(ClientAssertionNameValueRE)
		r.URL.RawQuery = m.ReplaceAllString(r.URL.RawQuery, ClientAssertionNameValueValue)
	}
	// scrub host for lookup
	r.URL.Host = TestDomainName

	// Default matcher compares method and URL only
	if !cassette.DefaultMatcher(r, i) {
		return false
	}
	// TODO: there might be header information we could inspect to make this more precise
	if r.Body == nil {
		return true
	}

	var b bytes.Buffer
	if _, err := b.ReadFrom(r.Body); err != nil {
		log.Printf("[DEBUG] Failed to read request body from cassette: %v", err)
		return false
	}
	r.Body = io.NopCloser(&b)
	reqBody := b.String()
	// If body matches identically, we are done
	if reqBody == i.Body {
		return true
	}

	// JSON might be the same, but reordered. Try parsing json and comparing
	contentType := r.Header.Get(utils.ContentType)
	if strings.Contains(contentType, utils.ApplicationJSON) {
		var reqJSON, cassetteJSON interface{}
		if err := json.Unmarshal([]byte(reqBody), &reqJSON); err != nil {
			log.Printf("[DEBUG] Failed to unmarshall request json: %v", err)
			return false
		}
		if err := json.Unmarshal([]byte(i.Body), &cassetteJSON); err != nil {
			log.Printf("[DEBUG] Failed to unmarshall cassette json: %v", err)
			return false
		}
		return reflect.DeepEqual(reqJSON, cassetteJSON)
	}

	return true
}

// NewVCRRecorder New VCR recording settings
func NewVCRRecorder(t *testing.T, transport http.RoundTripper) (rec *recorder.Recorder, err error) {
	dir, _ := os.Getwd()
	vcrFixturesHome := path.Join(dir, "../../test/fixtures/vcr")
	cassettesPath := path.Join(vcrFixturesHome, t.Name())
	rec, err = recorder.NewWithOptions(&recorder.Options{
		CassetteName:       cassettesPath,
		Mode:               recorder.ModeRecordOnce,
		SkipRequestLatency: true, // skip how vcr will mimic the real request latency that it can record allowing for fast playback
		RealTransport:      transport,
	})
	if err != nil {
		return
	}

	rec.SetMatcher(VCROktaAPIRequestMatcher)
	rec.AddHook(VCROktaAPIRequestHook, recorder.AfterCaptureHook)

	return
}

// OsSetEnvIfBlank Set env var if its blank and return a clearing function
func OsSetEnvIfBlank(key, value string) func() {
	if os.Getenv(key) != "" {
		return func() {}
	}
	_ = os.Setenv(key, value)
	return func() {
		_ = os.Unsetenv(key)
	}
}
