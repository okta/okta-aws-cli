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
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

func debugRequest(req *http.Request) {
	if req == nil {
		return
	}
	reqData, err := httputil.DumpRequest(req, true)
	if err == nil {
		log.Printf("[DEBUG] "+logReqMsg, req.RequestURI, prettyPrintJSONLines(reqData))
	} else {
		log.Printf("[ERROR] %s API Request error: %#v", req.RequestURI, err)
	}
}

func debugResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	respData, err := httputil.DumpResponse(resp, true)
	if err == nil {
		log.Printf("[DEBUG] "+logRespMsg, resp.Request.RequestURI, prettyPrintJSONLines(respData))
	} else {
		log.Printf("[ERROR] %s API Response error: %#v", resp.Request.RequestURI, err)
	}
}

// prettyPrintJSONLines iterates through a []byte line-by-line, transforming any
// lines that are complete json into pretty-printed json.
func prettyPrintJSONLines(b []byte) string {
	parts := strings.Split(string(b), "\n")
	for i, p := range parts {
		if b := []byte(p); json.Valid(b) {
			var out bytes.Buffer
			_ = json.Indent(&out, b, "", " ")
			parts[i] = out.String()
		}
	}
	return strings.Join(parts, "\n")
}

const logReqMsg = `%s API Request Details:
---[ REQUEST ]---------------------------------------
%s
-----------------------------------------------------`

const logRespMsg = `%s API Response Details:
---[ RESPONSE ]--------------------------------------
%s
-----------------------------------------------------`

type configTransport struct {
	rt    http.RoundTripper
	debug bool
}

func newConfigTransport(debug bool) *configTransport {
	rt := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
	}
	if os.Getenv("HTTPS_PROXY") != "" || os.Getenv("HTTP_PROXY") != "" {
		rt.Proxy = http.ProxyFromEnvironment
	}

	ct := configTransport{
		rt:    rt,
		debug: debug,
	}
	return &ct
}

func (ct *configTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if ct.debug {
		debugRequest(r)
	}
	resp, err := ct.rt.RoundTrip(r)
	if ct.debug {
		debugResponse(resp)
	}

	return resp, err
}
