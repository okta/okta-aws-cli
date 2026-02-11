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

package paginator

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/okta/okta-aws-cli/v2/internal/okta"
)

const (
	// HTTPHeaderWwwAuthenticate Www-Authenticate header
	HTTPHeaderWwwAuthenticate = "Www-Authenticate"
	// APIErrorMessageWithErrorDescription API error message with description
	APIErrorMessageWithErrorDescription = "the API returned an error: %s"
	// APIErrorMessageWithErrorSummary API error message with summary
	APIErrorMessageWithErrorSummary = "the API returned an error: %s"
)

// PaginateResponse HTTP Response wrapper for behavior the the Paginator
type PaginateResponse struct {
	*http.Response
	pgntr    *Paginator
	Self     string
	NextPage string
}

// HasNextPage Paginate response has a next page
func (r *PaginateResponse) HasNextPage() bool {
	return r.NextPage != ""
}

// Next Paginate response to call for next page
func (r *PaginateResponse) Next(v interface{}) (*PaginateResponse, error) {
	req, err := http.NewRequest(http.MethodGet, r.NextPage, nil)
	for k, v := range *r.pgntr.headers {
		req.Header.Add(k, v)
	}
	if err != nil {
		return nil, err
	}
	return r.pgntr.Do(req, v)
}

// Paginator Paginates Okta's API response Link(s)
type Paginator struct {
	httpClient *http.Client
	url        *url.URL
	headers    *map[string]string
	params     *map[string]string
}

// NewPaginator Paginator constructor
func NewPaginator(httpClient *http.Client, url *url.URL, headers, params *map[string]string) *Paginator {
	pgntr := Paginator{
		httpClient: httpClient,
		url:        url,
		headers:    headers,
		params:     params,
	}
	return &pgntr
}

// Do Paginator does an HTTP request
func (pgntr *Paginator) Do(req *http.Request, v interface{}) (*PaginateResponse, error) {
	resp, err := pgntr.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return buildPaginateResponse(resp, pgntr, &v)
}

// GetItems Paginator gets an array of items of type v
func (pgntr *Paginator) GetItems(v interface{}) (resp *PaginateResponse, err error) {
	params := url.Values{}
	if pgntr.params != nil {
		for k, v := range *pgntr.params {
			params.Add(k, v)
		}
	}
	pgntr.url.RawQuery = params.Encode()

	req, err := http.NewRequest(http.MethodGet, pgntr.url.String(), nil)
	if err != nil {
		return
	}
	for k, v := range *pgntr.headers {
		req.Header.Add(k, v)
	}

	resp, err = pgntr.Do(req, v)
	return
}

func newPaginateResponse(r *http.Response, pgntr *Paginator) *PaginateResponse {
	response := &PaginateResponse{Response: r, pgntr: pgntr}
	links := r.Header["Link"]

	if len(links) == 0 {
		return response
	}
	for _, link := range links {
		splitLinkHeader := strings.Split(link, ";")
		if len(splitLinkHeader) < 2 {
			continue
		}
		linkStr := strings.TrimRight(strings.TrimLeft(splitLinkHeader[0], "<"), ">")
		if urlURL, err := url.Parse(linkStr); err == nil {
			if r.Request != nil {
				q := r.Request.URL.Query()
				for k, v := range urlURL.Query() {
					q.Set(k, v[0])
				}
				urlURL.RawQuery = q.Encode()
			}
			if strings.Contains(link, `rel="self"`) {
				response.Self = urlURL.String()
			}
			if strings.Contains(link, `rel="next"`) {
				response.NextPage = urlURL.String()
			}
		}
	}

	return response
}

func buildPaginateResponse(resp *http.Response, pgntr *Paginator, v interface{}) (*PaginateResponse, error) {
	ct := resp.Header.Get("Content-Type")
	response := newPaginateResponse(resp, pgntr)
	err := okta.NewAPIError(resp)
	if err != nil {
		return response, err
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	copyBodyBytes := make([]byte, len(bodyBytes))
	copy(copyBodyBytes, bodyBytes)
	_ = resp.Body.Close()                                // close it to avoid memory leaks
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // restore the original response body
	if len(copyBodyBytes) == 0 {
		return response, nil
	}
	switch {
	case strings.Contains(ct, "application/xml"):
		err = xml.NewDecoder(bytes.NewReader(copyBodyBytes)).Decode(v)
	case strings.Contains(ct, "application/json"):
		err = json.NewDecoder(bytes.NewReader(copyBodyBytes)).Decode(v)
	case strings.Contains(ct, "application/octet-stream"):
		// since the response is arbitrary binary data, we leave it to the user to decode it
		return response, nil
	default:
		return nil, errors.New("could not build a response for type: " + ct)
	}
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return response, nil
}
