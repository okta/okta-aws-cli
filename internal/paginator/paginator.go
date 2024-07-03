package paginator

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	// HTTPHeaderWwwAuthenticate Www-Authenticate header
	HTTPHeaderWwwAuthenticate = "Www-Authenticate"
	// APIErrorMessageBase base API error message
	APIErrorMessageBase = "the API returned an unknown error"
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
func NewPaginator(httpClient *http.Client, url *url.URL, headers *map[string]string, params *map[string]string) *Paginator {
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
	err := checkResponseForError(resp)
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

func checkResponseForError(resp *http.Response) error {
	statusCode := resp.StatusCode
	if statusCode >= http.StatusOK && statusCode < http.StatusBadRequest {
		return nil
	}
	e := Error{}
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

// Error A struct for marshalling Okta's API error response bodies
type Error struct {
	ErrorMessage     string                   `json:"error"`
	ErrorDescription string                   `json:"error_description"`
	ErrorCode        string                   `json:"errorCode,omitempty"`
	ErrorSummary     string                   `json:"errorSummary,omitempty" toml:"error_description"`
	ErrorLink        string                   `json:"errorLink,omitempty"`
	ErrorID          string                   `json:"errorId,omitempty"`
	ErrorCauses      []map[string]interface{} `json:"errorCauses,omitempty"`
}

// Error String-ify the Error
func (e *Error) Error() string {
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
