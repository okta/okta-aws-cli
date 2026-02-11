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

// Organization The well known Okta organization at GET /.well-known/okta-organization
type Organization struct {
	ID       string      `json:"id"`
	Pipeline string      `json:"pipeline"`
	Links    interface{} `json:"_links,omitempty"`
	Settings interface{} `json:"settings,omitempty"`
}
