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

// Application Okta API application object.
// See: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/#tag/Application/operation/listApplications
type Application struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Settings struct {
		App struct {
			IdentityProviderARN string `json:"identityProviderArn"`
			WebSSOClientID      string `json:"webSSOAllowedClient"`
		} `json:"app"`
	} `json:"settings"`
}

// ApplicationLink Okta API application link object.
// See: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listAppLinks
type ApplicationLink struct {
	ID    string `json:"appInstanceId"`
	Label string `json:"label"`
	Name  string `json:"appName"`
}
