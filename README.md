# okta-aws-cli

**NOTE**: *Some environment variable names changed with the v2.0.0 release of
`okta-aws-cli`; double check your existing named variables in the [configuration
documentation](#configuration).*

`okta-aws-cli` is a CLI program allowing Okta to act as an identity provider and
retrieve AWS IAM temporary credentials for use in AWS CLI, AWS SDKs, and other
tools accessing the AWS API. It has two primary commands:

- `web` - combined human and device authorization
- `m2m` -  headless authorization

```shell
 # *nix, export statements
$ okta-aws-cli web --oidc-client-id 0oabc --aws-acct-fed-app-id 0oaxy --org-domain my-org.okta.com
export AWS_ACCESS_KEY_ID=ASIAUJHVCS6UQC52NOL7
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...

rem Windows setx statements
C:\> okta-aws-cli web --oidc-client-id 0oabc --aws-acct-fed-app-id 0oaxy --org-domain my-org.okta.com
SETX AWS_ACCESS_KEY_ID ASIAUJHVCS6UQC52NOL7
SETX AWS_SECRET_ACCESS_KEY wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SETX AWS_SESSION_TOKEN AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...

```

The result of both the `web` and `m2m` operations is to secure and emit [IAM temporary
credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html).
The credentials have three different output formats that are chosen by the user:
[environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html),
AWS [credentials
file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html),
or JSON [process
credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)
format.

## Table of Contents

 - [Commands](#commands)
 - [Web Command](#web-command)
   - [Web Command Requirements](#web-command-requirements)
     - [Multiple AWS environments](#multiple-aws-environments)
     - [Non-Admin Users](#non-admin-users)
 - [M2M Command](#m2m-command)
   - [M2M Command Requirements](#m2m-command-requirements)
 - [List-Profiles Command](#list-profiles-command)
 - [Configuration](#configuration)
   - [Global settings](#global-settings)
   - [Web command settings](#web-command-settings)
   - [M2M command settings](#m2m-command-settings)
   - [Friendly IdP and Role menu labels](#friendly-idp-and-role-menu-labels)
   - [Configuration by profile name](#configuration-by-profile-name)
 - [Debug okta.yaml](#debug-oktayaml)
 - [Installation](#installation)
 - [Recommendations](#recommendations)
 - [Operation](#operation)
 - [Comparison](#comparison)
 - [Development](#development)
 - [Contributing](#contributing)
 - [References](#references)

## Commands

| Command | Description |
|-----|-----|
| (empty) | When `okta-aws-cli` is executed without a subcommand **and** without arguments it will print the online help and exit. With arguments it defaults to the `web` command. |
| `web` | Human oriented retrieval of temporary IAM credentials through Okta authentication and device authorization. |
| `m2m` | Machine/headless oriented retrieval of temporary IAM credentials through Okta authentication with a private key. **IMPORTANT!** This a not a feature intended for a human use case. Be sure to use industry state of the art secrets management techniques with the private key. |
| `list-profiles` | Lists profile names in ~/.okta/okta.yaml. |
| `debug` | Debug okta.yaml config file and exit. |

## Web Command

```shell
$ okta-aws-cli web --oidc-client-id 0oabc --aws-acct-fed-app-id 0oaxy --org-domain my-org.okta.com
export AWS_ACCESS_KEY_ID=ASIAUJHVCS6UQC52NOL7
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...
```

Web command is the human oriented device authorization mode. The user executes
`okta-aws-cli web` to retrieve an authorization URL. The user can copy/paste the
URL into a web browser, have the CLI open a web browser, or have the CLI print a
QR code that can be scanned by a handset to open a web browser there. After the
human completes the authorization flow in a browser they return to the CLI to
complete the process of retrieving AWS credentials.

Web command is an integration that pairs an Okta [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) with an
[Okta AWS Federation integration
application](https://www.okta.com/integrations/aws-account-federation/). In turn
the Okta AWS Fed app is itself paired with an [AWS IAM identity
provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create.html).
The Okta AWS Fed app is SAML based and the Okta AWS CLI interacts with AWS IAM
using
[AssumeRoleWithSAML](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html)
via AWS STS.

After the CLI has presented its SAML assertion to AWS STS it collects a proper
IAM role for the AWS CLI operator. The resulting output is a set made up of
`Access Key ID`, `Secret Access Key`, and `Session Token` of [AWS
credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
for the AWS CLI. The Okta AWS CLI expresses the AWS credentials as [environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html),
or appended (or overwrites existing values) to an AWS CLI [credentials
file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html),
or emits JSON in [process
credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)
format.

The `Session Token` has a default expiry of 60 minutes.

**IMPORTANT!** The Okta AWS Federation Application does not work in a headless
environment; it only operates with a human performing authorization in a web
browser.

### Web Command Requirements

For web command the Okta AWS CLI requires an OIE organization and an [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) paired with
an [Okta AWS Federation integration
application](https://www.okta.com/integrations/aws-account-federation/). The
Okta AWS Fed app is itself paired with an [AWS IAM identity
provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create.html).

The OIDC Native Application requires Grant Types `Authorization Code`, `Device
Authorization` , and `Token Exchange`. These settings are in the Okta Admin UI
at `Applications > [the OIDC app] > General Settings > Grant type`.

If [Multiple AWS environments](#multiple-aws-environments) (alleviates the need
for use of the `--aws-acct-fed-app-id` argument) are to be supported by
a single OIDC application, the OIDC app must have the `okta.apps.read` grant
for admin users and `okta.users.read.self` for non-admin users. Application
grants are configured at `Applications > [the OIDC app] > Okta API Scopes` in
the Okta Admin UI.
 
The pairing with the AWS Federation Application is achieved in the Fed app's
Sign On Settings. These settings are in the Okta Admin UI at `Applications > [the
AWS Fed app] > Sign On`. There are two values that need to be set on the Sign On
form. The first is the `Allowed Web SSO Client` value which is the Client ID of
the OIDC Native Application. The second is `Identity Provider ARN (Required only
for SAML SSO)` value which is the AWS ARN of the associated IAM Identity
Provider.

Okta has a wizard to help establish the settings needed in AWS IAM, automatic
generation of a SAML certificate for the IAM Identity Provider, and the settings
needed for the Okta AWS Federation app. Replace these required values in the
URL below. Then follow the directions in that wizard.

* Org Admin Domain - [ADMIN_DOMAIN] - example: `myorg-admin.okta.com`
* Okta AWS Federation app Client ID - [CLIENT_ID] - example: `0oa555555aaaaaaZZZZZ`

`https://saml-doc.okta.com/SAML_Docs/How-to-Configure-SAML-2.0-for-Amazon-Web-Service.html?baseAdminUrl=https://[ADMIN_DOMAIN]&app=amazon_aws&instanceId=[CLIENT_ID]`

#### Multiple AWS environments

To support multiple AWS environments, associate additional AWS Federation
applications with an OIDC app. The OIDC app **must** have the `okta.apps.read`
grant to support admin users. To support non-admin users the OIDC app **must**
have the `okta.users.read.self` grant. The following is an illustration of the
association of objects that make up this kind of configuration.

![okta-aws-cli supporting multiple AWS environments](./doc/multi-aws-environments.jpg)

The example diagram reflects the following:

* All AWS Federation apps have the OIDC native app as their Allowed Web SSO client
* Fed App #1 is linked with an IAM IdP that has two Roles, one for S3 read, and one for S3 read/write
* Fed App #2 is linked to an IdP and Role dedicated to ec2 operations
* Fed App #3 is oriented for an administrator is comprised of an IdP and Role with many different permissions

##### Multiple AWS environments for Non-Admin Users

The multiple AWS environments feature will work for non-admin users if the
OIDC Native app is granted the`okta.users.read.self` scope and the user is
assigned to the OIDC Native app and assigned to each Okta AWS Federation app.
The API endpoint `GET /api/v1/users/me/appLinks` is referenced to discover
which applications are assigned to the non-admin user.

**IMPORTANT!!!**

Below is a deprecated recommendation for non-admin users. We are leaving it in
the README for legacy purposes. We are no longer recommending this workaround so
long as the OIDC app is granted the `okta.users.read.self` scope.

**OLD work around for non-admin users**

Multiple AWS environments requires extra configuration for non-admin users.
Follow these steps to support non-admin users.

1) Create a custom admin role with the only permission being "View application
and their details", and a resource set constrained to "All AWS Account
Federation apps".

2) Create a group that will contain the AWS custom admin role users.

3) Add a rule on the admin console authentication policy that denies access if
the use is a member of the group from step 2.

4) Assign non-admin users this custom role in step 1 and assign them to the
group in step 2.

The "Admin" button will be visible on the Okta dashboard of non-admin users but
they will receive a 403 if they attempt to open the Admin UI.

## M2M Command

***IMPORTANT! This a not a feature intended for a human use case. Be sure to
use industry state of the art secrets management techniques with the private
key.***

```shell
# This example presumes its arguments are set as environment variables such as
# one may find in a headless CI environment.
# e.g.
# export OKTA_AWSCLI_ORG_DOMAIN="my-org.oka.com"
# export OKTA_AWSCLI_OIDC_CLIENT_ID="0oaa4htg72TNrkTDr1d7"
# export OKTA_AWSCLI_IAM_ROLE="arn:aws:iam::1234:role/Circle-CI-ops"
# export OKTA_AWSCLI_CUSTOM_SCOPE="okta-m2m-access"
# export OKTA_AWSCLI_KEY_ID="kid-rock"
# export OKTA_AWSCLI_PRIVATE_KEY="... long string with new lines ..."
# export OKTA_AWSCLI_AUTHZ_ID="aus8w23r13NvyUwln1d7"

$ okta-aws-cli m2m
export AWS_ACCESS_KEY_ID=ASIAUJHVCS6UQC52NOL7
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...
```

M2M command is headless machine to machine authorization. The operator executes
`okta-aws-cli m2m` which has access to a private key whose public key is
registered in an Okta API service application. `okta-aws-cli m2m` signs a
request for an Okta access token that is associated with the Okta service
application. Given the Okta authorization (default or custom) server returns an
access token, the access token is presented to AWS STS using
[AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html).
AWS and Okta communicate directly by OIDC protocol to confirm authorization for
IAM credentials.

Given access is granted by AWS the result of `okta-aws-cli m2m` is a set made up
of `Access Key ID`, `Secret Access Key`, and `Session Token` of [AWS
credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
for the AWS CLI. The Okta AWS CLI expresses the AWS credentials as [environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html),
or appended (or overwrites existing values) to an AWS CLI [credentials
file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html),
or emits JSON in [process
credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)
format.

The `Session Token` has a default expiry of 60 minutes.

### M2M Command Requirements

M2M is an integration of:

- [Okta API service app](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)
- Okta default or [custom](https://developer.okta.com/docs/guides/customize-authz-server/main/) authorization server with a custom scope
- [Okta access policy](https://developer.okta.com/docs/guides/configure-access-policy/main/) associated with the service app and have rule(s) for the client credentials flow
- [AWS IAM OpenID Connect (OIDC) identity provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

#### Okta Service Application

The Okta API services app requires "Public key / Private key" for "Client
authentication". This is set at `Applications > [the API services app] > General
Settings > Client Credentials`. In the "Public Keys" section select "Add Key"
then either add your own public key in JWKS format, or have Okta generate a new
key pair and copy the PEM formatted private key. Where ever the private key
resides it needs to be available to `okta-aws-cli m2m` at runtime; for instance
injected as an environment variable from a secrets manager / vault.

#### Okta Authorization Server

Follow these steps for a custom authorization server, `okta-aws-cli` will
utilize the default authorization server otherwise.

Okta custom authorization servers are available in Developer Edition orgs. For
production orgs the Workforce Identity SKU "API Access Management" needs to be
[requested for the
org](https://developer.okta.com/docs/guides/customize-authz-server/main/#about-the-authorization-server)
if it doesn't already have the feature enabled.

Custom authorization servers are set in the Admin UI at `Security > API` and
select "Add Authorization Server". The "Audience" value needs to be set to
something URL-like, for instance "https://my-project-name". Audience will be
referenced later in the AWS IAM OIDC Identity Provider settings.

#### Okta Custom Scope

A [custom Okta
scope](https://support.okta.com/help/s/article/Creating-a-Scope-for-an-Authorization-Server-in-Okta)
needs to be set on the authorization server. This is at `Security > API > [the
authorization server] > Scopes` and choose "Add Scope". `okta-aws-cli` will
assume the scope is named `okta-m2m-access`, but if it isn't the CLI flag
`--custom-scope` argument trains the CLI for the scope to use.

#### Okta Access Policy

On the authorization server panel select "Access Policies" this is at
`Security > API > [the server] > Access Policies`. Then select
"Add New Access Policy", give it a name and description. Also, select "Assign
to" > "The following clients" and assign to the established Okta service app.
Save the policy.

On the new access policy select "Add rule" and give it a descriptive name, for
instance "Client Credentials Client acting on behalf of itself". Give the rule
the parameters "IF Grant type is" / "Client acting on behalf of itself" and
select "Client Credentials". Then "AND User is", assign your user(s) preference.
Finally, "AND Scopes requested" / "The following scopes", choose the custom
scope created. The CLI defaults to custom scope named `okta-m2m-acces` otherwise
the `--custom-scope` CLI flag is required at runtime specify the name. Save the
rule.

#### AWS IAM OIDC IdP

From the AWS Console, in the IAM panel, select "Identity providers". Then click
"Add provider". In the add provider form select "OpenID Connect". Set the
"Provider URL" to the issuer URL from the Okta API Authorization Servers list
for your custom authorization server (example: `https://[your
org].okta.com/oauth2/[custom auth server id or 'default']`). Set the "Audience"
value from the "Audience" value listed for the authorization server in the Okta
panel.

After the IdP is created note it's ARN value. Any IAM roles that need to be
associated with the IdP need to have a trust relationship established on the
role of the `sts:AssumeRoleWithWebIdentity` action type. This setting is on the
trust relationship tab when viewing a specific role in the AWS Console. Also
note the ARNs of these roles for later use.

## List-Profiles Command

```shell
$ okta-aws-cli list-profiles
Profiles:

 sample-account X(Non-Prod)
 sample-account X (Prod)
 another-sample-account Y (Non-Prod)
```

List-profiles command is a human oriented command to show the list of profile names stored in the ~/.okta/okta.yaml file.  The user
executes `okta-aws-cli list-profiles` where a list of profile name shall be listed for convenience.  The names will be indented.

## Configuration
### Global settings

**NOTE**: If your AWS IAM IdP is in a non-commercial region, such as GovCloud,
the environmental variable
[`AWS_REGION`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
should be set
[accordingly](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-region).

At a minimum the Okta AWS CLI requires three configuration values. These are the
values for the [Okta Org
domain](https://developer.okta.com/docs/guides/find-your-domain/main/), the
client ID of the [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso), and the ID
of the [Okta AWS Federation integration
application](https://www.okta.com/integrations/aws-account-federation/). For the
`web` command, when support for multiple AWS environments has been configured
the AWS Fed app ID becomes optional.

An optional output format value can be configured. Default output format is as
[environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
that can be used for the AWS CLI configuration. Output can also be expressed as
[AWS credential file
values](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
or JSON [process
credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)
format.

Configuration can be done with command line flags, environment variables, an
`.env` file, or a combination of the three. The first value found in that
evaluation order takes precedent.

**NOTE**: If
[`AWS_REGION`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
is set in the `.env` file it will be promoted into the okta-aws-cli runtime if
it isn't also already set as an ENV VAR. This will allow operators making use of
an `.env` file to have proper AWS API behavior in specific regions, for instance
in US govcloud and other non-North America regions.

Also see the CLI's online help `$ okta-aws-cli --help`

These global settings are optional unless marked otherwise:

| Name | Description | Command line flag | ENV var and .env file value |
|-----|-----|-----|-----|
| AWS Region (**optional**) | AWS region (will override ENV VAR `AWS_REGION` and `AWS_DEFAULT_REGION`) e.g. `us-east-2` | `--aws-region [value]` | `OKTA_AWSCLI_AWS_REGION` |
| Okta Org Domain (**required**) | Full host and domain name of the Okta org e.g. `my-org.okta.com` or the custom domain value | `--org-domain [value]` | `OKTA_AWSCLI_ORG_DOMAIN` |
| OIDC Client ID (**required**) | For `web` the OIDC native application / [Allowed Web SSO Client ID](#allowed-web-sso-client-id), for `m2m` the API services app ID | `--oidc-client-id [value]` | `OKTA_AWSCLI_OIDC_CLIENT_ID` |
| AWS IAM Role ARN (**optional** for `web`, **required** for `m2m`) | For web preselects the role list to this preferred IAM role for the given IAM Identity Provider. For `m2m` | `--aws-iam-role [value]` | `OKTA_AWSCLI_IAM_ROLE` |
| AWS Session Duration | The lifetime, in seconds, of the AWS credentials. Must be between 60 and 43200. | `--session-duration [value]` | `OKTA_AWSCLI_SESSION_DURATION` |
| Output format | Default is `env-var`. Options: `env-var` for output to environment variables, `aws-credentials` for output to AWS credentials file, `process-credentials` for credentials as JSON, or `noop` for no output which can be useful with `--exec` | `--format [value]` | `OKTA_AWSCLI_FORMAT` |
| Profile | Default is `default` | `--profile [value]` | `OKTA_AWSCLI_PROFILE` |
| Cache Okta access token at `$HOME/.okta/awscli-access-token.json` to reduce need to open device authorization URL | `true` if flag is present | `--cache-access-token` | `OKTA_AWSCLI_CACHE_ACCESS_TOKEN=true` |
| Alternate AWS credentials file path | Path to alternative credentials file other than AWS CLI default | `--aws-credentials` | `OKTA_AWSCLI_AWS_CREDENTIALS` |
| (Over)write the given profile to the AWS credentials file. WARNING: When enabled, overwriting can inadvertently remove dangling comments and extraneous formatting from the creds file. | `true` if flag is present | `--write-aws-credentials` | `OKTA_AWSCLI_WRITE_AWS_CREDENTIALS=true` |
| Emit deprecated AWS variable `aws_security_token` with duplicated value from `aws_session_token`. AWS CLI removed any reference and documentation for `aws_security_token` in November 2014. | `true` if flag is present | `--legacy-aws-variables` | `OKTA_AWSCLI_LEGACY_AWS_VARIABLES=true` |
| Emit expiry timestamp `x_security_token_expires` in RFC3339 format for the session/security token (AWS credentials file only). This is a non-standard profile variable. | `true` if flag is present | `--expiry-aws-variables` | `OKTA_AWSCLI_EXPIRY_AWS_VARIABLES=true` |
| Print operational information to the screen for debugging purposes | `true` if flag is present | `--debug` | `OKTA_AWSCLI_DEBUG=true` |
| Verbosely print all API calls/responses to the screen | `true` if flag is present | `--debug-api-calls` | `OKTA_AWSCLI_DEBUG_API_CALLS=true` |
| HTTP/HTTPS Proxy support | HTTP/HTTPS URL of proxy service (based on golang [net/http/httpproxy](https://pkg.go.dev/golang.org/x/net/http/httpproxy) package) | n/a | `HTTP_PROXY` or `HTTPS_PROXY` |
| Execute arguments after CLI arg terminator `--` as a separate process. Process will be executed with AWS cred values as AWS env vars `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`. | `true` if flag is present | `--exec` | `OKTA_AWSCLI_EXEC=true` |


### Web command settings

If the OIDC Native App doesn't also have the `okta.apps.read` grant (for admin
users) or the `okta.users.read.self` grant (for non-admin users) the client ID
of the [Okta AWS
Federation](https://www.okta.com/integrations/aws-account-federation/)
integration application is also required.

These settings are all optional:

| Name | Description | Command line flag | ENV var and .env file value |
|-----|-----|-----|-----|
| Okta AWS Account Federation integration app ID | See [AWS Account Federation integration app](#aws-account-federation-integration-app). This value is only required if the CLI is not running for multiple AWS environments | `--aws-acct-fed-app-id [value]` | `OKTA_AWSCLI_AWS_ACCOUNT_FEDERATION_APP_ID` |
| AWS IAM Identity Provider ARN | Preselects the IdP list to this preferred IAM Identity Provider. If there are other IdPs available they will not be listed. | `--aws-iam-idp [value]` | `OKTA_AWSCLI_IAM_IDP` |
| Display QR Code | `true` if flag is present | `--qr-code` | `OKTA_AWSCLI_QR_CODE=true` |
| Automatically open the activation URL with the system web browser | `true` if flag is present | `--open-browser` | `OKTA_AWSCLI_OPEN_BROWSER=true` |
| Automatically open the activation URL with the given web browser command | Shell escaped browser command | `--open-browser-command [command]` | `OKTA_AWSCLI_OPEN_BROWSER_COMMAND` |
| Gather all profiles for all IdPs and Roles associated with an AWS Fed App (implies aws-credentials file output format)) | `true` if flag is present | `--all-profiles` | `OKTA_AWSCLI_OPEN_BROWSER=true` |

#### Allowed Web SSO Client ID

This is the "Allowed Web SSO Client" value from the "Sign On" settings of an
[AWS Account
Federation"](https://www.okta.com/integrations/aws-account-federation/)
integration app and is an Okta [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) ID. The ID
is the identifier of the client is Okta app acting as the IdP for AWS.

Example: `0oa5wyqjk6Wm148fE1d7`

#### AWS Account Federation integration app

ID for the [AWS Account
Federation"](https://www.okta.com/integrations/aws-account-federation/)
integration app.

Example: `0oa9x1rifa2H6Q5d8325`


#### Environment variables example

```shell
export OKTA_AWSCLI_ORG_DOMAIN=my-org.okta.com
export OKTA_AWSCLI_OIDC_CLIENT_ID=0oa5wyqjk6Wm148fE1d7
```

#### `.env` file variables example

```
OKTA_AWSCLI_ORG_DOMAIN=my-org.okta.com
OKTA_AWSCLI_OIDC_CLIENT_ID=0oa5wyqjk6Wm148fE1d7
```

#### Command line flags example

##### OIDC client has `okta.apps.read` grant

```shell

$ okta-aws-cli web --org-domain my-org.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
```

#### OIDC client **does not** have `okta.apps.read` grant (admins) or `okta.users.read.self` grant (non-admins)
```shell

$ okta-aws-cli web --org-domain my-org.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --aws-acct-fed-app-id 0oa9x1rifa2H6Q5d8325
```

### M2M command settings

These settings are optional unless marked otherwise:

| Name | Description | Command line flag | ENV var and .env file value |
|-----|-----|-----|-----|
| Key ID (kid) (**required**) | The ID of the key stored in the service app | `--key-id [value]` | `OKTA_AWSCLI_KEY_ID` |
| Private Key (**required** in lieu of private key file) | PEM (pkcs#1 or pkcs#9) private key whose public key is stored on the service app | `--private-key [value]` | `OKTA_AWSCLI_PRIVATE_KEY` |
| Private Key File (**required** in lieu of private key) | File holding PEM (pkcs#1 or pkcs#9) private key whose public key is stored on the service app | `--private-key-file [value]` | `OKTA_AWSCLI_PRIVATE_KEY_FILE` |
| Authorization Server ID | The ID of the Okta authorization server, set ID for a custom authorization server, will use default otherwise. Default `default` | `--authz-id [value]` | `OKTA_AWSCLI_AUTHZ_ID` |
| Custom scope name | The custom scope established in the custom authorization server. Default `okta-m2m-access` | `--custom-scope [value]` | `OKTA_AWSCLI_CUSTOM_SCOPE` |

### Friendly IdP and Role menu labels

When the operator has many AWS Federation apps listing the AWS IAM IdP ARNs can
make it hard to read the list. The same can be said if an IdP has many IAM Role
ARNs associated with it. To make this easier to manage the operator can create
an Okta config file in YAML format at `$HOME/.okta/okta.yaml` that allows them
to set a map of alias labels for the ARN values. Then ARN values for both IdPs
and Roles can also be evaluated are regular expressions (see example below).

**NOTE**: The Okta language SDKs have standardized on using
`$HOME/.okta/okta.yaml` as a configuration file and location. We will continue
that practice with read-only friendly okta-aws-cli application values.

#### Before

```
? Choose an IdP:  [Use arrows to move, type to filter]
> Fed App 1 Label
  Fed App 2 Label
  Fed App 3 Label
  Fed App 4 Label

? Choose a Role:  [Use arrows to move, type to filter]
> arn:aws:iam::123456789012:role/admin
  arn:aws:iam::123456789012:role/ops
```

#### Example `$HOME/.okta/okta.yaml`

```yaml
---
awscli:
  idps:
    "arn:aws:iam::123456789012:saml-provider/company-okta-idp": "Data Production"
    "arn:aws:iam::012345678901:saml-provider/company-okta-idp": "Data Development"
    "arn:aws:iam::901234567890:saml-provider/company-okta-idp": "Marketing Production"
    "arn:aws:iam::890123456789:saml-provider/company-okta-idp": "Marketing Development"
  roles:
    "arn:aws:iam::.*:role/admin": "Admin"
    "arn:aws:iam::.*:role/operator": "Ops"
```

#### After

```
? Choose an IdP:  [Use arrows to move, type to filter]
> Data Production
  Data Development
  Marketing Production
  Marketing Development

? Choose a Role:  [Use arrows to move, type to filter]
> Admin
  Ops
```

### Configuration by profile name

Multiple `okta-aws-cli` configurations can be saved in the `$HOME/.okta/okta.yaml`
file and are keyed by AWS profile name in the `awscli.profiles` section. This
allows the operator to save many `okta-aws-cli` configurations in the okta.yaml.

```
$ okta-aws-cli web --oidc-client-id 0oabc --org-domain my-org.okta.com --profile staging
```

#### Example `$HOME/.okta/okta.yaml`

```yaml
---
awscli:
  profiles:
    staging:
      oidc-client-id: "0osabc"
      org-domain: "org-stg.okata.com"
      aws-iam-idp: "arn:aws:iam::123:saml-provider/MyIdP"
      aws-iam-role: "arn:aws:iam::123:role/S3_Read"
      write-aws-credentials: true
      open-browser: true
    production:
      oidc-client-id: "0opabc"
      org-domain: "org-prd.okata.com"
      aws-iam-idp: "arn:aws:iam::456:saml-provider/MyIdP"
      aws-iam-role: "arn:aws:iam::456:role/S3_Read"
      write-aws-credentials: true
      open-browser: true
```

## Debug okta.yaml

okta-aws-cli has a debug option to check if the okta.yaml file is readable and
in valid format.

```
$ okta-aws-cli debug

Given this YAML as an example template of okta.yaml for reference:

---
awscli:
  idps:
    "arn:aws:iam::123456789012:saml-provider/company-okta-idp": "Data Production"
    "arn:aws:iam::012345678901:saml-provider/company-okta-idp": "Data Development"
  roles:
    "arn:aws:iam::123456789012:role/admin": "Prod Admin"
    "arn:aws:iam::123456789012:role/operator": "Prod Ops"
    "arn:aws:iam::012345678901:role/admin": "Dev Admin"
    "arn:aws:iam::012345678901:role/operator": "Dev Ops"

found home directory "/Users/person"
okta.yaml is readable "/Users/person/.okta/okta.yaml"
okta.yaml is valid yaml
okta.yaml has root "awscli" section
okta.yaml "awscli.idps" section is a map of 2 ARN string keys to friendly string label values
okta.yaml "awscli.roles" section is a map of 4 ARN string keys to friendly string label values
okta.yaml is OK
debugging okta-aws-cli config $HOME/.okta/okta.yaml is complete
```

If any of the checks fail a warning and diagnostic message is given.

okta-aws-cli will exit once the debug config operation is complete. It is not
intended to be run with other flags.

## Installation

### Binaries

Binary releases for combinations of operating systems and architectures are
posted to the [okta-aws-cli
releases](https://github.com/okta/okta-aws-cli/releases) section in Github. Each
release includes CHANGELOG notes for that release.

### OSX/Homebrew

okta-aws-cli is distributed to OSX via [homebrew](https://brew.sh/)

```
$ brew install okta-aws-cli
```

### Windows/Chocolatey

okta-aws-cli is distributed to Windows via [Chocolatey](https://community.chocolatey.org/packages/okta-aws-cli/)

```
> choco install okta-aws-cli
```

### Local build/install

See [Development](#development) section.

TL;DR run directly from source
```
$ go run cmd/okta-aws-cli/main.go --help
```

TL;DR build from source, installed into golang bin directory
```
$ make build
```

## Recommendations

We recommend that the AWS Federation Application and OIDC native application
have equivalent policies if not share the same policy. If the AWS Federation
app has more stringent assurance requirements than the OIDC app a `400 Bad
Request` API error is likely to occur.

**NOTE**: In authentication policy rule of AWS Federation app, **Device State**
must be set to **Any** for using Okta AWS CLI. Other options are not supported
at this time.

## Operation

The behavior of the Okta AWS CLI is to be friendly for shell input and
scripting. Output of the command that is human oriented is done on `STDERR` and
output for the AWS CLI that can be consumed in scripting is done on `STDOUT`.
This allows for the command's results to be `eval`'d into the current shell as
`eval` will only make use of `STDOUT` values.


### Plain usage

**NOTE**: The default sub command is `web` and it can be left off as a command argument.

**NOTE**: example assumes other Okta AWS CLI configuration values have already been
set by ENV variables or `.env` file.

**NOTE**: output will be in `setx` statements if the runtime is Windows.

**NOTE**: okta-aws-cli only needs to be called the first time to gather AWS
creds. Then called again once those creds have expired. _It does not need to be
called every time before each actual AWS CLI invocation._


```shell
$ okta-aws-cli
Open the following URL to begin Okta device authorization for the AWS CLI.

https://test-org.okta.com/activate?user_code=ZNQZQXQQ

? Choose an IdP: arn:aws:iam::123456789012:saml-provider/My_IdP
? Choose a Role: arn:aws:iam::456789012345:role/My_Role

export AWS_ACCESS_KEY_ID=ASIAUJHVCS6UQC52NOL7
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...

$ export AWS_ACCESS_KEY_ID=ASIAUJHVCS6UQC52NOL7
$ export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
$ export AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...
$ aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket
```

### Scripted orientated usages

**NOTE**: example assumes other Okta AWS CLI configuration values have already been
set by ENV variables or `.env` file.

```shell
$ eval `okta-aws-cli web --oidc-client-id 0oabc --org-domain my-org.okta.com` && aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket

$ eval `okta-aws-cli`

$ aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket

$ okta-aws-cli web --oidc-client-id 0oabc --org-domain my-org.okta.com --exec -- aws s3 ls s3://example
                           PRE aaa/
2023-03-08 16:01:01          4 a.log
```

### AWS credentials file orientated usage

**NOTE**: example assumes other Okta AWS CLI configuration values have already
been set by ENV variables or `.env` file.

```shell
$ okta-aws-cli web --oidc-client-id 0oabc --org-domain my-org.okta.com --profile test --format aws-credentials && \
  aws --profile test s3 ls

Open the following URL to begin Okta device authorization for the AWS CLI.

https://test-org.okta.com/activate?user_code=ZNQZQXQQ

? Choose an IdP: arn:aws:iam::123456789012:saml-provider/My_IdP
? Choose a Role: arn:aws:iam::456789012345:role/My_Role
Wrote profile "test" to /Users/mikemondragon/.aws/credentials

2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket
```
**NOTE**: Writing to the AWS credentials file will include the
*`x_security_token_expires` value in RFC3339 format. This allows tools dependent
*on valid AWS credentials to validate if they are expired or not, and
*potentially trigger a refresh if needed.

**NOTE**: the Okta AWS CLI will only append to the AWS credentials file. Be sure to
comment out or remove previous named profiles from the credentials file.
Otherwise an `Unable to parse config file` error like the following may occur.

```shell
aws --profile example s3 ls

Unable to parse config file: /home/user/.aws/credentials
```

### Process credentials provider

`okta-aws-cli` supports JSON output for the AWS CLI [credential process
argument](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html).
Add this line to the `default` section of `$/.aws/config`. First m2m example
presumes `m2m` arguments are in `OKTA_AWSCLI_*` environment variables, AWS CLI
passes those through. Second web example has args spelled out directly in the
credential process values.

M2M example:

`credential_process = okta-aws-cli m2m --format process-credentials --oidc-client-id 0oabc --org-domain my-org.okta.com`

Web example:

`credential_process = okta-aws-cli web --format process-credentials --oidc-client-id 0oabc --org-domain my-org.okta.com --aws-iam-idp arn:aws:iam::123:saml-provider/my-idp --aws-iam-role arn:aws:iam::294719231913:role/s3 --open-browser`

### Execute follow-on process

`okta-aws-cli` can execute a process after it has collected credentials. It will
do so with any existing env vars prefaced by `AWS_` such as `AWS_REGION` and
also append the env vars for the new AWS credentials `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`. Use `noop` format so `aws-aws-cli`
doesn't emit credentials to stdeout itself but passes them to the process it
executes. The output from the process will be printed to the screen properly to
STDOUT, and also STDERR if the process also writes to STDERR.

Example 1

```
$ okta-aws-cli m2m --format noop --oidc-client-id 0oabc --org-domain my-org.okta.com --exec -- printenv
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=ASIAUJHVCS6UYRTRTSQE
AWS_SECRET_ACCESS_KEY=TmvLOM/doSWfmIMK...
AWS_SESSION_TOKEN=FwoGZXIvYXdzEF8aDKrf...
```

Example 2

```
$ okta-aws-cli m2m --format noop --oidc-client-id 0oabc --org-domain my-org.okta.com --exec -- aws s3 ls s3://example
                           PRE aaa/
2023-03-08 16:01:01          4 a.log
```

Example 3 (process had error and also writes to STDERR)

```
$ okta-aws-cli m2m --format noop --oidc-client-id 0oabc --org-domain my-org.okta.com --exec -- aws s3 mb s3://no-access-example
error running process
aws s3 mb s3://yz-nomad-og
make_bucket failed: s3://no-access-example An error occurred (AccessDenied) when calling the CreateBucket operation: Access Denied

Error: exit status 1
```

### Collect all roles for all AWS Fed Apps (IdP)  at once

`okta-aws-cli web` will collect all available AWS IAM Roles for all Okta AWS
Federation apps (IdP) at once.  This is a feature specific to writing the
`$HOME/.aws/credentials` file. Roles will be AWS account alias name (if STS list
aliases is available on the given role) then `-` then abbreviated role name.

```
# Two Okta "AWS Account Federation" apps, one on AWS alias "prod-org", the other
# on alias "dev-org". Includes short name for the actual IAM IdPs and IAM Roles
# on the Fed App.

$ okta-aws-cli web \
    --org-domain my-org.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --write-aws-credentials \
    --all-profiles

? Choose an IdP: AWS Account Federation
Updated profile "dev-org-s3ops-read" in credentials file "/Users/me/.aws/credentials".
Updated profile "dev-org-s3ops-write" in credentials file "/Users/me/.aws/credentials".
Updated profile "prod-org-containerops-ec2-full" in credentials file "/Users/me/.aws/credentials".
Updated profile "prod-org-containerops-eks-full" in credentials file "/Users/me/.aws/credentials".
```

### Alternative open browser command

`okta-aws-cli web` can have it's open browser command customized.

#### OSX / MacBook
```
# OSX examples, the device authorization URL is appended to the browser args.

$ okta-aws-cli web \
  --oidc-client-id 0oabc \
  --org-domain my-org.okta.com \
  --open-browser-command "/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --profile-directory=\"Profile\ 1\""

$ okta-aws-cli web \
  --oidc-client-id 0oabc \
  --org-domain my-org.okta.com \
  --open-browser-command "open -na \"Google\ Chrome\" --args --incognito"
```

#### Windows

```
REM Windows examples, the device authorization URL is appended to the browser
REM args using cmd.exe with the run command flag /C used to spawn the browser
REM that is installed on the host OS e.g. msedge, chrome, firefox . Additional
REM arguments can be passed on to the browser command that are valid for it.

> okta-aws-cli web \
  --oidc-client-id 0oabc \
  --org-domain my-org.okta.com \
  --open-browser-command "cmd.exe /C start msedge"

> okta-aws-cli web \
  --oidc-client-id 0oabc \
  --org-domain my-org.okta.com \
  --open-browser-command "cmd.exe /C start chrome"

> okta-aws-cli web \
  --oidc-client-id 0oabc \
  --org-domain my-org.okta.com \
  --open-browser-command "cmd.exe /C start chrome --incognito"

> okta-aws-cli web \
  --oidc-client-id 0oabc \
  --org-domain my-org.okta.com \
  --open-browser-command "cmd.exe /C start chrome --profile-directory=\"Profile\ 1\""
```

### Help

```shell
$ okta-aws-cli --help
```

### Version

```shell
$ okta-aws-cli --version
```

## Comparison

### Nike gimme-aws-creds

There are a number of differences in terms of operation and functionality
between Okta AWS CLI and [Nike's
gimme-aws-creds](https://github.com/Nike-Inc/gimme-aws-creds).

The Okta AWS CLI is native to the [Okta Identity
Engine](https://help.okta.com/oie/en-us/Content/Topics/identity-engine/oie-index.htm).
No matter what kinds of authentication flows (multi-factors, assigned users,
etc.) have been applied to the Native OIDC application, the CLI works within
those constraints naturally. The Okta CLI is OIE only and will not work with
Classic orgs.

A simple URL is given to the operator to open in a browser and from there the
CLI's authentication and authorization is initiated. The Okta AWS CLI doesn't
prompt for passwords or any other user credentials itself, or offers to store
user credentials on a desktop keychain.

The configuration of the Okta AWS CLI is minimal with only two required values:
Okta org domain name, and OIDC app id.

The Okta CLI is CLI flag and environment variable oriented and its default
output is as environment variables. It can also write to AWS credentials file.
The default writing option is an append operation and can be explicitly set to
overwrite previous values for a profile with the `--write-aws-credentials` flag.

### Versent saml2aws

The comparison between Okta AWS CLI and [Versent
saml2aws](https://github.com/Versent/saml2aws) are identical to the comparison
between Okta AWS CLI and [Nike gimme-aws-creds](#nike-gimme-aws-creds).

## Development

Run source code locally

```
go run cmd/okta-aws-cli/main.go
```

Install tools that the Makefile uses like `gofumpt` and `golint`

```
make tools
```

Building

```
make build
```

Testing

```
make test
```

Run golang code quality control tools on the codebase (`go vet`, `golint`, etc.)

```
make qc
```

## Contributing

We're happy to accept contributions and PRs! Please see the [contribution
guide](CONTRIBUTING.md) to understand how to structure a contribution.

## References

* [Okta Developer Forum](https://devforum.okta.com/)
* [Okta Developer Documentation](https://developer.okta.com/)
* [okta-aws-cli issues](https://github.com/okta/okta-aws-cli/issues)
* [okta-aws-cli releases](https://github.com/okta/okta-aws-cli/releases)
