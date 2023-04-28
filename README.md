# okta-aws-cli

Okta authentication in support of AWS CLI operation. The `okta-aws-cli` CLI is
native to the Okta Identity Engine and its authentication flows. The CLI is not
compatible with Okta Classic orgs.

The Okta AWS Federation application is SAML based and the Okta AWS CLI interacts
with AWS IAM using 
[AssumeRoleWithSAML](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html).
Okta does not have an OIDC based AWS Federation application at this time.

`okta-aws-cli` handles authentication through Okta and token exchange with AWS
STS to collect a proper IAM role for the AWS CLI operator.  The resulting
output is a set made up of  `Access Key ID`, `Secret Access Key`, and `Session
Token` of [AWS
credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
for the AWS CLI. The Okta AWS CLI expresses the AWS credentials as either
[environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
or appended to an AWS CLI [credentials
file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).
The `Session Token` has an expiry of 60 minutes.

```shell
# *nix, export statements
$ okta-aws-cli
export AWS_ACCESS_KEY_ID=ASIAUJHVCS6UQC52NOL7
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...

# *nix, eval export ENV vars into current shell
$ eval `okta-aws-cli` && aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket

rem Windows setx statements
C:\> okta-aws-cli
SETX AWS_ACCESS_KEY_ID ASIAUJHVCS6UQC52NOL7
SETX AWS_SECRET_ACCESS_KEY wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SETX AWS_SESSION_TOKEN AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5T...

```

* [Requirements](#requirements)
* [Recommendations](#recommendations)
* [Installation](#installation)
* [Configuration](#configuration)
* [Operation](#operation)
* Comparison
  * [Nike gimme-aws-creds](#nike-gimme-aws-creds)
  * [Versent saml2aws](#versent-saml2aws)
* [Development](#development)
* [Contributing](#contributing)
* [References](#references)

## Requirements

The Okta AWS CLI requires an OIE organization and an [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) paired with
an [Okta AWS Federation integration
application](https://www.okta.com/integrations/aws-account-federation/). The
Okta AWS Fed app is itself paired with an [AWS IAM identity
provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create.html).

The OIDC Native Application requires Grant Types `Authorization Code`, `Device
Authorization` , and `Token Exchange`. These settings are in the Okta Admin UI
at `Applications > [the OIDC app] > General Settings > Grant type`.

 If [Multiple AWS environments](#multiple-aws-environments) (see below) are to
 be supported by a single OIDC application, the OIDC app must have the
 `okta.apps.read` grant. Apps read and other application grants are configured
 at `Applications > [the OIDC app] > Okta API Scopes` in the Okta Admin UI.
 
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

### Multiple AWS environments

To support multiple AWS environments, associate additional AWS Federation
applications with the OIDC app The OIDC app **must** have the `okta.apps.read`
grant. The following is an illustration of the association of objects that make
up this kind of configuration.

![okta-aws-cli supporting multiple AWS environments](./doc/multi-aws-environments.jpg)

* All AWS Federation apps have the OIDC native app as their Allowed Web SSO client
* Fed App #1 is linked with an IAM IdP that has two Roles, one for S3 read, and one for S3 read/write
* Fed App #2 is linked to an IdP and Role dedicated to ec2 operations
* Fed App #3 is oriented for an administrator is comprised of an IdP and Role with many different permissions

#### Example select from multiple IdPs

![select IdP](./doc/example-select-idp.png)

#### Example select from multiple Roles

![select Role](./doc/example-select-role.png)

#### Example creds consumed for S3 operations

![conclusion](./doc/example-conclusion.png)

## Recommendations

We recommend that the AWS Federation Application and OIDC native application
have equivalent policies if not share the same policy. If the AWS Federation
app has more stringent assurance requirements than the OIDC app a `400 Bad
Request` API error is likely to occur.

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

## Configuration

**Note**: If your AWS IAM IdP is in a non-commercial region, such as GovCloud,
the environmental variable
[`AWS_REGION`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
should be set
[accordingly](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-region).

At a minimum the Okta AWS CLI requires two configuration values. These are the
values for the [Okta Org
domain](https://developer.okta.com/docs/guides/find-your-domain/main/), and the
client ID of the [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso).

If the OIDC Native App doesn't also have the `okta.apps.read` grant the client
ID of the [Okta AWS
Federation](https://www.okta.com/integrations/aws-account-federation/)
integration application is also required.

An optional output format value can be configured. Default output format is as
[environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
that can be used for the AWS CLI configuration. Output can also be expressed as
[credential file
values](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
for AWS CLI configuration.

Configuration can be done with environment variables, an `.env` file, command line flags, or a combination of the three.

Also see the CLI's online help `$ okta-aws-cli --help`

| Name | ENV var and .env file value | Command line flag | Description |
|-------|-----------------------------|-------------------|-------------|
| Okta Org Domain (**required**) | `OKTA_ORG_DOMAIN` | `--org-domain [value]` | Full domain hostname of the Okta org e.g. `test.okta.com` |
| OIDC Client ID (**required**) | `OKTA_OIDC_CLIENT_ID` | `--oidc-client-id [value]` | See [Allowed Web SSO Client](#allowed-web-sso-client) |
| Okta AWS Account Federation integration app ID (optional) | `OKTA_AWS_ACCOUNT_FEDERATION_APP_ID` | `--aws-acct-fed-app-id [value]` | See [AWS Account Federation integration app](#aws-account-federation-integration-app). This value is only required if the OIDC app doesn't have the `okta.apps.read` grant for whatever reason |
| Preselect the AWS IAM Identity Provider ARN (optional) | `OKTA_AWSCLI_IAM_IDP` | `--aws-iam-idp [value]` | Preselects the IdP list to this preferred IAM Identity Provider. If there are other IdPs available they will not be listed. |
| Preselects the AWS IAM Role ARN to assume (optional) | `OKTA_AWSCLI_IAM_ROLE` | `--aws-iam-role [value]` | Preselects the role list to this preferred IAM role for the given IAM Identity Provider. If there are other Roles available they will not be listed. |
| AWS Session Duration (optional) | `OKTA_AWSCLI_SESSION_DURATION` | `--session-duration [value]` | The lifetime, in seconds, of the AWS credentials. Must be between 60 and 43200. |
| Output format (optional) | `OKTA_AWSCLI_FORMAT` | `--format [value]` | Default is `env-var`. Options: `env-var` for output to environment variables, `aws-credentials` for output to AWS credentials file |
| Profile (optional) | `OKTA_AWSCLI_PROFILE` | `--profile [value]` | Default is `default`  |
| Display QR Code (optional) | `OKTA_AWSCLI_QR_CODE=true` | `--qr-code` | `true` if flag is present  |
| Automatically open the activation URL with the system web browser (optional) | `OKTA_AWSCLI_OPEN_BROWSER=true` | `--open-browser` | `true` if flag is present  |
| Cache Okta access token at `$HOME/.okta/awscli-access-token.json` to reduce need to open device authorization URL | `OKTA_AWSCLI_CACHE_ACCESS_TOKEN=true` | `--cache-access-token` | `true` if flag is present  |
| Alternate AWS credentials file path (optional) | `OKTA_AWSCLI_AWS_CREDENTIALS` | `--aws-credentials` | Path to alternative credentials file other than AWS CLI default |
| (Over)write the given profile to the AWS credentials file (optional). WARNING: When enabled, overwriting can inadvertently remove dangling comments and extraneous formatting from the creds file. | `OKTA_AWSCLI_WRITE_AWS_CREDENTIALS=true` | `--write-aws-credentials` | `true` if flag is present  |
| Emit deprecated AWS variable `aws_security_token` with duplicated value from `aws_session_token` | `OKTA_AWSCLI_LEGACY_AWS_VARIABLES=true` | `--legacy-aws-variables` | `true` if flag is present  |
| Emit expiry timestamp `x_security_token_expires` in RFC3339 format for the session/security token (AWS credentials file only) | `OKTA_AWSCLI_EXPIRY_AWS_VARIABLES=true` | `--expiry-aws-variables` | `true` if flag is present  |
| Verbosely print all API calls/responses to the screen | `OKTA_AWSCLI_DEBUG_API_CALLS=true` | `--debug-api-calls` | `true` if flag is present  |
| HTTP/HTTPS Proxy support | `HTTP_PROXY` or `HTTPS_PROXY` | n/a | HTTP/HTTPS URL of proxy service (based on golang [net/http/httpproxy](https://pkg.go.dev/golang.org/x/net/http/httpproxy) package) |

NOTE: If
[`AWS_REGION`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
is set in the `.env` file it will be promoted into the okta-aws-cli runtime if
it isn't also already set as an ENV VAR. This will allow operators making use of
an `.env` file to have proper AWS API behavior in spefific regions, for instance
in US govcloud and other non-North America regions.

### Allowed Web SSO Client

This is the "Allowed Web SSO Client" value from the "Sign On" settings of an
[AWS Account
Federation"](https://www.okta.com/integrations/aws-account-federation/)
integration app and is an Okta [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) ID. The ID
is the identifier of the client is Okta app acting as the IdP for AWS.

Example: `0oa5wyqjk6Wm148fE1d7`

### AWS Account Federation integration app

ID for the [AWS Account
Federation"](https://www.okta.com/integrations/aws-account-federation/)
integration app.

Example: `0oa9x1rifa2H6Q5d8325`


### Environment variables example

```shell
export OKTA_ORG_DOMAIN=test.okta.com
export OKTA_OIDC_CLIENT_ID=0oa5wyqjk6Wm148fE1d7
```

### `.env` file variables example

```
OKTA_ORG_DOMAIN=test.okta.com
OKTA_OIDC_CLIENT_ID=0oa5wyqjk6Wm148fE1d7
```

### Command line flags example

#### OIDC client has `okta.apps.read` grant

```shell

$ okta-aws-cli --org-domain test.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7
```

#### OIDC client **does not** have `okta.apps.read` grant

```shell

$ okta-aws-cli --org-domain test.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --aws-acct-fed-app-id 0oa9x1rifa2H6Q5d8325
```

### Friendly IdP menus

When the operator has many AWS Federation apps, listing the AWS IAM IdP ARNs can
make it hard to read the list. The operator can create an Okta config file in
YAML format at `$HOME/.okta/okta.yaml` that allows them to set a map of alias
labels for the ARN values.

Note: The Okta language SDKs have standardized on using `$HOME/.okta/okta.yaml`
as a configuration file and location. We will continue that practice with
read-only friendly okta-aws-cli application values.

#### Before

```
? Choose an IdP:  [Use arrows to move, type to filter]
> Fed App 1 Label (arn:aws:iam::123456789012:saml-provider/company-okta-idp)
  Fed App 2 Label (arn:aws:iam::012345678901:saml-provider/company-okta-idp)
  Fed App 3 Label (arn:aws:iam::901234567890:saml-provider/company-okta-idp)
  Fed App 4 Label (arn:aws:iam::890123456789:saml-provider/company-okta-idp)
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
```

#### After

```
? Choose an IdP:  [Use arrows to move, type to filter]
> Data Production
  Data Development
  Marketing Production
  Marketing Development
```

## Operation

The behavior of the Okta AWS CLI is to be friendly for shell input and
scripting. Output of the command that is human oriented is done on `STDERR` and
output for the AWS CLI that can be consumed in scripting is done on `STDOUT`.
This allows for the command's results to be `eval`'d into the current shell as
`eval` will only make use of `STDOUT` values.


### Plain usage

**NOTE**: example assumes other Okta AWS CLI configuration values have already been
set by ENV variables or `.env` file.

**NOTE**: output will be in `setx` statements if the runtime is Windows.

**NOTE**: okta-aws-cli only needs to be called the first time to gather AWS
creds. Then called again once those creds have expired. It does not need to be
called every time before each actual AWS CLI invocation.

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
$ eval `okta-aws-cli` && aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket

$ eval `okta-aws-cli`

$ aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket

$ aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket
```

### AWS credentials file orientated usage

**NOTE**: example assumes other Okta AWS CLI configuration values have already been
set by ENV variables or `.env` file.

```shell
$ okta-aws-cli --profile test --format aws-credentials && \
  aws --profile test s3 ls

Open the following URL to begin Okta device authorization for the AWS CLI.

https://test-org.okta.com/activate?user_code=ZNQZQXQQ

? Choose an IdP: arn:aws:iam::123456789012:saml-provider/My_IdP
? Choose a Role: arn:aws:iam::456789012345:role/My_Role
Wrote profile "test" to /Users/mikemondragon/.aws/credentials

2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket
```
Note: Writing to the AWS credentials file will include the `x_security_token_expires` value in RFC3339 format. This allows tools dependent on valid AWS credentials to validate if they are expired or not, and potentially trigger a refresh if needed.

**NOTE**: the Okta AWS CLI will only append to the AWS credentials file. Be sure to
comment out or remove previous named profiles from the credentials file.
Otherwise an `Unable to parse config file` error like the following may occur.

```shell
aws --profile example s3 ls

Unable to parse config file: /home/user/.aws/credentials
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
The default writing option is an apped operation and can be explicitly set to
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
