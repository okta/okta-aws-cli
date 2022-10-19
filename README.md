# okta-aws-cli

Okta authentication for federated identity providers in support of AWS CLI.

`okta-aws-cli` handles authentication through Okta and token exchange with AWS
STS to collect a proper IAM role for the AWS CLI operator.

This result is in the form of a set made up of  `Access Key ID`, `Secret Access
Key`, and `Session Token` of [AWS
credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
to use as the credentials for the AWS CLI. The Okta AWS CLI expresses the AWS
credentials as either environment variables or can be appended to an AWS CLI
credentials file. The `Session Token` has an expiry of 60 minutes.

```shell
$ eval `okta-aws-cli` && aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket
```

* [Requirements](#requirements)
* [Configuration](#configuration)
* [Operation](#operation)
* [Development](#development)
* [Contributing](#contributing)
* [References](#references)

## Requirements

The Okta AWS CLI requires at a minimum an Okta [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) with Grant
Types (as listed in Admin UI > Applications > [the OIDC app] > General Settings
    > Grant type) `Authorization Code`, `Device Authorization`, and `Token
Exchange`.  The OIDC app is then paired with an [Okta AWS
Federation](https://www.okta.com/integrations/aws-account-federation/)
integration application. The pairing is acheived in the Fed app's `Allowed Web
SSO Client` setting (as listed in the Admin UI > Applications > [the AWS Fed
    app] > Sign On) the Client ID of the OIDC native app and `Identity Provider
ARN (Required only for SAML SSO)` setting is the AWS ARN value for the AWS IAM
Identity Provider for the integration.

Okta has a wizzard to help establish the settings needed in AWS IAM, SAML
certificate generation, and settings needed for the Okta AWS Federation app.
Replace these required values in the URL below. Then follow the directions in
that wizzard.

* Org Admin Domain - [ADMIN_DOMAIN] - example: `myorg-admin.okta.com`
* Okta AWS Federation app Client ID - [CLIENT_ID] - example: `0oa555555aaaaaaZZZZZ`

`https://saml-doc.okta.com/SAML_Docs/How-to-Configure-SAML-2.0-for-Amazon-Web-Service.html?baseAdminUrl=https://[ADMIN_DOMAIN]&app=amazon_aws&instanceId=[CLIENT_ID]`


## Configuration

The Okta AWS CLI requires configuration values for the [Okta Org
domain](https://developer.okta.com/docs/guides/find-your-domain/main/), the ID
of the [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) client app
acting as identity provider for AWS. If the OIDC application has not been
granted the `okta.apps.read` scope the ID of the [Okta AWS
Federation](https://www.okta.com/integrations/aws-account-federation/)
integration application is also required.

An optional output format value can also be configured. Default output format is
as [environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
that can be used for the AWS CLI configuration.  Output can be expressed as
[credential file
values](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
for AWS CLI configuration.

Configuration can be done with environment variables, an `.env` file, command line flags, or a combination of the three.

Also see the CLI's online help `$ okta-aws-cli --help`

| Name | ENV var and .env file value | Command line flag | Description |
|-------|-----------------------------|-------------------|-------------|
| Okta Org Domain | OKTA_ORG_DOMAIN | `--org-domain` **[value]** | Full domain hostname of the Okta org e.g. `test.okta.com` |
| OIDC Client ID | OKTA_OIDC_CLIENT_ID | --oidc-client-id **[value]** | See [Allowed Web SSO Client](#allowed-web-sso-client) |
| Okta AWS Account Federation integration app ID | OKTA_AWS_ACCOUNT_FEDERATION_APP_ID | --aws-acct-fed-app-id **[value]** | Required if OIDC client is not granted `okta.apps.read` scope. See [AWS Account Federation integration app](#aws-account-federation-integration-app) |
| AWS IAM Identity Provider ARN | AWS_IAM_IDP | --aws-iam-idp **[value]** | The preferred IAM Identity Provider |
| AWS IAM Role ARN to assume | AWS_IAM_ROLE | --aws-iam-role **[value]** | The preferred IAM role for the given IAM Identity Provider |
| Output format | FORMAT | --format **[value]** | Default is `env-var`. Options: `env-var` for output to environment variables, `aws-credentials` for output to AWS credentials file |
| Profile | PROFILE | --profile **[value]** | Default is `default`  |
| Display QR Code | QR_CODE | --qr-code | `yes` if flag is present  |
| Alternate AWS credentials file path | AWS_CREDENTIALS | --aws-credentials | Path to alternative credentials file other than AWS CLI default |

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

Note: Only required if OIDC client is not granted `okta.apps.read` scope.


### Environment variables example

```shell
export OKTA_ORG_DOMAIN=test.okta.com
export OKTA_OIDC_CLIENT_ID=0oa5wyqjk6Wm148fE1d7
export OKTA_AWS_ACCOUNT_FEDERATION_APP_ID=0oa9x1rifa2H6Q5d8325
```

### `.env` file varialbes example

```
OKTA_ORG_DOMAIN=test.okta.com
OKTA_OIDC_CLIENT_ID=0oa5wyqjk6Wm148fE1d7
OKTA_AWS_ACCOUNT_FEDERATION_APP_ID=0oa9x1rifa2H6Q5d8325
```

### Command line flags example

```shell

$ okta-aws-cli --org-domain test.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --aws-acct-fed-app-id 0oa9x1rifa2H6Q5d8325
```

## Operation

The behavior of the Okta AWS CLI is to be friendly for shell scripting. Output
of the command that is human oriented is done on `STDERR` and output for the AWS
CLI that can be consumed in scripting is done on `STDOUT`. This allows for the
command's results to be `eval`'d into the current shell as `eval` will only make
use of `STDOUT` values.


### Plain usage

Note: Example assumes other Okta AWS CLI configuration vales have already been
set by ENV variables or `.env` file.

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

Note: Example assumes other Okta AWS CLI configuration vales have already been
set by ENV variables or `.env` file.

```shell
$ eval `okta-aws-cli` && aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket

$ eval `okta-aws-cli`
$ aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket
```

### AWS credentials file orientated usage

Note: Example assumes other Okta AWS CLI configuration vales have already been
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

Note: The Okta AWS CLI will only append to the AWS credentials file. Be sure to
comment out or remove previous named profiles from the credentials file.
Otherwise and error like the following may occur.

```shell
aws --profile example s3 ls

Unable to parse config file: /home/user/.aws/credentials
```

### Help

```shell
$ otka-aws --help
```

### Version

```shell
$ otka-aws --version
```

## Development

Run source code locally

```
go run cmd/okta-aws-cli/main.go
```

Make file help

```
make help
```

Building

```
make build
```

Testing

```
make test
```

## Contributing

We're happy to accept contributions and PRs! Please see the [contribution
guide](CONTRIBUTING.md) to understand how to structure a contribution.

## References

* [Okta Developer Forum](https://devforum.okta.com/)
* [Okta Developer Documentation](https://developer.okta.com/)
* [okta-aws-cli issues](/okta/okta-aws-cli/issues)
* [okta-aws-cli releases](/okta/okta-aws-cli/releases)
