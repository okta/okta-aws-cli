# okta-aws-cli

Okta authentication for federated identity providers in support of AWS CLI.

`okta-aws-cli` handles authentication to the IdP and token exchange with AWS STS
to collect a proper IAM role for the AWS CLI operator.

* [Configuration](#configuration)
* [Operation](#operation)
* [Development](#development)
* [Contributing](#contributing)
* [References](#references)

## Configuration

The Okta AWS CLI requires configuration values for the [Okta Org
domain](https://developer.okta.com/docs/guides/find-your-domain/main/), the ID
of the [OIDC Native
Application](https://developer.okta.com/blog/2021/11/12/native-sso) client app
acting as identity provider for AWS, and the ID of the [Okta AWS
Federation](https://www.okta.com/integrations/aws-account-federation/)
integration application.

An optional output format value can also be configured. Default output format is
as [environment
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
that can be used for the AWS CLI configuration.  Output can be expressed as
[credential file
values](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
for AWS CLI configuration.

Configuration can be done with environment variables, `.env` file, or command line flags.

| Value | ENV var | .env file value | Command line flag | Description |
|-------|---------|-----------------|-------------------|-------------|
| Okta Org Domain | OKTA_ORG_DOMAIN | OKTA_ORG_DOMAIN | --org-domain value | Full domain hostname of the Okta org e.g. `test.okta.com` |
| OIDC Client ID | OKTA_OIDC_CLIENT_ID | OKTA_OIDC_CLIENT_ID | --oidc-client-id value | See [Allowed Web SSO Client](#allowed-web-sso-client) |
| Okta AWS Account Federation integration app ID | OKTA_AWS_ACCOUNT_FEDERATION_APP_ID | OKTA_AWS_ACCOUNT_FEDERATION_APP_ID | --aws-acct-fed-app-id value | See [AWS Account Federation integration app](#aws-account-federation-integration-app) |
| AWS IAM Identity Provider ARN | AWS_IAM_IDP | AWS_IAM_IDP | --aws-iam-idp | The preferred IAM Identity Provider. If there are multiple IdPs available from AWS and this value does not match then a menu of choices will be rendered. |
| AWS IAM Role ARN to assume | AWS_IAM_ROLE | AWS_IAM_ROLE | --aws-iam-role | The preferred IAM role for the given IAM Identity Provider |
| Output format | FORMAT | FORMAT | --format value | Default is `env-var`. `cred-file` is also allowed |
| Profile | PROFILE | PROFILE | --profile value | Default is `default`  |
| Display QR Code | QR_CODE | QR_CODE | --qr-code | `yes` if flag is present  |

#### Allowed Web SSO Client

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

Note: Example assumes Okta AWS CLI configuration has already been set by ENV
variables or `.env` file.

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

Note: Example assumes Okta AWS CLI configuration has already been set by ENV
variables or `.env` file.

```shell
$ eval `okta-aws-cli` && aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket

$ eval `okta-aws-cli`
$ aws s3 ls
2018-04-04 11:56:00 test-bucket
2021-06-10 12:47:11 mah-bucket
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
[Okta Developer Forum](https://devforum.okta.com/)

[Okta Developer Documentation](https://developer.okta.com/)
[okta-aws-cli issues](/okta/okta-aws-cli/issues)
[okta-aws-cli releases](/okta/okta-aws-cli/releases)
