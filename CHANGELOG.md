# Changelog

## 2.1.1 (February 23, 2024)

### BUG FIXES

* Fix bug dealing with multiple profiles in okta.yaml [#187](https://github.com/okta/okta-aws-cli/pull/187), thanks [@MatthewJohn](https://github.com/MatthewJohn)!

## 2.1.0 (February 15, 2024)

### ENHANCEMENTS

* Multiple okta-aws-cli configurations in `okta.yaml` by AWS profile name.  [#162](https://github.com/okta/okta-aws-cli/pull/162), thanks [@MatthewJohn](https://github.com/MatthewJohn)!

* Explicitly set AWS Region with CLI flag `--aws-region` [#174](https://github.com/okta/okta-aws-cli/pull/174), thanks [@euchen-circle](https://github.com/euchen-circle), [@igaskin](https://github.com/igaskin)!

* `--aws-iam-idp` and `--aws-iam-role` arguments can be ARN or friendly label [#178](https://github.com/okta/okta-aws-cli/pull/178), thanks [@monde](https://github.com/monde)!

### BUG FIXES

* Fix bug where all flags were not being set on the config object. [#177](https://github.com/okta/okta-aws-cli/pull/177), thanks [@monde](https://github.com/monde)!
* Process credentials format was not emitting JSON correctly when `--write-aws-credentials` flag is present [#173](https://github.com/okta/okta-aws-cli/pull/173), thanks [@monde](https://github.com/monde)!
* Open browser and open browser command behavior was fouled in v2 release [#172](https://github.com/okta/okta-aws-cli/pull/172), thanks [@monde](https://github.com/monde)!

## 2.0.1 (January 31, 2024)

### ENHANCEMENTS

 * Packaged binary's don't have postfix version value on file name [#154](https://github.com/okta/okta-aws-cli/pull/154)

### BUG FIXES

 * Binaries produced by golang for Windows amd64 runtimes are triggering AVs so we will not publish this for the OS/Arch [#166](https://github.com/okta/okta-aws-cli/pull/166)
 * CLI version incorrectly rev'd on previous release [#164](https://github.com/okta/okta-aws-cli/pull/164)

## 2.0.0 (January 25, 2024)

V2 GA Release 🎉🎉

### New commands

`okta-aws-cli`'s functions are encapsulated as (sub)commands e.g. `$ okta-aws-cli [sub-command]`

| Command | Description |
|-----|-----|
| `web` | Human oriented retrieval of temporary IAM credentials through Okta authentication and device authorization. Note: if `okta-aws-cli` is not given a command it defaults to this original `web` command. |
| `m2m` | Machine/headless oriented retrieval of temporary IAM credentials through Okta authentication with a private key. |
| `debug` | Debug okta.yaml config file and exit. |

### Environment variable name changes

A small number of environment variable names have been renamed to be consistent
in the naming convention for `okta-aws-cli` specific names.

| old name | new name |
|----------|----------|
| `OKTA_ORG_DOMAIN` | `OKTA_AWSCLI_ORG_DOMAIN` |
| `OKTA_OIDC_CLIENT_ID` | `OKTA_AWSCLI_OIDC_CLIENT_ID` |
| `OKTA_AWS_ACCOUNT_FEDERATION_APP_ID` | `OKTA_AWSCLI_AWS_ACCOUNT_FEDERATION_APP_ID` |

### Process credential provider output as JSON

Emits IAM temporary credentials as JSON in [process
credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)
format.

```
# In $/.aws/config
[default]
  # presumes OKTA_AWSCLI_* env vars are set
  credential_process = okta-aws-cli m2m --format process-credentials
```

### Execute follow-on command

Instead of scripting and/or eval'ing `okta-aws-cli` into a shell and then
running another command have `okta-aws-cli` run the command directly passing
along the IAM credentials as environment variables.

```
# CLI exec's anything after the double dash "--" arguments terminator as another command.
$ okta-aws-cli web \
    --org-domain test.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --exec -- aws ec2 describe-instances
```

### Collect all roles for all AWS Fed Apps (IdP) at once

`okta-aws-cli web` will collect all available AWS IAM Roles for all Okta AWS
Federation apps (IdP) at once.  This is a feature specific to writing the
`$HOME/.aws/credentials` file. Roles will be AWS account alias name (if STS list
aliases is available on the given role) then `-` then abbreviated role name.


```
# AWS account alias "myorg", given IdP associated with "AWS Account Federation"
# and an app associated with two roles.

$ okta-aws-cli web \
    --org-domain test.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --write-aws-credentials \
    --all-profiles

Web browser will open the following URL to begin Okta device authorization for the AWS CLI

https://test.okta.com/activate?user_code=QHDMVQTZ

Updated profile "devorg-idp1-role1" in credentials file "/Users/me/.aws/credentials".
Updated profile "devorg-idp1-role2" in credentials file "/Users/me/.aws/credentials".
Updated profile "devorg-idp2-role1" in credentials file "/Users/me/.aws/credentials".
Updated profile "prodorg-idp1-role1" in credentials file "/Users/me/.aws/credentials".
```

### Alternate web browser open command

The `web` command will open the system's default web browser when the
`--open-browser` flag is present. It is convenient to have the browser open on a
separate profile. If the command to open the browser is known for the host
system an alternate open command can be specified.

```
# Use macOS open to open browser in Chrome incognito mode
$ okta-aws-cli web \
    --org-domain test.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --open-browser-command "open -na \"Google\ Chrome\" --args --incognito"
```

```
# Open browser in Chrome "Profile 1" on macOS calling the Chrome executable directly
$ okta-aws-cli web \
    --org-domain test.okta.com \
    --oidc-client-id 0oa5wyqjk6Wm148fE1d7 \
    --open-browser-command "/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --profile-directory=\"Profile\ 1\""
```

Windows examples
```
> okta-aws-cli web \
  --oidc-client-id abc \
  --org-domain test.okta.com \
  --open-browser-command "cmd.exe /C start msedge"

> okta-aws-cli web \
  --oidc-client-id abc \
  --org-domain test.okta.com \
  --open-browser-command "cmd.exe /C start chrome"

> okta-aws-cli web \
  --oidc-client-id abc \
  --org-domain test.okta.com \
  --open-browser-command "cmd.exe /C start chrome --incognito"

> okta-aws-cli web \
  --oidc-client-id abc \
  --org-domain test.okta.com \
  --open-browser-command "cmd.exe /C start chrome --profile-directory=\"Profile\ 1\""
```

### Friendly label matching with regular expressions

Friendly label matching for IdPs and Roles with `$HOME/.okta/okta.yaml` file can
be regular expressions.

Example: your organization uses the same role naming convention across many
different AWS accounts:

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

```
? Choose an IdP:  
> Data Production
  Data Development
  Marketing Production
  Marketing Development

? Choose a Role:  [Use arrows to move, type to filter]
> Admin
  Ops
```

## 2.0.0-beta.6 (November 2, 2023)

* New m2m flag `--private-key-file` read private key from file
* Bug fix panic when okta.yaml is not established (it doesn't have to be established either)
* Bug fix allowing `--version` w/o sub command [#150](https://github.com/okta/okta-aws-cli/pull/150), thanks [@malept](https://github.com/malept)!

## 2.0.0-beta.5 (October 13, 2023)

Friendly label matching for IdPs and Roles with `$HOME/.okta/okta.yaml` file can be regular expressions.

## 2.0.0-beta.4 (October 12, 2023)

`okta-aws-cli web` can have it's open browser command customized.

## 2.0.0-beta.3 (October 10, 2023)

`okta-aws-cli web` can collect all roles for all AWS Federation Apps (IdP) to an
AWS credentials file in one invocation of the CLI.

## 2.0.0-beta.2 (October 5, 2023)

Execute a subcommand directly from `okta-aws-cli`

## 2.0.0-beta.1 (October 2, 2023)

Support for AWS CLI [process credential provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)

## 2.0.0-beta.0 (September 29, 2023)

`okta-aws-cli`'s functions are encapsulated as (sub)commands `web`, `m2m`, `debug`

A small number of environment variable names have been renamed to be consistent
in the naming convention for `okta-aws-cli` specific names.

## 1.2.2 (August 30, 2023)

* Ensure evaluation of CLI flag for profile is in the same order as the other flags [#124](https://github.com/okta/okta-aws-cli/pull/124)
* Retry cached access token if it isn't expired by but receives API error [#127](https://github.com/okta/okta-aws-cli/pull/127)

## 1.2.1 (August 15, 2023)

* Friendly IdP and Role labels don't also print out ARN value (less text clutter in the UI)

## 1.2.0 (August 15, 2023)

* [Friendly Role menu labels](https://github.com/okta/okta-aws-cli#friendly-idp-and-role-menu-labels) for long ARN values can be set in `$HOME/.okta/okta.yaml`

## 1.1.0 (July 13, 2023)

* Print out operational debugging information flag [#113](https://github.com/okta/okta-aws-cli/pull/113), thanks [@monde](https://github.com/monde)!

## 1.0.2 (June 27, 2023)

* [#112](https://github.com/okta/okta-aws-cli/pull/112), thanks [@monde](https://github.com/monde)!
  * Fix broken preselecting  --aws-iam-idp / OKTA_AWSCLI_IAM_IDP value [#95](https://github.com/okta/okta-aws-cli/issues/95)
  * Ensure ENV VAR OKTA_AWSCLI_PROFILE is honored. [#109](https://github.com/okta/okta-aws-cli/issues/109)
  * Operation to debug/inspect okta.yaml config for valid format [#106](https://github.com/okta/okta-aws-cli/issues/106)

## 1.0.1 (May 04, 2023)

* Remove okta-only domain check [#103](https://github.com/okta/okta-aws-cli/pull/103), thanks [@duytiennguyen-okta](https://github.com/duytiennguyen-okta)!

## 1.0.0 (May 02, 2023)

### ENHANCEMENTS

* Cache Okta API access token [#100](https://github.com/okta/okta-aws-cli/pull/100), thanks [@monde](https://github.com/monde)!
* Bringing in @tim-fitzgerald's PR #56 `x_security_token_expires` value [#56](https://github.com/okta/okta-aws-cli/pull/56) [#99](https://github.com/okta/okta-aws-cli/pull/99), thanks [@tim-fitzgerald](https://github.com/tim-fitzgerald)!
* Prepend OKTA_AWSCLI_ on ENV VARs [#98](https://github.com/okta/okta-aws-cli/pull/98), thanks [@monde](https://github.com/monde)!
* Config for IdP menu [#97](https://github.com/okta/okta-aws-cli/pull/97), thanks [@monde](https://github.com/monde)!
* Send browser command stdout to stderr [#93](https://github.com/okta/okta-aws-cli/pull/93), thanks [@daniel-sampliner](https://github.com/daniel-sampliner)!
* Refactor config [#90](https://github.com/okta/okta-aws-cli/pull/90), thanks [@duytiennguyen-okta](https://github.com/duytiennguyen-okta)!
* Update aws-cli with best practices [#88](https://github.com/okta/okta-aws-cli/pull/88), thanks [@duytiennguyen-okta](https://github.com/duytiennguyen-okta)!

### NOTICES

#### New Features

* `--expiry-aws-variables` CLI flag for `x_security_token_expires` support in AWS creds file
* `--cache-access-token` CLI flag to cache the access token associated device authorization to preempt needing to open the browser frequently
* [Friendly IdP menu labels](https://github.com/okta/okta-aws-cli#friendly-idp-menu-labels) for long ARN values can be set in `$HOME/.okta/okta.yaml`

#### ENV VAR changes

The following ENV VARs have been renamed

| old value | new value |
|-----------|-----------|
|`AWS_IAM_IDP` |`OKTA_AWSCLI_IAM_IDP` |
|`AWS_IAM_ROLE` |`OKTA_AWSCLI_IAM_ROLE` |
|`AWS_SESSION_DURATION` |`OKTA_AWSCLI_SESSION_DURATION` |
|`FORMAT` |`OKTA_AWSCLI_FORMAT` |
|`PROFILE` |`OKTA_AWSCLI_PROFILE` |
|`QR_CODE` |`OKTA_AWSCLI_QR_CODE` |
|`OPEN_BROWSER` |`OKTA_AWSCLI_OPEN_BROWSER` |
|`AWS_CREDENTIALS` |`OKTA_AWSCLI_AWS_CREDENTIALS` |
|`WRITE_AWS_CREDENTIALS` |`OKTA_AWSCLI_WRITE_AWS_CREDENTIALS` |
|`LEGACY_AWS_VARIABLES` |`OKTA_AWSCLI_LEGACY_AWS_VARIABLES` |
|`DEBUG_API_CALLS` |`OKTA_AWSCLI_DEBUG_API_CALLS` |

#### Support for non-admin users needing multiple AWS Federation Application support

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

It is on our feature backlog to get support into the Okta API to allow the
multiple AWS Fed apps feature into okta-aws-cli without needing this work
around using a custom admin role.

## 0.3.0 (March 15, 2023)

### ENHANCEMENTS

* Remove an extra colon in usage text [#76](https://github.com/okta/okta-aws-cli/pull/76), thanks [@ZhongRuoyu](https://github.com/ZhongRuoyu)!
* Deal with deprecated/obsolete/unsupported `aws_security_token` variable [#79](https://github.com/okta/okta-aws-cli/pull/79), thanks [@monde](https://github.com/monde)!
* added proxy support to http client [#80](https://github.com/okta/okta-aws-cli/pull/80), thanks [@SaltyPeaches](https://github.com/SaltyPeaches)!
* Try to help the operator if they are using a URL format value for org [#82](https://github.com/okta/okta-aws-cli/pull/82), thanks [@monde](https://github.com/monde)!
* Pre-flight check if org is Classic or OIE [#84](https://github.com/okta/okta-aws-cli/pull/84), thanks [@monde](https://github.com/monde)!
* Promote AWS_REGION from .env if it exists for proper AWS API behavior [#85](https://github.com/okta/okta-aws-cli/pull/85), thanks [@monde](https://github.com/monde)!
* Emit tar.gz and zip archives upon release [#87](https://github.com/okta/okta-aws-cli/pull/87), thanks [@monde](https://github.com/monde)!

### BUG FIXES

* Fix "SETX commands emitted on Windows have incorrect syntax" [#78](https://github.com/okta/okta-aws-cli/pull/78), thanks [@laura-rodriguez](https://github.com/laura-rodriguez)!
* Correctly set session duration from AWS_SESSION_DURATION env var [#81](https://github.com/okta/okta-aws-cli/pull/81), thanks [@monde](https://github.com/monde)!

### MAINTENANCE

* Update golang/text dependency [#71](https://github.com/okta/okta-aws-cli/pull/71), thanks [@laura-rodriquez](https://github.com/laura-rodriquez)!
* update dependencies [#73](https://github.com/okta/okta-aws-cli/pull/73), thanks [@duytiennguyen-okta](https://github.com/duytiennguyen-okta)!

### NOTICES

In the v1.0.0 release ENV VARs specific to okta-aws-cli will be prefixed with
`OKTA_` in 12factor format.

| old value | new value |
|-----------|-----------|
|`AWS_IAM_IDP` |`OKTA_AWS_IAM_IDP` |
|`AWS_IAM_ROLE` |`OKTA_AWS_IAM_ROLE` |
|`AWS_SESSION_DURATION` |`OKTA_AWS_SESSION_DURATION` |
|`FORMAT` |`OKTA_FORMAT` |
|`PROFILE` |`OKTA_PROFILE` |
|`QR_CODE` |`OKTA_QR_CODE` |
|`OPEN_BROWSER` |`OKTA_OPEN_BROWSER` |
|`AWS_CREDENTIALS` |`OKTA_AWS_CREDENTIALS` |
|`WRITE_AWS_CREDENTIALS` |`OKTA_WRITE_AWS_CREDENTIALS` |
|`LEGACY_AWS_VARIABLES` |`OKTA_LEGACY_AWS_VARIABLES` |
|`DEBUG_API_CALLS` |`OKTA_DEBUG_API_CALLS` |

## 0.2.1 (January 24, 2023)

### BUG FIXES

* Fix IdP text rendering bug caused by linting changes [#54](https://github.com/okta/okta-aws-cli/pull/54), thanks [@monde](https://github.com/monde)!

## 0.2.0 (January 24, 2023)

### ENHANCEMENTS

* `setx` output when in Windows environment [#49](https://github.com/okta/okta-aws-cli/pull/49), thanks [@monde](https://github.com/monde)!
* `--write-aws-credentials` implies output format `aws-credentials` [#40](https://github.com/okta/okta-aws-cli/pull/40), thanks [@monde](https://github.com/monde)!
* Verbose HTTP API call/response logging with `--debug-api-calls` flag [#43](https://github.com/okta/okta-aws-cli/pull/43), thanks [@monde](https://github.com/monde)!
* Return underlying Error if present in fetchWebSSO() [#47](https://github.com/okta/okta-aws-cli/pull/47), thanks [@emanor-okta](https://github.com/emanor-okta)!

### BUG FIXES

* Fix setting/getting IDP ARN value when Role Value Pattern is used on AWS Federation App [#51](https://github.com/okta/okta-aws-cli/pull/51), thanks [@monde](https://github.com/monde)!
* Accept `OPEN_BROWSER`, `WRITE_AWS_CREDENTALS` env vars  [#50](https://github.com/okta/okta-aws-cli/pull/50), thanks [@monde](https://github.com/monde)!

## 0.1.0 (December 21, 2022)

First GA release

### NEW FEATURES

* Auto pop system web browser to device authorization form when `--open-browser` CLI flag is present - PR [#21](https://github.com/okta/okta-aws-cli/pull/21)
  * Thanks [@kda-jt](https://github.com/kda-jt), [@monde](https://github.com/monde)!
* Full multiple AWS Federation Applications support - see [README - Multiple AWS environments](https://github.com/okta/okta-aws-cli/#multiple-aws-environments) - [#28](https://github.com/okta/okta-aws-cli/pull/28)
  * Thanks [@monde](https://github.com/monde)!
* Write/update (instead of append) AWS Credentials file when `--write-aws-credentials` CLI flag is present - PR [#30](https://github.com/okta/okta-aws-cli/pull/30)
  * Thanks [@ctennis](https://github.com/ctennis), [@monde](https://github.com/monde)!

### ENHANCEMENTS

* Print response body with error message when API error occurs [#22](https://github.com/okta/okta-aws-cli/pull/22)
  * Thanks [@ctennis](https://github.com/ctennis)!
* Don't render ncurses select menu for IdP or Role when there is only one item to choose from [#25](https://github.com/okta/okta-aws-cli/pull/25)
  * Thanks [@ctennis](https://github.com/ctennis)!
* Document policy recommendation for AWS Fed App and OIDC Native App
* Document need for `AWS_REGION` env variable if AWS IdP is in a non-commercial AWS region
* Auto-correct org domain when it is in admin form - `ORGNAME-admin.okta.com` to `ORGNAME.okta.com`
* Illustrate `make tools` is used to install the tools the Makefile makes use of
* Notorizing OSX x86_64 and arm64 binaries

### BUG FIXES

* Correctly write creds file when `AWS_CREDENTIALS` env var is set
* `AWS_PROFILE` is unnecessary in env var output

## 0.0.4 (October 24, 2022)

* Configurable AWS Session TTL `--session-duration [value]` [#14](https://github.com/okta/okta-aws-cli/pull/14). Thanks, [@tim-fitzgerald](https://github.com/tim-fitzgerald)!
* Documentation improvements [#13](https://github.com/okta/okta-aws-cli/pull/13), [#12](https://github.com/okta/okta-aws-cli/pull/12) . Thanks, [@BryanStenson-okta](https://github.com/BryanStenson-okta)!

MVP release

## 0.0.3 (October 20, 2022)

MVP release

## 0.0.2 (October 10, 2022)

Release testing

## 0.0.1 (September 09, 2022)

Initial implementation

