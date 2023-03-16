# Changelog

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

