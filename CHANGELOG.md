# Changelog

## 0.2.1 (January 24, 2023)

### BUG FIXES

* Fix IdP text rendering bug caused by linting changes [#54](https://github.com/okta/okta-aws-cli/pull/54), thanks [@monde](https://github.com/monde)!

## 0.2.0 (January 24, 2023)

### ENHANCEMENTS

* `setx` output when in Windows environment [#49](https://github.com/okta/okta-aws-cli/pull/49), thanks [@monde](https://github.com/monde)!
* `--write-aws-credentials` implies output format `aws-credentials` [#40](https://github.com/okta/okta-aws-cli/pull/40), thanks [@monde](https://github.com/monde)!
* Verbose HTTP API call/resonse logging with `--debug-api-calls` flag [#43](https://github.com/okta/okta-aws-cli/pull/43), thanks [@monde](https://github.com/monde)!
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

