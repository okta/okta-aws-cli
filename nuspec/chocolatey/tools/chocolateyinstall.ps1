
$ErrorActionPreference = 'Stop'
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/okta/okta-aws-cli/releases/download/v2.0.1/okta-aws-cli_2.0.1_windows_386.zip'

$packageArgs = @{
  packageName   = $env:ChocolateyPackageName
  unzipLocation = $toolsDir
  url           = $url
  checksum      = 'F05862D42BF14133EFA88C9F77C0AB942858CA0FFDE980D0615395E8E48FD4D6'
  checksumType  = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

















