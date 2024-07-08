
$ErrorActionPreference = 'Stop'
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

$packageArgs = @{
  packageName   = $env:ChocolateyPackageName
  unzipLocation = $toolsDir
  url           = '{ZIPURL}'
  checksum      = '{SHA256CHECKSUM}'
  checksumType  = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

















