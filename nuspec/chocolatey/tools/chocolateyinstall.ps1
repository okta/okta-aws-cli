$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Extract the embedded zip file (no remote download needed)
$zipPath = Join-Path -Path $toolsDir -ChildPath 'okta-aws-cli.zip'
Get-ChocolateyUnzip -FileFullPath $zipPath -Destination $toolsDir -PackageName $env:ChocolateyPackageName

# Clean up the zip after extraction
Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue

