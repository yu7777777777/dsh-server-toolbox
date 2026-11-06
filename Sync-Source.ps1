[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SourceDirectory)
$ErrorActionPreference='Stop'
$source=(Resolve-Path -LiteralPath $SourceDirectory).Path
$destination=$PSScriptRoot
if($source.TrimEnd('\') -eq $destination.TrimEnd('\')){throw 'Source directory must differ from the Git repository.'}
$files=@('index.js','client.js','application.js','secrets.js','ssh.js','tools.js','transport.js','package.json','cordis.patch.yml','test.mjs','integration-test.mjs','icon.svg','locale\zh.json','locale\en.json')
# Validate the entire allowlist before copying anything. Never copy data or dependencies.
foreach($file in $files){if(-not(Test-Path -LiteralPath (Join-Path $source $file) -PathType Leaf)){throw "Missing source file: $file"}}
foreach($file in $files){
  $target=Join-Path $destination $file
  $parent=Split-Path -Parent $target
  if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null}
  Copy-Item -LiteralPath (Join-Path $source $file) -Destination $target
}
Write-Output 'Source files synchronized. Review git diff, run tests, then commit and push.'
Write-Output 'README, maintenance guides, lockfile, CI, and Git settings are maintained in this repository separately.'
Write-Output 'No data, credentials, screenshots, logs, or node_modules were copied.'
