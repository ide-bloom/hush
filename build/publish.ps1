<#
.SYNOPSIS
  Publishes hush.exe (Native AOT) and HushTray.exe (self-contained single file) side by side.
.EXAMPLE
  ./build/publish.ps1                       # win-x64 and win-arm64 into ./artifacts/<rid>
  ./build/publish.ps1 -Runtimes win-x64 -NoAot
#>
param(
    [string[]] $Runtimes = @('win-x64', 'win-arm64'),
    [string] $Configuration = 'Release',
    [string] $Output = "$PSScriptRoot/../artifacts",
    [switch] $NoAot
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')

# Native AOT links with the MSVC toolchain, which the ILCompiler locates through vswhere.exe.
$installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
if ((Test-Path $installer) -and -not ($env:PATH -split ';' -contains $installer)) {
    $env:PATH = "$installer;$env:PATH"
}

foreach ($rid in $Runtimes) {
    $target = Join-Path $Output $rid
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
    Write-Host "Publishing $rid -> $target"
    dotnet publish (Join-Path $root 'src/Hush.Cli/Hush.Cli.csproj') -c $Configuration -r $rid -o $target "-p:HushAot=$(-not $NoAot)"
    if ($LASTEXITCODE -ne 0) { throw "hush.exe publish failed for $rid" }
    dotnet publish (Join-Path $root 'src/Hush.App/Hush.App.csproj') -c $Configuration -r $rid -o $target
    if ($LASTEXITCODE -ne 0) { throw "HushTray.exe publish failed for $rid" }
    Get-ChildItem $target -Filter *.pdb | Remove-Item
    Get-ChildItem $target | Format-Table Name, Length
}
