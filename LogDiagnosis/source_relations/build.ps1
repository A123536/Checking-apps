param(
    [string]$QtRoot = 'D:\Qt\Qt5.12.1',
    [string]$BuildRoot = 'D:\Qt\build-SourceRelations',
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$qtBin = Join-Path $QtRoot '5.12.1\mingw73_64\bin'
$compilerBin = Join-Path $QtRoot 'Tools\mingw730_64\bin'
$env:PATH = "$compilerBin;$qtBin;$env:PATH"
New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null
$venv = Join-Path $BuildRoot 'python'
if (!(Test-Path -LiteralPath "$venv\Scripts\python.exe")) {
    & $Python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Creating Python build environment failed' }
}
$buildPython = Join-Path $venv 'Scripts\python.exe'
& $buildPython -m pip install -r "$PSScriptRoot\requirements.txt" pyinstaller==6.16.0
if ($LASTEXITCODE -ne 0) { throw 'Installing build dependencies failed' }
& $buildPython -m unittest discover -s $PSScriptRoot -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) { throw 'Source index tests failed' }
$bundleArguments = @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--name', 'SourceIndexer',
    '--collect-all', 'tree_sitter_c', '--collect-all', 'pcpp', '--add-data', "$PSScriptRoot\board_profiles.json;.",
    '--distpath', "$projectRoot\bin\source_relations", '--workpath', "$BuildRoot\freeze", '--specpath', $BuildRoot)
if (Test-Path -LiteralPath "$PSScriptRoot\config") { $bundleArguments += @('--add-data', "$PSScriptRoot\config;config") }
$bundleArguments += "$PSScriptRoot\index_source.py"
& $buildPython @bundleArguments
if ($LASTEXITCODE -ne 0) { throw 'Packaging indexer failed' }
foreach ($component in @('plugin', 'host')) {
    $directory = Join-Path $BuildRoot $component
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $project = "$PSScriptRoot\plugin\SourceRelations.pro"
    if ($component -eq 'host') { $project = "$projectRoot\LogDiagnosis.pro" }
    Push-Location -LiteralPath $directory
    try {
        & "$qtBin\qmake.exe" $project 'CONFIG+=release'
        if ($LASTEXITCODE -ne 0) { throw "qmake failed for $component" }
        & "$compilerBin\mingw32-make.exe" -j4
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for $component" }
    } finally { Pop-Location }
}
New-Item -ItemType Directory -Force -Path "$projectRoot\bin\plugins" | Out-Null
Copy-Item -LiteralPath "$BuildRoot\plugin\release\SourceRelations.dll" -Destination "$projectRoot\bin\plugins\SourceRelations.dll"
Copy-Item -LiteralPath "$BuildRoot\host\release\LogDiagnosis.exe" -Destination "$projectRoot\bin\LogDiagnosis.exe"
$profiles = Get-Content -LiteralPath "$PSScriptRoot\board_profiles.json" -Raw | ConvertFrom-Json
foreach ($entry in $profiles.PSObject.Properties) {
    $entry.Value.configuration_header = "../../board_config/$($entry.Name)/PROJECT_OR_BOARD_PTCL.h"
}
$profiles | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$projectRoot\bin\source_relations\board_profiles.json" -Encoding UTF8
if (Test-Path -LiteralPath "$PSScriptRoot\config") {
    Copy-Item -LiteralPath "$PSScriptRoot\config" -Destination "$projectRoot\bin\source_relations" -Recurse -Force
}
New-Item -ItemType Directory -Force -Path "$projectRoot\bin\skills\crash-log-rca" | Out-Null
Copy-Item -LiteralPath "$projectRoot\skills\crash-log-rca\SKILL.md" -Destination "$projectRoot\bin\skills\crash-log-rca\SKILL.md"
Write-Output "Built host, query plugin, and standalone indexer in $projectRoot\bin"
