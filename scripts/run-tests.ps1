[CmdletBinding()]
param(
    [string]$Python = "python",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PytestArguments
)

$ErrorActionPreference = "Stop"
$artifactsParent = if ($env:CI_PLATFORM_TEST_ARTIFACTS_DIR) {
    $env:CI_PLATFORM_TEST_ARTIFACTS_DIR
} else {
    [System.IO.Path]::GetTempPath()
}
New-Item -ItemType Directory -Force -Path $artifactsParent | Out-Null
$temporaryRoot = Join-Path $artifactsParent ("ci-platform-pytest-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
$exitCode = 1

try {
    & $Python -B -m pytest @PytestArguments -p no:cacheprovider "--basetemp=$temporaryRoot\basetemp" "--junitxml=$temporaryRoot\pytest-junit.xml"
    if ($null -ne $LASTEXITCODE) {
        $exitCode = $LASTEXITCODE
    }
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

exit $exitCode
