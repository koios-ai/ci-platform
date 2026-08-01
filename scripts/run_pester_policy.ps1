$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 2) {
    throw "usage: run_pester_policy.ps1 <module-root> <output-path>"
}

$moduleRoot = $args[0]
$outputPath = $args[1]
$manifest = Join-Path $moduleRoot "Pester/5.7.1/Pester.psd1"
Import-Module $manifest -RequiredVersion "5.7.1" -Force -ErrorAction Stop

$configuration = New-PesterConfiguration
$configuration.Run.Path = "/workspace/target/tests"
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = "Detailed"
$configuration.TestResult.Enabled = $true
$configuration.TestResult.OutputFormat = "NUnitXml"
$configuration.TestResult.OutputPath = $outputPath
$result = Invoke-Pester -Configuration $configuration

if ($result.TotalCount -le 0 -or $result.FailedCount -ne 0 -or $result.SkippedCount -ne 0 -or $result.NotRunCount -ne 0) {
    throw "Pester did not execute a non-empty, fully green, zero-skip suite"
}
