param(
    [ValidateSet("default", "divert_cgo", "divert_embedded")]
    [string]$Mode = "divert_cgo",

    [string]$Output = ".\build\tls-mitm.exe"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $repoRoot $Output
$outputDir = Split-Path -Parent $outputPath

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$tags = switch ($Mode) {
    "default" { "" }
    "divert_cgo" { "divert_cgo" }
    "divert_embedded" { "divert_embedded" }
}

$arguments = @("build")
if ($tags -ne "") {
    $arguments += @("-tags", $tags)
}
$arguments += @("-o", $outputPath, ".\cmd\tls-mitm")

Write-Host "构建模式: $Mode"
Write-Host "输出文件: $outputPath"
Write-Host "执行命令: go $($arguments -join ' ')"

Push-Location $repoRoot
try {
    $originalCgoEnabled = $env:CGO_ENABLED
    if ($Mode -eq "divert_cgo") {
        $env:CGO_ENABLED = "1"
    }
    & go @arguments
}
finally {
    $env:CGO_ENABLED = $originalCgoEnabled
    Pop-Location
}
