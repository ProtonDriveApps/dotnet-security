param ([switch] $RebuildAll, [bool] $IsArm)

Push-Location "$PSScriptRoot\..\src\go"

Remove-Item -r -fo bin -ea SilentlyContinue

$lib_name = "ProtonSecurity"

$env:GOFLAGS = "-trimpath"
$env:CGO_ENABLED = "1"
$env:CGO_LDFLAGS = "-s -w"

$env:GOARCH = If($IsArm) { "arm64" } Else { "amd64" }
$pathArch = If($IsArm) { "win-arm64" } Else { "win-x64" }

$outputPath = "bin\runtimes\$pathArch\native\$lib_name.dll"
$buildCommand = "go build -buildmode=c-shared -v -o `"$outputPath`""
if ($RebuildAll) {
	$buildCommand += " -a"
}

Invoke-Expression $buildCommand

Pop-Location