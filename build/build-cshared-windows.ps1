param ([switch] $RebuildAll)

Push-Location "$PSScriptRoot\..\src\go"

Remove-Item -r -fo bin -ea SilentlyContinue

$lib_name = "ProtonSecurity"

$env:GOFLAGS = "-trimpath"
$env:CGO_ENABLED = "1"
$env:CGO_LDFLAGS = "-s -w"

$env:GOARCH = "amd64"

$outputPath = "bin\runtimes\win-x64\native\$lib_name.dll"
$buildCommand = "go build -buildmode=c-shared -v -o `"$outputPath`""
if ($RebuildAll) {
	$buildCommand += " -a"
}

Invoke-Expression $buildCommand

Pop-Location