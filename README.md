# Proton.Security

Copyright (c) 2024 Proton AG

Provides SRP and PGP functionality to .NET projects by wrapping GoSRP and GopenPGP.

## License

The code and data files in this repository are licensed under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE.md) or https://www.gnu.org/licenses/ for a copy of the license.

## Build

1. Build the Go C bindings package into a shared library by running the appropriate script in the `build` folder.
2. Build the .NET project using `dotnet pack -p:Version=<version> -p:PackageVersion=<package version>`.

## Usage

Push the output NuGet package to a repository.
Add the output NuGet package to your .NET project.

## Contributions

Contributions are not accepted at the moment.
