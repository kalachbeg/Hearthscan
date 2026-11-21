# Run Hearthscan on Windows without installing it.
#
#   irm https://raw.githubusercontent.com/kalachbeg/Hearthscan/main/launch/run.ps1 | iex
#
# With arguments:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kalachbeg/Hearthscan/main/launch/run.ps1))) scan --lang tr
#
# It downloads hearthscan-windows-x64.exe and SHA256SUMS from the latest
# release, checks the program's SHA-256, runs it from a new temporary folder
# and deletes that folder when the program ends, also after Ctrl+C or an
# error. Nothing is installed, no setting is changed and no admin rights are
# needed. Windows on ARM runs the x64 build. Works in Windows PowerShell 5.1
# and in PowerShell 7.
#
# $env:HEARTHSCAN_VERSION = '2.0.0' runs that release instead of the latest one.
# $env:HEARTHSCAN_DOWNLOAD_BASE replaces the download address. It is only
# meant for testing against a local copy of a release.
#
# The whole script runs in a scope of its own, so nothing it defines is left
# behind in the session. Afterwards $LASTEXITCODE holds the program's exit code.

& {
    Set-StrictMode -Off
    $ErrorActionPreference = 'Stop'
    # A failing program is not an error of this script.
    $PSNativeCommandUseErrorActionPreference = $false
    # The progress bar slows Invoke-WebRequest down a lot in Windows PowerShell.
    $ProgressPreference = 'SilentlyContinue'

    $repo = 'https://github.com/kalachbeg/Hearthscan'
    $fromSource = "uvx --from git+$repo hearthscan"
    $asset = 'hearthscan-windows-x64.exe'

    function Write-Step([string]$Text) {
        Write-Host $Text
    }

    function Write-Problem([string]$Text) {
        Write-Host $Text -ForegroundColor Yellow
    }

    function Write-NotFound {
        if ($env:HEARTHSCAN_VERSION) {
            Write-Problem "Hearthscan $version was not found at $base"
        } else {
            Write-Problem 'There is no Hearthscan release to download yet.'
        }
        Write-Problem 'You can run it from source with uv instead:'
        Write-Problem "  $fromSource"
    }

    function Test-NotFound($Failure) {
        $response = $Failure.Exception.Response
        return ($null -ne $response -and [int]$response.StatusCode -eq 404)
    }

    # Saves $Url to $Path. Returns $false when the server says there is no such file.
    function Save-Download([string]$Url, [string]$Path) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
            return $true
        } catch {
            $failure = $_
        }
        if (Test-NotFound $failure) {
            return $false
        }
        # Windows PowerShell cannot read the 404 page of github.com and reports
        # a closed connection instead. A HEAD request gets a clean answer.
        if ($null -eq $failure.Exception.Response) {
            try {
                [void](Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing)
            } catch {
                if (Test-NotFound $_) {
                    return $false
                }
            }
        }
        throw $failure
    }

    # Downloads and checks the program. Returns its path, or $null when it
    # must not be run.
    function Get-Hearthscan([string]$Folder) {
        Write-Step "Downloading $asset from $release..."
        $sums = Join-Path $Folder 'SHA256SUMS'
        if (-not (Save-Download "$base/SHA256SUMS" $sums)) {
            Write-NotFound
            return $null
        }
        $expected = $null
        foreach ($line in [IO.File]::ReadAllLines($sums)) {
            $fields = $line.Trim() -split '\s+'
            $named = $fields.Count -eq 2 -and ($fields[1] -eq $asset -or $fields[1] -eq "*$asset")
            if ($named -and $fields[0] -match '^[0-9A-Fa-f]{64}$') {
                $expected = $fields[0].ToLowerInvariant()
                break
            }
        }
        if (-not $expected) {
            Write-Problem "SHA256SUMS has no checksum for $asset, so it will not be run."
            return $null
        }
        $exe = Join-Path $Folder $asset
        if (-not (Save-Download "$base/$asset" $exe)) {
            Write-NotFound
            return $null
        }
        Write-Step 'Checking the SHA-256 checksum...'
        $actual = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $expected) {
            Write-Problem "The SHA-256 of $asset does not match SHA256SUMS, so it was not run."
            return $null
        }
        return $exe
    }

    # Only .NET calls in here: they also work while Ctrl+C is stopping the script.
    function Remove-TempFolder([string]$Path) {
        # The program can hold on to its files for a moment after it ends.
        for ($try = 0; $try -lt 40; $try++) {
            try {
                if ([IO.Directory]::Exists($Path)) {
                    [IO.Directory]::Delete($Path, $true)
                }
                return
            } catch {
                [Threading.Thread]::Sleep(250)
            }
        }
        $Host.UI.WriteWarningLine("Could not delete the temporary folder $Path; it can be removed by hand.")
    }

    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
        Write-Problem 'This script is for Windows. On macOS and Linux use run.sh:'
        Write-Problem '  curl -fsSL https://raw.githubusercontent.com/kalachbeg/Hearthscan/main/launch/run.sh | sh'
        $global:LASTEXITCODE = 1
        return
    }
    if (-not [Environment]::Is64BitOperatingSystem) {
        Write-Problem 'Hearthscan needs 64-bit Windows.'
        $global:LASTEXITCODE = 1
        return
    }
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
        Write-Step 'Windows on ARM: using the x64 build, which Windows runs through emulation.'
    }

    if ($env:HEARTHSCAN_VERSION) {
        $version = $env:HEARTHSCAN_VERSION -replace '^v', ''
        if ($version -notmatch '^[0-9A-Za-z.+-]+$') {
            Write-Problem "HEARTHSCAN_VERSION should look like 2.0.0, not '$env:HEARTHSCAN_VERSION'."
            $global:LASTEXITCODE = 1
            return
        }
        $base = "$repo/releases/download/v$version"
        $release = "release $version"
    } else {
        $base = "$repo/releases/latest/download"
        $release = 'the latest release'
    }
    if ($env:HEARTHSCAN_DOWNLOAD_BASE) {
        $base = $env:HEARTHSCAN_DOWNLOAD_BASE.TrimEnd('/')
    }

    $exitCode = 1
    $tmp = $null
    $savedTemp = $env:TEMP
    $savedTmp = $env:TMP
    $savedProtocols = [Net.ServicePointManager]::SecurityProtocol
    try {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            # Windows PowerShell can default to TLS 1.0, which GitHub refuses.
            [Net.ServicePointManager]::SecurityProtocol = $savedProtocols -bor [Net.SecurityProtocolType]::Tls12
        }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('hearthscan-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
        [void][IO.Directory]::CreateDirectory($tmp)

        $exe = Get-Hearthscan $tmp
        if ($exe) {
            Write-Step 'Checksum OK. Starting Hearthscan.'
            # The program unpacks itself into a temporary folder of its own.
            # TEMP and TMP keep that folder inside this one as well.
            $env:TEMP = $tmp
            $env:TMP = $tmp
            & $exe @args
            $exitCode = $LASTEXITCODE
        }
    } catch {
        Write-Problem "Hearthscan could not be started: $($_.Exception.Message)"
    } finally {
        $env:TEMP = $savedTemp
        $env:TMP = $savedTmp
        [Net.ServicePointManager]::SecurityProtocol = $savedProtocols
        if ($tmp) {
            Remove-TempFolder $tmp
        }
    }
    $global:LASTEXITCODE = $exitCode
    # Saved and started as a script file, end that script with the same code.
    if ($PSCommandPath) {
        exit $exitCode
    }
} @args
