# FigJuicer.psm1

# Dot-source all private functions (internal use only)
Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -File | ForEach-Object {
    try {
        . $_.FullName
    }
    catch {
        Write-Warning "Failed to load private function: $($_)"
    }
}

# Dot-source all public functions (exported via .psd1)
Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -File | ForEach-Object {
    try {
        . $_.FullName
    }
    catch {
        Write-Warning "Failed to load public function: $($_)"
    }
}
