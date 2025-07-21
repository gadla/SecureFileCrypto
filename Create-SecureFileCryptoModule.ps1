# Generate module metadata using splatting
$manifestParams = @{
    Path              = ".\SecureFileCrypto.psd1"
    RootModule        = "SecureFileCrypto.psm1"
    ModuleVersion     = "1.0.0"
    GUID              = [guid]::NewGuid()
    Author            = "Gadi Lev-Ari"
    CompanyName       = "Gadla Solutions"
    Description       = "Module to securely encrypt and decrypt files using AES-256 with optional key/IV generation."
    PowerShellVersion = "5.1"
    FunctionsToExport = @(
        'Protect-FileWithAes',
        'Unprotect-FileWithAes',
        'Get-DecryptedContentFromFile'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}

New-ModuleManifest @manifestParams
