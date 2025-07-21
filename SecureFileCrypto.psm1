<#
.SYNOPSIS
Encrypts a file using AES-256 with either a newly generated or existing key and IV.

.DESCRIPTION
Encrypts the content of a given input file using AES encryption in CBC mode. The user can choose to generate a new AES key and IV,
or supply existing key and IV files. The output file will be saved with a `_encrypted` suffix.

.PARAMETER InputFilePath
The path to the file that should be encrypted.

.PARAMETER OutKeyPath
If generating a new key/IV, specifies the path to save the AES key.

.PARAMETER OutIVPath
If generating a new key/IV, specifies the path to save the AES IV.

.PARAMETER InKeyPath
If using existing key/IV, specifies the path to the AES key file.

.PARAMETER InIVPath
If using existing key/IV, specifies the path to the AES IV file.

.PARAMETER EncryptedFilePath
Full path (absolute or relative) where the encrypted file will be saved.

.PARAMETER Force 
If specified, overwrites the encrypted output file if it already exists.

.EXAMPLE
Protect-FileWithAes -InputFilePath "C:\Financials.xlsx" -OutKeyPath "C:\key.bin" -OutIVPath "C:\iv.bin" -EncryptedFilePath ".\Financials.enc"

Encrypts the file 'Financials.xlsx' using a newly generated AES key and IV,
saving the encrypted output to 'Financials.enc' and storing the key/IV separately.
This scenario is useful when preparing sensitive reports for secure long-term archiving
or uploading to an external backup destination.

.EXAMPLE
Protect-FileWithAes -InputFilePath "C:\Financials.xlsx" -InKeyPath "C:\key.bin" -InIVPath "C:\iv.bin" -EncryptedFilePath "Financials.enc"

Decrypts the file 'Financials.xlsx' using an existing AES key and IV,
saving the encrypted output to 'Financials.enc'. This is useful when you have previously created your key and IV files
and want to encrypt another file with the same parameters, ensuring consistent encryption across multiple files.

.EXAMPLE
Protect-FileWithAes -InputFilePath "C:\data.txt" -InKeyPath "C:\key.bin" -InIVPath "C:\iv.bin" -EncryptedFilePath "data.enc" -Force

Decrypts the file 'data.txt' using an existing AES key and IV,
saving the encrypted output to 'data.enc'. The `-Force` parameter allows overwriting the existing 'data.enc' file if it already exists.


.OUTPUTS
[bool]

.NOTES
Author: Gadi Lev-Ari
#>
function Protect-FileWithAes {

[CmdletBinding(PositionalBinding = $false)]
[OutputType([bool])]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Full path to the input file that will be encrypted.")]
    [string]$InputFilePath,

    [Parameter(Mandatory = $true, ParameterSetName = "GenerateNew", HelpMessage = "Path to save the newly generated AES key file.")]
    [string]$OutKeyPath,

    [Parameter(Mandatory = $true, ParameterSetName = "GenerateNew", HelpMessage = "Path to save the newly generated AES IV file.")]
    [string]$OutIVPath,

    [Parameter(Mandatory = $true, ParameterSetName = "UseExisting", HelpMessage = "Path to an existing AES key file to use for encryption.")]
    [string]$InKeyPath,

    [Parameter(Mandatory = $true, ParameterSetName = "UseExisting", HelpMessage = "Path to an existing AES IV file to use for encryption.")]
    [string]$InIVPath,

    [Parameter(Mandatory = $true, HelpMessage = "Path where the encrypted output file will be saved.")]
    [string]$EncryptedFilePath,

    [Parameter()]
    [switch]$Force
)


    try {
        
        if (-not (Test-Path $InputFilePath)) {
            Write-Error "❌ Input file not found: '$ResolvedInputPath'"
            return $false
        }

        switch ($PSCmdlet.ParameterSetName) {
            "GenerateNew" {
                $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
                $aes.GenerateKey()
                $aes.GenerateIV()

                # Create files
                $paths = @($OutKeyPath, $OutIVPath)
                foreach ($path in $paths) {
                    New-Item -Path $path -ItemType File -Force -ErrorAction Stop | Out-Null
                }

                # Get full path of the input file
                if (-not ([System.IO.Path]::IsPathRooted($OutKeyPath))) {
                    $OutKeyPath = Join-Path -Path (Get-Location) -ChildPath $OutKeyPath
                }
                if (-not ([System.IO.Path]::IsPathRooted($OutIVPath))) {
                    $OutIVPath = Join-Path -Path (Get-Location) -ChildPath $OutIVPath
                }
                # Write key and IV to files
                [System.IO.File]::WriteAllBytes($OutKeyPath, $aes.Key)
                [System.IO.File]::WriteAllBytes($OutIVPath, $aes.IV)

                Write-Host "🗝️  Generated key: $OutKeyPath" -ForegroundColor Cyan
                Write-Host "🧬 Generated IV:  $OutIVPath" -ForegroundColor Cyan
            }
            "UseExisting" {
                if (-not (Test-Path $InKeyPath)) {
                    Write-Error "❌ Key file not found: '$InKeyPath'"
                    return $false
                }
                if (-not (Test-Path $InIVPath)) {
                    Write-Error "❌ IV file not found: '$InIVPath'"
                    return $false
                }
                $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
                $aes.Key = [System.IO.File]::ReadAllBytes($InKeyPath)
                $aes.IV  = [System.IO.File]::ReadAllBytes($InIVPath)

                Write-Host "✅ Loaded key from: $InKeyPath" -ForegroundColor Cyan
                Write-Host "✅ Loaded IV from:  $InIVPath" -ForegroundColor Cyan
            }
        }

        # Get full path of the EncryptedFilePath
        if (-not ([System.IO.Path]::IsPathRooted($EncryptedFilePath))) {
            $EncryptedFilePath = Join-Path -Path (Get-Location) -ChildPath $EncryptedFilePath
        }   
        #$EncryptedFilePath = [System.IO.Path]::ChangeExtension($ResolvedInputPath, $null) + "_encrypted" + [System.IO.Path]::GetExtension($ResolvedInputPath)
        if ((Test-Path $EncryptedFilePath) -and (-not $Force)) {
            Write-Error "❌ Encrypted file already exists. Use -Force to overwrite."
            return $false
        }

         # Get full path of the InputFilePath
        if (-not ([System.IO.Path]::IsPathRooted($InputFilePath))) {
            $InputFilePath = Join-Path -Path (Get-Location) -ChildPath $InputFilePath
        }
        try {
            $content = [System.IO.File]::ReadAllBytes($inputFilePath)
            $encryptor = $aes.CreateEncryptor()
            $encrypted = $encryptor.TransformFinalBlock($content, 0, $content.Length)
            [System.IO.File]::WriteAllBytes($EncryptedFilePath, $encrypted)

            Write-Host "🔒 Encrypted file saved to: $EncryptedFilePath" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "❌ Failed to encrypt or write output file: $_"
            return $false
        }
    }
    catch {
        Write-Error "❌ Unexpected failure: $_"
        return $false
    }
}

function UnProtect-FileWithAes {
<#
.SYNOPSIS
Decrypts an AES-encrypted file using a provided key and IV.

.DESCRIPTION
Takes an AES-encrypted input file and decrypts it using a provided key and IV file.
The output is saved to the specified DecryptedFilePath. Overwrites if -Force is used.

.PARAMETER InputFilePath
The path to the AES-encrypted input file.

.PARAMETER KeyPath
Path to the AES key used during encryption.

.PARAMETER IVPath
Path to the AES IV used during encryption.

.PARAMETER DecryptedFilePath
Path to save the resulting decrypted output file.

.PARAMETER Force
If specified, overwrites the decrypted output file if it already exists.

.EXAMPLE
UnProtect-FileWithAes -InputFilePath "C:\data_encrypted.txt" `
                      -KeyPath "C:\key.bin" `
                      -IVPath "C:\iv.bin" `
                      -DecryptedFilePath "C:\data.txt"

Decrypts the encrypted file and saves the result to the specified output file.

.EXAMPLE
UnProtect-FileWithAes -InputFilePath "C:\data_encrypted.txt" `
                      -KeyPath "C:\key.bin" `
                      -IVPath "C:\iv.bin" `
                      -DecryptedFilePath "C:\data.txt" `
                      -Force

Overwrites the target output file if it already exists.

.OUTPUTS
[bool]

.NOTES
Author: Gadi Lev-Ari
#>

    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Full path to the AES-encrypted input file.")]
        [string]$InputFilePath,

        [Parameter(Mandatory = $true, HelpMessage = "Path to the AES key used during encryption.")]
        [string]$KeyPath,

        [Parameter(Mandatory = $true, HelpMessage = "Path to the AES IV used during encryption.")]
        [string]$IVPath,

        [Parameter(Mandatory = $true, HelpMessage = "Full path to save the decrypted output file.")]
        [string]$DecryptedFilePath,

        [Parameter()]
        [switch]$Force
    )

    try {
        if (-not ([System.IO.Path]::IsPathRooted($InputFilePath))) {
            $InputFilePath = Join-Path -Path (Get-Location) -ChildPath $InputFilePath
        }
        if (-not (Test-Path $InputFilePath)) {
            Write-Error "❌ Input file not found: '$InputFilePath'"
            return $false
        }

        if (-not ([System.IO.Path]::IsPathRooted($KeyPath))) {
            $KeyPath = Join-Path -Path (Get-Location) -ChildPath $KeyPath
        }
        if (-not (Test-Path $KeyPath)) {
            Write-Error "❌ Key file not found: '$KeyPath'"
            return $false
        }

        if (-not ([System.IO.Path]::IsPathRooted($IVPath))) {
            $IVPath = Join-Path -Path (Get-Location) -ChildPath $IVPath
        }
        if (-not (Test-Path $IVPath)) {
            Write-Error "❌ IV file not found: '$IVPath'"
            return $false
        }

        if (-not ([System.IO.Path]::IsPathRooted($DecryptedFilePath))) {
            $DecryptedFilePath = Join-Path -Path (Get-Location) -ChildPath $DecryptedFilePath
        }

        if ((Test-Path $DecryptedFilePath) -and (-not $Force)) {
            Write-Error "❌ Decrypted file already exists. Use -Force to overwrite."
            return $false
        }

        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Key = [System.IO.File]::ReadAllBytes($KeyPath)
        $aes.IV  = [System.IO.File]::ReadAllBytes($IVPath)

        $content = [System.IO.File]::ReadAllBytes($InputFilePath)
        $decryptor = $aes.CreateDecryptor()

        try {
            $decrypted = $decryptor.TransformFinalBlock($content, 0, $content.Length)
            [System.IO.File]::WriteAllBytes($DecryptedFilePath, $decrypted)
            Write-Host "🔓 Decrypted file saved to: $DecryptedFilePath" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "❌ Failed to decrypt or write output file: $_"
            return $false
        }
    }
    catch {
        Write-Error "❌ Unexpected failure: $_"
        return $false
    }
}


function Get-DecryptedContentFromFile {
<#
.SYNOPSIS
Decrypts AES-encrypted content from a file and returns the decrypted string.

.DESCRIPTION
Reads an encrypted file, decrypts its content using the provided AES key and IV, and returns the plaintext content as a [string].
Does not save the decrypted content to disk.

.PARAMETER InputFilePath
The full path to the AES-encrypted input file.

.PARAMETER KeyPath
The full path to the AES key file (in binary format).

.PARAMETER IVPath
The full path to the AES IV file (in binary format).

.EXAMPLE
Get-DecryptedContentFromFile -InputFilePath "C:\secret.enc" -KeyPath "C:\key.bin" -IVPath "C:\iv.bin"

Decrypts the content of 'secret.enc' and returns it as a plaintext string.

.OUTPUTS
[string]

.NOTES
Author: Gadi Lev-Ari
#>

    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputFilePath,

        [Parameter(Mandatory = $true)]
        [string]$KeyPath,

        [Parameter(Mandatory = $true)]
        [string]$IVPath
    )

    try {
        if (-not ([System.IO.Path]::IsPathRooted($InputFilePath))) {
            $ResolvedInputPath = Join-Path -Path (Get-Location) -ChildPath $InputFilePath
        }
        if (-not (Test-Path $ResolvedInputPath)) {
            Write-Error "❌ Input file not found: '$ResolvedInputPath'"
            return
        }

        if (-not ([System.IO.Path]::IsPathRooted($KeyPath))) {
            $KeyPath = Join-Path -Path (Get-Location) -ChildPath $KeyPath
        }
        if (-not (Test-Path $KeyPath)) {
            Write-Error "❌ Key file not found: '$KeyPath'"
            return
        }

        if (-not ([System.IO.Path]::IsPathRooted($IVPath))) {
            $IVPath = Join-Path -Path (Get-Location) -ChildPath $IVPath
        }
        if (-not (Test-Path $IVPath)) {
            Write-Error "❌ IV file not found: '$IVPath'"
            return
        }

        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Key = [System.IO.File]::ReadAllBytes($KeyPath)
        $aes.IV  = [System.IO.File]::ReadAllBytes($IVPath)

        $content = [System.IO.File]::ReadAllBytes($ResolvedInputPath)
        $decryptor = $aes.CreateDecryptor()

        try {
            $decrypted = $decryptor.TransformFinalBlock($content, 0, $content.Length)
            $plaintext = [System.Text.Encoding]::UTF8.GetString($decrypted)
            return $plaintext
        }
        catch {
            Write-Error "❌ Failed to decrypt the file content: $_"
            return
        }
    }
    catch {
        Write-Error "❌ Unexpected failure: $_"
        return
    }
}
