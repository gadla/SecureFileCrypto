# 🔐 SecureFileCrypto PowerShell Module

SecureFileCrypto is a lightweight PowerShell module for AES-based file encryption and decryption. It provides three core functions:

* `Encrypt-FileWithAes` — encrypts files using a generated or existing AES key and IV
* `Decrypt-FileWithAes` — decrypts encrypted files and writes the plaintext back to disk
* `Get-DecryptedContentFromFile` — decrypts an encrypted file and returns the content directly into memory (as a string)

All functions support robust error handling, `-Force` overwrites, and helpful colored output.

---

## 📦 Installation

Clone or copy the module into your local PowerShell module directory:

```powershell
$modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\SecureFileCrypto"
New-Item -ItemType Directory -Path $modulePath -Force
Copy-Item .\SecureFileCrypto\* -Destination $modulePath -Recurse
Import-Module SecureFileCrypto
```

---


## 🔧 Function Reference

### 1️⃣ Encrypt-FileWithAes

Encrypts a file using either a **newly** generated key/IV or **existing** ones.

#### 🔹 Generate and save new key/IV:

```powershell
Protect-FileWithAes `
  -InputFilePath ".\secret.txt" `
  -OutKeyPath ".\key.bin" `
  -OutIVPath ".\iv.bin" `
  -EncryptedFilePath ".\secret.enc"

```
🧠 Use this when encrypting for the first time and storing keys for later decryption.

#### 🔹 Use existing key/IV:

```powershell
Protect-FileWithAes `
  -InputFilePath ".\secret.txt" `
  -InKeyPath ".\key.bin" `
  -InIVPath ".\iv.bin" `
  -EncryptedFilePath ".\secret.enc"
```
🔁 Ideal for consistently encrypting multiple files with the same key/IV.

#### ✅ Force overwrite:

```powershell
Encrypt-FileWithAes -InputFilePath ".\report.txt" -InKeyPath ".\key.bin" -InIVPath ".\iv.bin" -Force
```
Overwrites the existing output file if it already exists.
---

### 2️⃣ UnProtect-FileWithAes

Decrypts an encrypted file using the specified key/IV and writes the output to a given path.

```powershell
UnProtect-FileWithAes `
  -InputFilePath ".\secret.enc" `
  -KeyPath ".\key.bin" `
  -IVPath ".\iv.bin" `
  -DecryptedFilePath ".\secret.txt"

```

🗂️ Use -Force if the decrypted file path already exists and should be overwritten.

---

### 3️⃣ Get-DecryptedContentFromFile

Returns the plaintext **directly to memory** (as a `[string]`). Great for scripting or pipelines.

```powershell
$plainText = Get-DecryptedContentFromFile `
  -InputFilePath ".\secret.enc" `
  -KeyPath ".\key.bin" `
  -IVPath ".\iv.bin"

Write-Host "🔓 Decrypted content: $plainText"

```
This is useful for scripts and automation scenarios where you don’t want to store the decrypted content on disk.

---

## ❗ Usage Tips & Security Best Practices

| ⚠️ Best Practice                     | 💡 Why It Matters                                 |
| ------------------------------------ | ------------------------------------------------- |
| 🔐 Treat key/IV files like passwords | Leaking these allows anyone to decrypt your files |
| 📁 Use `-Force` with care            | Prevents accidental overwrites                    |
| 🔎 Verify paths and permissions      | Especially in scheduled scripts or CI/CD          |
| 🧹 Securely delete sensitive files   | Use tools that properly erase file content        |
| 🔄 Reuse keys only if needed         | Frequent key rotation increases security          |
values.

---

## 📚 Requirements

* PowerShell 5.1+
* Windows OS (relies on `System.Security.Cryptography.AesCryptoServiceProvider`)



---

## 👨‍💻 Author

* **Gadi Lev-Ari**
* Github page https://github.com/gadla
 