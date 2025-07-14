<#
.SYNOPSIS
  Advanced DPAPI Wrapper Module with Dynamic XOR and Per-Character Shift Obfuscation
.DESCRIPTION
  Provides Protect-Data and Unprotect-Data functions that wrap DPAPI encryption with
  layered obfuscation:
  - Forward XOR using dynamic slices of machine\username.
  - Per-character shifting from a 1000-pattern table generated deterministically based on encryptedKey.
  - Reverse XOR using reversed slices of machine\username.
  - Pattern index extracted from encryptedKey hash.
  - Stateless pattern regeneration.
.EXAMPLE
  $encryptedKey = "<your base64 encrypted AES key>"
  $plaintext = "SensitiveData123!"
  $cipher = Protect-Data -PlainText $plaintext -EncryptedKey $encryptedKey
  Write-Host "Encrypted: $cipher"
  $decoded = Unprotect-Data -CipherText $cipher -EncryptedKey $encryptedKey
  Write-Host "Decrypted: $decoded"
#>

function Get-UserMachineString {
    return "$($env:COMPUTERNAME)\$($env:USERNAME)"
}

function Get-Slice {
    param(
        [string]$inputStr,
        [int]$patternIndex,
        [switch]$reverse
    )
    $len = $inputStr.Length
    switch ($patternIndex % 5) {
        0 { $slice = $inputStr }
        1 { $slice = $inputStr.Substring(0, [Math]::Min(6, $len)) }
        2 { $slice = $inputStr.Substring([Math]::Max(0, $len - 6)) }
        3 { $slice = ($inputStr.ToCharArray() | Sort-Object) -join '' }
        4 { $slice = -join ($inputStr.ToCharArray() | [array]::Reverse($_)) }
        default { $slice = $inputStr }
    }
    if ($reverse) {
        $slice = -join ($slice.ToCharArray() | [array]::Reverse($_))
    }
    return $slice
}

function XOR-Data {
    param(
        [byte[]]$data,
        [byte[]]$key
    )
    $result = New-Object byte[] $data.Length
    for ($i=0; $i -lt $data.Length; $i++) {
        $result[$i] = $data[$i] -bxor $key[$i % $key.Length]
    }
    return $result
}

function Get-HashAndPatternIndex {
    param([string]$encryptedKey)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($encryptedKey)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    $sha256.Dispose()
    $hashHex = [BitConverter]::ToString($hashBytes) -replace '-'
    $last4 = $hashHex.Substring($hashHex.Length - 4, 4)
    $patternIndex = [Convert]::ToInt32($last4, 16) % 1000
    return @{ HashBytes = $hashBytes; PatternIndex = $patternIndex }
}

function Generate-ShiftTable {
    param(
        [byte[]]$hashBytes,
        [int]$patternCount = 1000
    )
    $seed = [BitConverter]::ToInt32($hashBytes,0)
    $rand = New-Object System.Random $seed
    $patterns = New-Object 'byte[,]' $patternCount, 256

    function Get-Shift {
        param([char]$c)
        switch ($true) {
            {$_ -and $c -ge 'a' -and $c -le 'd'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'e' -and $c -le 'h'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'i' -and $c -le 'l'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'm' -and $c -le 'p'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'q' -and $c -le 't'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'u' -and $c -le 'x'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'y' -and $c -le 'z'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'A' -and $c -le 'D'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'E' -and $c -le 'H'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'I' -and $c -le 'L'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'M' -and $c -le 'P'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'Q' -and $c -le 'T'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'U' -and $c -le 'X'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge 'Y' -and $c -le 'Z'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge '0' -and $c -le '1'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge '2' -and $c -le '3'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge '4' -and $c -le '5'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge '6' -and $c -le '7'} { return $rand.Next(-5,6) }
            {$_ -and $c -ge '8' -and $c -le '9'} { return $rand.Next(-5,6) }
            default { return $rand.Next(-5,6) }
        }
    }

    for ($p = 0; $p -lt $patternCount; $p++) {
        for ($i = 0; $i -lt 256; $i++) {
            $c = [char][byte]$i
            $shift = Get-Shift $c
            $patterns[$p, $i] = [byte](($i + $shift + 256) % 256)
        }
    }
    return $patterns
}

function Apply-Shift {
    param(
        [byte[]]$data,
        [byte[,]]$shiftTable,
        [int]$patternIndex
    )
    $result = New-Object byte[] $data.Length
    for ($i=0; $i -lt $data.Length; $i++) {
        $result[$i] = $shiftTable[$patternIndex, $data[$i]]
    }
    return $result
}

function Invert-Shift {
    param(
        [byte[]]$data,
        [byte[,]]$shiftTable,
        [int]$patternIndex
    )
    $result = New-Object byte[] $data.Length
    for ($i=0; $i -lt $data.Length; $i++) {
        $val = -1
        for ($j=0; $j -lt 256; $j++) {
            if ($shiftTable[$patternIndex, $j] -eq $data[$i]) {
                $val = $j
                break
            }
        }
        if ($val -eq -1) { $val = $data[$i] }
        $result[$i] = [byte]$val
    }
    return $result
}

function Protect-Data {
    param(
        [string]$PlainText,
        [string]$EncryptedKey
    )
    $hashInfo = Get-HashAndPatternIndex -encryptedKey $EncryptedKey
    $patternIndex = $hashInfo.PatternIndex
    $hashBytes = $hashInfo.HashBytes

    if (-not $script:ShiftTables) {
        $script:ShiftTables = Generate-ShiftTable -hashBytes $hashBytes -patternCount 1000
    }

    $userMachine = Get-UserMachineString
    $forwardSlice = Get-Slice -inputStr $userMachine -patternIndex $patternIndex
    $reverseSlice = Get-Slice -inputStr $userMachine -patternIndex $patternIndex -reverse

    $keyForward = [System.Text.Encoding]::UTF8.GetBytes($forwardSlice)
    $keyReverse = [System.Text.Encoding]::UTF8.GetBytes($reverseSlice)

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $xoredForward = XOR-Data -data $plainBytes -key $keyForward
    $shifted = Apply-Shift -data $xoredForward -shiftTable $script:ShiftTables -patternIndex $patternIndex
    $xoredReverse = XOR-Data -data $shifted -key $keyReverse

    $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect($xoredReverse, $null, 'CurrentUser')
    return [Convert]::ToBase64String($protectedBytes)
}

function Unprotect-Data {
    param(
        [string]$CipherText,
        [string]$EncryptedKey
    )
    $hashInfo = Get-HashAndPatternIndex -encryptedKey $EncryptedKey
    $patternIndex = $hashInfo.PatternIndex
    $hashBytes = $hashInfo.HashBytes

    if (-not $script:ShiftTables) {
        $script:ShiftTables = Generate-ShiftTable -hashBytes $hashBytes -patternCount 1000
    }

    $userMachine = Get-UserMachineString
    $forwardSlice = Get-Slice -inputStr $userMachine -patternIndex $patternIndex
    $reverseSlice = Get-Slice -inputStr $userMachine -patternIndex $patternIndex -reverse

    $keyForward = [System.Text.Encoding]::UTF8.GetBytes($forwardSlice)
    $keyReverse = [System.Text.Encoding]::UTF8.GetBytes($reverseSlice)

    $protectedBytes = [Convert]::FromBase64String($CipherText)
    $xoredReverse = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedBytes, $null, 'CurrentUser')

    $shifted = XOR-Data -data $xoredReverse -key $keyReverse
    $xoredForward = Invert-Shift -data $shifted -shiftTable $script:ShiftTables -patternIndex $patternIndex
    $plainBytes = XOR-Data -data $xoredForward -key $keyForward

    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

# === Sample usage ===
if ($MyInvocation.InvocationName -eq '.\AdvancedDpapiWrapper.ps1' -or $MyInvocation.MyCommand.Name -eq 'AdvancedDpapiWrapper.ps1') {
    $testEncryptedKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZHewXfUPF7CpiNlzNqRkgPjm2qgZZw=="
    $testPlainText = "SuperSecret123!"

    Write-Host "Plaintext: $testPlainText"
    $enc = Protect-Data -PlainText $testPlainText -EncryptedKey $testEncryptedKey
    Write-Host "Encrypted: $enc"
    $dec = Unprotect-Data -CipherText $enc -EncryptedKey $testEncryptedKey
    Write-Host "Decrypted: $dec"
}
