param(
	[string] $name
)

Write-Host("[*] Cleaning $name embed header file")

$StartLocation = $PWD
Set-Location -Path "..\..\..\..\"

$HeaderFile = $PWD.ToString() + "\$name\embed.hpp"

if (Test-Path $HeaderFile) {
	Remove-Item $HeaderFile
	Write-Host("`t[*] $HeaderFile removed")
} else {
	Write-Host("`t[!] $HeaderFile does not exist")
}

Set-Location $StartLocation

Write-Host("[+] Creating $name embed header file")

$StartLocation = $PWD

Set-Location "..\"

$EXEFile = $PWD.ToString() + "\$name\$name.exe"
$DLLFile = $PWD.ToString() + "\$name\$name.dll"

if (Test-Path $EXEFile) {

	Write-Host("`t[*] $EXEFile found")

	$bytes = Get-Content -Path $EXEFile -Encoding Byte
	$hex = [System.Text.StringBuilder]::new($bytes.Length * 4)
	ForEach($byte in $bytes) { $hex.AppendFormat("0x{0:x2},", $byte) | Out-Null }

	$hexStr = $hex.ToString()
	$hexStr = $hexStr.Substring(0,$hexStr.Length-1)

	$header = "#include <vector>
#pragma warning ( push )
#pragma warning ( disable : 4309 )
#pragma warning ( disable : 4838 )
extern const char $name[] = {
$hexStr
};
#pragma warning ( pop )"

	Set-Location -Path "..\..\..\"
	$OutPath = $PWD.ToString() + "\$name\embed.hpp"

	$header | Out-File -FilePath $OutPath

	Write-Host("`t[+] Wrote $name embed header file to $OutPath")

} elseif (Test-Path $DLLFile) {

	Write-Host("`t[*] $DLLFile found")

	$bytes = Get-Content -Path $DLLFile -Encoding Byte
	$hex = [System.Text.StringBuilder]::new($bytes.Length * 4)
	ForEach($byte in $bytes) { $hex.AppendFormat("0x{0:x2},", $byte) | Out-Null }

	$hexStr = $hex.ToString()
	$hexStr = $hexStr.Substring(0,$hexStr.Length-1)

	$header = "#include <vector>
#pragma warning ( push )
#pragma warning ( disable : 4309 )
#pragma warning ( disable : 4838 )
extern const char $name[] = {
$hexStr
};
#pragma warning ( pop )"

	Set-Location -Path "..\..\..\"
	$OutPath = $PWD.ToString() + "\$name\embed.hpp"

	$header | Out-File -FilePath $OutPath

	Write-Host("`t[+] Wrote $name embed header file to $OutPath")

} else {
	Write-Host("`t[!] $EXEFile or $DLLFile does not exist")
}

Set-Location $StartLocation	