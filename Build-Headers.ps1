function Clean-Headers {
	param (
		[string[]]$Names
	)

	Write-Host("[*] Cleaning header files")

	$StartLocation = $PWD
	Set-Location -Path "../../../"

	foreach ($Name in $Names) {
		$File = "./$Name/embed.hpp"

		Write-Host("`t[*] Removing $File")

		if (Test-Path $File) {
			Remove-Item $File
		} else {
			Write-Host "`t[!] $File does not exist"
		}
	}

	Set-Location $StartLocation
}

function Create-Header {
	param (
		[string[]]$Names
	)

	Write-Host("[+] Creating header files")

	foreach ($Name in $Names) {
		$StartLocation = $PWD

		Write-Host("`t[+] Creating embedded $Name header")

		$bytes = Get-Content -Path "./$Name/$Name.exe" -Encoding Byte
		$hex = [System.Text.StringBuilder]::new($bytes.Length * 4)
		ForEach($byte in $bytes) { $hex.AppendFormat("0x{0:x2},", $byte) | Out-Null }

		$hexStr = $hex.ToString()
		$hexStr = $hexStr.Substring(0,$hexStr.Length-1)

		$header = "#include <vector>
#pragma warning ( push )
#pragma warning ( disable : 4309 )
#pragma warning ( disable : 4838 )
extern const char $Name[] = {
	$hexStr
};
#pragma warning ( pop )"

		Set-Location -Path "../../../"
		$OutPath = "./$Name/embed.hpp"

		$header | Out-File -FilePath $OutPath

		Set-Location $StartLocation	
	}
}

$components = @("dropper", "listener", "loader", "persistence", "privesc")

Clean-Headers -Names $components
Create-Header -Names $components