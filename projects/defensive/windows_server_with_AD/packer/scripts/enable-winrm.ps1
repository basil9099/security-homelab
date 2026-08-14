# Enable WinRM over HTTPS for Ansible + Vagrant.
# Uses a self-signed cert; client-side cert validation is disabled in ansible.cfg.

$ErrorActionPreference = 'Stop'

Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Set-Item WSMan:\localhost\Service\Auth\Basic     $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted $false
Set-Item WSMan:\localhost\Client\Auth\Basic      $true
Set-Item WSMan:\localhost\Client\AllowUnencrypted $false

$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
$thumb = $cert.Thumbprint
$listenerCmd = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS " +
               "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumb`"}"
cmd.exe /c $listenerCmd

New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -Profile Any | Out-Null

# Ensure the service starts on boot.
Set-Service -Name WinRM -StartupType Automatic
Restart-Service WinRM
