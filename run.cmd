@echo off

for /f "tokens=6 delims=,.] "  %%a in ('ver') do set "ver=%%a"

set var_hostname=
set var_ip=
set var_nic1=Ethernet0
set var_nic2=Ethernet1

REM https://www.gaijin.at/en/infos/windows-version-numbers
if %ver% == 7601 (
	echo Setup Window 2008 R2 SP1 VM
	set var_hostname=W2008-R2
	set var_ip=221

	set var_nic1=Local Area Connection
	set var_nic2=Local Area Connection 2
) else if %ver% == 9600 (
	echo Setup Window 2012 R2 VM
	set var_hostname=W2012-R2
	set var_ip=222
) else if %ver% == 14393 (
	echo Setup Window 2016 VM
	set var_hostname=W2016
	set var_ip=223
) else if %ver% == 17763 (
	echo Setup Window 2019 VM
	set var_hostname=W2019
	set var_ip=224
) else (
	echo Unsupported OS version %ver%
	pause
	exit
)

echo - Network and hostname
wmic computersystem where name='%computername%' call rename name='%var_hostname%'

netsh advfirewall set allprofiles state off

netsh int ipv4 set dns "%var_nic1%" static 192.168.154.2
netsh int ipv4 set address "%var_nic1%" static 192.168.154.%var_ip% 255.255.255.0 192.168.154.2

netsh int ipv4 set dns "%var_nic2%" dhcp
netsh int ipv4 set address "%var_nic2%" static 172.16.177.%var_ip% 255.255.255.0

echo - Power config
powercfg -change -monitor-timeout-ac 0
powercfg -change -standby-timeout-ac 0

echo - Disable page file, system restore and shutdown tracker
wmic pagefileset where name="C:\\pagefile.sys" delete
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability /v ShutdownReasonUI /t REG_DWORD /d 0 /f

echo - Enable auto login, disable UAC and CAD
wmic UserAccount where Name='Administrator' set PasswordExpires=False
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /v AutoAdminLogon /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /v DefaultUserName /t REG_SZ /d Administrator /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /v DefaultPassword /t REG_SZ /d YOUR_PASSWORD /f

reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLinkedConnections /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 1 /f

echo - Disable Server Manager
schtasks /Change /TN "Microsoft\Windows\Server Manager\ServerManager" /Disable

echo - Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

echo - Setup timezone
tzutil /s "China Standard Time"
control intl.cpl,, /f:language.xml

echo - Set Defender to never send samples
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f

REM DISM for patched system
REM dism /online /Cleanup-Image /StartComponentCleanup

pause
