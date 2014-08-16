function DownloadPackage($source, $destination)
{
  $wc = New-Object System.Net.WebClient
  $wc.DownloadFile($source, $destination)
}

function UnzipFile($file, $destination)
{
  $shell = new-object -com shell.application
  $zip = $shell.NameSpace($file)
  foreach($item in $zip.items())
  {
    $shell.Namespace($destination).copyhere($item)
  }
}

function GenPassword
{
  $key = New-Object byte[](32)
  $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
  $rng.GetBytes($key)
  $result = [System.Convert]::ToBase64String($key)
  return "Ghjk123+" + $result
}

function GenJobuserPassword($pubkey)
{
  $hasher = new-object System.Security.Cryptography.SHA256Managed
  $toHash = [System.Text.Encoding]::UTF8.GetBytes($pubkey)
  $hashByteArray = $hasher.ComputeHash($toHash)
  $result = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($hashByteArray))
  return "Ghjk123+" + $result.Substring(0, 12)
}

function InstallCygwinAndOpensshAndExpect
{
  $cygUrl = "$env:BLOB_STORAGEURL/bootstrap/cygwin.zip"
  $cygLocalPath = $localStorage + "cygwin.zip"
  $cygExtractPath = $localStorage
  $cygInstallPath = $localStorage + "cygwin64"
  DownloadPackage -Source $cygUrl -Destination $cygLocalPath
  UnzipFile -File $cygLocalPath -Destination $cygExtractPath
  Start-Process -Wait -FilePath "$cygExtractPath\cygwin\setup-x86_64.exe" -ArgumentList "-L -q -n -l $cygExtractPath\cygwin -R $cygInstallPath"
  Start-Process -Wait -FilePath "$cygExtractPath\cygwin\setup-x86_64.exe" -ArgumentList "-L -q -n -l $cygExtractPath\cygwin -R $cygInstallPath -P openssh"
  Start-Process -Wait -FilePath "$cygExtractPath\cygwin\setup-x86_64.exe" -ArgumentList "-L -q -n -l $cygExtractPath\cygwin -R $cygInstallPath -P expect"
  [Environment]::SetEnvironmentVariable("CYGWIN_HOME","$cygInstallPath","Machine")
  [Environment]::SetEnvironmentVariable("BASH_PATH","$cygInstallPath\bin\bash.exe","Machine")
}

function InstallMsMpi
{
  $mpiUrl = "$env:BLOB_STORAGEURL/bootstrap/MSMPISetup.exe"
  $mpiLocalPath = $localStorage + "MSMPISetup.exe"
  DownloadPackage -Source $mpiUrl -Destination $mpiLocalPath
  Start-Process -Wait -FilePath $mpiLocalPath -ArgumentList "-unattend"
  $env:PATH = $env:PATH + ";$env:ProgramFiles\Microsoft MPI\Bin"
  [Environment]::SetEnvironmentVariable("PATH",$env:PATH,"Machine")

  netsh advfirewall firewall add rule name="mpiexec" dir=in action=allow program="$mpiInstallDir\Bin\mpiexec.exe"
  netsh advfirewall firewall add rule name="smpd" dir=in action=allow program="$mpiInstallDir\Bin\smpd.exe"
  netsh advfirewall firewall add rule name="ephemeral-tcp" dir=in action=allow localport=49152-65535 protocol=tcp
  netsh advfirewall firewall add rule name="ephemeral-udp" dir=in action=allow localport=49152-65535 protocol=udp
}

function InstallCarbon
{
  $carbonUrl = "$env:BLOB_STORAGEURL/bootstrap/Carbon-1.6.0.zip"
  $carbonLocalPath = $localStorage + "Carbon-1.6.0.zip"
  $carbonExtractPath = $env:ProgramFiles
  DownloadPackage -Source $carbonUrl -Destination $carbonLocalPath
  UnzipFile -File $carbonLocalPath -Destination $carbonExtractPath
}

function SetLocalStoragePermisson
{
  $colRights = [System.Security.AccessControl.FileSystemRights]"Read, Write, ExecuteFile"

  $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
  $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None

  $objType =[System.Security.AccessControl.AccessControlType]::Allow

  $objUser = New-Object System.Security.Principal.NTAccount("BUILTIN\Users")

  $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
    ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType)

  $objACL = Get-ACL "$localStorage"
  $objACL.AddAccessRule($objACE)

  Set-ACL "$localStorage" $objACL
}

function CreateUser($username, $groupname, $password)
{
  [ADSI]$server="WinNT://" + $hostname
  $user = $server.Create("User", $username)
  $user.SetPassword($password)
  # set a new value so that the password never expires
  $flag = $user.UserFlags.value -bor 0x10000
  $user.put("userflags",$flag)
  $user.SetInfo()
  [ADSI]$group = "WinNT://$hostname/$groupname,Group"
  $group.Add($user.path)
  "Created user [$username] in group [$groupname]"
}

function GrantBatchLogonRight($username)
{
  $identity = "$hostname\$username"
  $privilege = "SeBatchLogonRight"
  $CarbonDllPath = "$env:ProgramFiles\Carbon\bin\Carbon.dll"
  [Reflection.Assembly]::LoadFile($CarbonDllPath)
  [Carbon.Lsa]::GrantPrivileges($identity, $privilege)
}

function GrantUserLogOnLocal($username)
{
  $accountToAdd = "$hostname\$username"

  $sidstr = $null
  try {
    $ntprincipal = new-object System.Security.Principal.NTAccount "$accountToAdd"
    $sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
    $sidstr = $sid.Value.ToString()
  } catch {
    $sidstr = $null
  }

  "Account: $($accountToAdd)"

  if( [string]::IsNullOrEmpty($sidstr) ) {
    "Account not found!"
    exit -1
  }

  "Account SID: $($sidstr)"

  $tmp = [System.IO.Path]::GetTempFileName()

  "Export current Local Security Policy"
  secedit.exe /export /cfg "$($tmp)"

  $c = Get-Content -Path $tmp

  $currentSetting = ""

  foreach($s in $c) {
    if( $s -like "SeInteractiveLogonRight*") {
      $x = $s.split("=",[System.StringSplitOptions]::RemoveEmptyEntries)
      $currentSetting = $x[1].Trim()
    }
  }

  if( $currentSetting -notlike "*$($sidstr)*" ) {
    "Modify Setting ""Allow Logon Locally"""

    if( [string]::IsNullOrEmpty($currentSetting) ) {
      $currentSetting = "*$($sidstr)"
    } else {
      $currentSetting = "*$($sidstr),$($currentSetting)"
    }

    "$currentSetting"

    $outfile = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = $($currentSetting)
"@
    $tmp2 = [System.IO.Path]::GetTempFileName()

    "Import new settings to Local Security Policy"
    $outfile | Set-Content -Path $tmp2 -Encoding Unicode -Force

    Push-Location (Split-Path $tmp2)

    try {
      secedit.exe /configure /db "secedit.sdb" /cfg "$($tmp2)" /areas USER_RIGHTS
	} finally {
      Pop-Location
    }
  } else {
    "NO ACTIONS REQUIRED! Account already in ""Allow Logon Locally"""
  }
}

function ConfigureSshd
{
  $sshdpassword = GenPassword
  cd $cygwinPath\bin
  .\bash --login -c "mkpasswd -l > /etc/passwd"
  .\bash --login -c "mkgroup -l > /etc/group"
  .\bash --login -c "/bin/ssh-host-config -y -c ntsec -u sshd_account -w $sshdpassword"
  # Configure admin user
  .\bash --login -c "mkdir /home/$adminusername"
  .\bash --login -c "chown ${adminusername}:${adminusergroupname} /home/$adminusername"
  .\bash --login -c "chmod 750 /home/$adminusername"
  .\bash --login -c "mkdir /home/$adminusername/.ssh"
  .\bash --login -c "echo $adminuserpubkey > /home/$adminusername/.ssh/authorized_keys"
  .\bash --login -c "chmod 644 /home/$adminusername/.ssh/authorized_keys"
  # Set admin user environment variables
  .\bash --login -c "echo 'export DEPLOYMENT_ID=$env:DEPLOYMENT_ID' > /home/$adminusername/.bashrc"
  .\bash --login -c "echo 'export ROLE_ID=$env:ROLE_ID' >> /home/$adminusername/.bashrc"
  .\bash --login -c "chown ${adminusername}:${adminusergroupname} /home/$adminusername/.bashrc"
  .\bash --login -c "chmod 700 /home/$adminusername/.bashrc"
  # Configure job user
  .\bash --login -c "mkdir -p /home/$jobusername/work"
  .\bash --login -c "chown -R ${jobusername}:${jobusergroupname} /home/$jobusername"
  .\bash --login -c "chmod 777 /home/$jobusername"
  .\bash --login -c "mkdir /home/$jobusername/.ssh"
  .\bash --login -c "echo $jobuserpubkey > /home/$jobusername/.ssh/authorized_keys"
  .\bash --login -c "echo $adminuserpubkey >> /home/$jobusername/.ssh/authorized_keys"
  .\bash --login -c "chmod 644 /home/$jobusername/.ssh/authorized_keys"

  # disable ssh password authentication
  .\bash --login -c "sed -i.bak 's/#.*PasswordAuthentication.*yes/PasswordAuthentication no/' /etc/sshd_config"
  .\bash --login -c "sed -i.bak 's/#.*ClientAliveInterval.*/ClientAliveInterval 30/' /etc/sshd_config"
  .\bash --login -c "sed -i.bak 's/#.*ClientAliveCountMax.*/ClientAliveCountMax 10/' /etc/sshd_config"
  net start sshd
}

function SetJobuserPasswordToRegistry($username, $password)
{
  # Download the expect script
  $setPwdUrl = "$env:BLOB_STORAGEURL/bootstrap/setpwd.exp"
  $setPwdLocalPath = "$cygwinPath\bin\setpwd.exp"
  DownloadPackage -Source $setPwdUrl -Destination $setPwdLocalPath
  cd $cygwinPath\bin
  .\bash --login -c "setpwd.exp $username $password"
}

function StartSmpdAs($username, $password)
{
  schtasks /CREATE /TN "SMPD" /SC ONCE /SD 01/01/2020 /ST 00:00:00 /RL HIGHEST /RU $username /RP $password /TR "$env:ProgramFiles\Microsoft MPI\Bin\smpd.exe -d" /F
  schtasks /RUN /TN "SMPD"
}

function SetGlobalEnvironment
{
  cd $cygwinPath\bin
  # delete lines which prevent bash.bashrc from get export in non-interactive mode
  .\bash --login -c "sed -i '/If not running interactively/,+2d' /etc/bash.bashrc"
  # apply the global environment variables
  .\bash --login -c "echo 'export PATH=/usr/local/bin:/usr/bin:`$`{PATH`}' >> /etc/bash.bashrc"
  .\bash --login -c "echo 'export CYGWIN=nodosfilewarning' >> /etc/bash.bashrc"
  .\bash --login -c "echo 'export TMP=/tmp' >> /etc/bash.bashrc"
  .\bash --login -c "echo 'export TEMP=/tmp' >> /etc/bash.bashrc"
}

# Start of the script
$hostname = $env:COMPUTERNAME
$adminusername = $env:ADMIN_USER
$adminusergroupname = "Administrators"
$adminuserpubkey = $env:ADMIN_USER_PUBKEY
$adminuserpassword = GenPassword
$jobusername = $env:JOB_USER
$jobusergroupname = "Users"
$jobuserpubkey = $env:JOB_USER_PUBKEY
$jobuserpassword = GenJobuserPassword -pubkey $jobuserpubkey
$localStorage = $env:LOCAL_STORAGE -replace "\\directory\\", "\Directory\"
$cygwinPath = $localStorage + "cygwin64"

# Install basic tools
InstallCygwinAndOpensshAndExpect
InstallMsMpi
InstallCarbon

# Create user and start services
SetGlobalEnvironment
SetLocalStoragePermisson
CreateUser -Username $adminusername -Groupname $adminusergroupname -Password $adminuserpassword
CreateUser -Username $jobusername -Groupname $jobusergroupname -Password $jobuserpassword
GrantUserLogOnLocal -Username $jobusername
GrantBatchLogonRight -Username $jobusername
ConfigureSshd
SetJobuserPasswordToRegistry -Username $adminusername -Password $adminuserpassword
SetJobuserPasswordToRegistry -Username $jobusername -Password $jobuserpassword
StartSmpdAs -Username $jobusername -Password $jobuserpassword
# End of the script
