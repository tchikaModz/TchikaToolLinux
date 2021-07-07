import nmap
import os
import time
from SqlByTm import *
from scanxss import *
scan = nmap.PortScanner()


red='\033[91m'
b='\033[21m'
gren='\033[92m'
yellow='\033[93m'
cyan='\033[96m'
blue='\033[94m'


def scanfailleweb():
    n = input("1- Scan SQL\n2- Scan XSS\n")
    print(red+"Your choose : ")
    if n == '1':
        scansql()
    if n == '2':
        xssscan()


def scansql():
    url = input("enter URL : ")
    scan_sql_injection(url)


def xssscan():
    url = input("Enter URL : ")
    print(scan_xss(url))


def nslookup():
    domaine = input("Enter a domain (Exemple : google.com) : ")
    print(os.system('nslookup ' + domaine))
    time.sleep(2)
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def tracert():
    domaineorIpadresse = input("Enter a domain or IP adresse(Exemple : google.com or 192.168.1.1) : ")
    print(os.system('tracert ' + domaineorIpadresse))
    time.sleep(2)
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def whois():
    domaine = input("Enter a domain (Exemple : google.com) : ")
    print(os.system('whois ' + domaine))
    time.sleep(2)
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def vulnscan():
    print("Welcome to the Vulnerabilities Scanner")
    ip = input("\nPlease Enter IP: ")
    print(os.system('nmap -sV --script=vulscan.nse ' + ip))
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def nmap():
    print("Welcome to the network Scanner !")
    ip = input("\nPlease enter IP: ")
    print("This process may take some time please wait")
    scan.scan(ip, '1-1024')
    print(scan.scaninfo())
    print(scan[ip]['tcp'].keys())
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def startmetasploit():
    print("Metasploit must be installed on your machine")
    os.system('msfconsole')


def contact():
    print(gren+"Coded by tchikaModz")
    print(red+"Contact: \nDiscord : [LTMT]tchikaModz#0001\nInstagram : tchikaModz")
    n = input(blue+"Write 'back' to return to the main menu : ")
    if n == 'back':
        main()
    else:
        print("Please write 'back' return to the main menu")
        time.sleep(3)
        os.system('clear')
        contact()


def cmdforuserwin():
    print("This tool was made for windows users (cmd)\n")
    n = input("1- Ipconfig\n2- nslookup\n3- tracert\nYour choose : ")
    if n == '1':
        os.system('ipconfig')
    if n == '2':
        nslookup()
    if n == '3':
        tracert()


def cmdlinux():
    print("This tool was made for noob linux users \n")
    n = input("1- Ifconfig\n2- sl\n3- nslookup\n4- whois\nYour choose : ")
    if n == '1':
        os.system('ifconfig')
    if n == '2':
        os.system('apt install sl')
        os.system('sl')
    if n == '3':
        nslookup()
    if n == '4':
        whois()


def main():
    print(gren+"                Welcome to my hacking tool ", red+ "!")
    print(yellow + "            <===[[ coded by tchikamodz ]]===>\n")
    n = input(cyan+"1- Network scanner\n2- Vulnerabilities Scanner\n3- Start metasploit(If installed)\n4- Web exploit Scanner\n5-Cmd command for user windows\n6- Command linux for noob\n7- Contact" +red+"\nYour choose : ")
    if n == '1':
        nmap()
    if n == '2':
        vulnscan()
    if n == '3':
        startmetasploit()
    if n == '4':
        scanfailleweb()
    if n == '5':
        cmdforuserwin()
    if n == '6':
        cmdlinux()
    if n == '7':
        contact()


if __name__ == "__main__":
    main()

