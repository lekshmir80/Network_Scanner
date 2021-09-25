#!/usr/bin/python3

#Menu driven network scanning tool:
import nmap
import os
from rich.console import Console
from rich.text import Text
from rich.prompt import Prompt

os.system('banner NETSCAN')
console = Console()

def yprint(string):
	console.print(Text(string,style="bold yellow"))

def rprint(string): 
	console.print(Text(string,style="bold red"))
	
def gprint(string): 
	console.print(Text(string,style="bold green"))
	
def scan_single_host():
	nm = nmap.PortScanner() #Create object of nmap port scannet class
	ip_address = Prompt.ask("\tEnter the IP")
	gprint("Wait.......................")
	try:
		scan = nm.scan(hosts=ip_address,ports="1-2000",arguments = "-v -sS -O -Pn") #Returns Dictionary
		for port in scan["scan"][ip_address]['tcp'].items():
			yprint(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		rprint("Use root priviliege")
		
def scan_range():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = Prompt.ask("\tEnter the IP : ")
	gprint("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			yprint(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		rprint("Use root priviliege")
	
	
def scan_network():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = Prompt.ask("\tEnter the IP : ")
	gprint("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for i in scan["scan"][ip_address]['osmatch']:
			yprint(f"Name -> {i['name']}")
			yprint(f"Accuracy -> {i['accuracy']}")
			yprint(f"OSClass -> {i['osclass']}\n")
		
	except:
		rprint("Use root priviliege")
	

def aggressive_scan():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = Prompt.ask("\tEnter the IP : ")
	gprint("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn -T4")
		for i in scan["scan"][ip_address]['osmatch']:
			yprint(f"Name -> {i['name']}")
			yprint(f"Accuracy -> {i['accuracy']}")
			yprint(f"OSClass -> {i['osclass']}\n")
		
	except:
		rprint("Use root priviliege")
	

def arp_pkts():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = Prompt.ask("\tEnter the IP : ")
	gprint("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -PR")
		yprint(scan)
	except:
		rprint("Use root priviliege")
		

def scan_all_ports():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = Prompt.ask("\tEnter the IP ")
	gprint("Wait........................")
	try:
		scan = nm.scan(hosts = ip_address,ports = "1-3",arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			yprint(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		rprint("Use root priviliege")
	

def scan_verbose():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = Prompt.ask("\tEnter the IP ")
	gprint("Wait........................")
	try:
		scan = nm.scan(hosts = ip_address,arguments = "-sS -O -Pn -v")
		for i in scan["scan"][ip_address]['osmatch']:
			yprint(f"Name -> {i['name']}")
			yprint(f"Accuracy -> {i['accuracy']}")
			yprint(f"OSClass -> {i['osclass']}\n")
	except:
		rprint("Use root priviliege")
		
	
def menu():
	gprint("1. Scan single host")
	gprint("2. Scan range")
	gprint("3. Scan network")
	gprint("4. Agressive scan")
	gprint("5. Scan ARP packet")
	gprint("6. Scan All port only")
	gprint("7. Scan in verbose mode")
	gprint("8.Exit")
	
while True:
	menu()
	ch = Prompt.ask("Enter your option ", choices=["1", "2", "3","4","5","6","7","8"])
	if ch == "1":
		scan_single_host()
	elif ch == "2":
		scan_range()
	elif ch == "3":
		scan_network()
	elif ch == "4":
		aggressive_scan()
	elif ch == "5":
		arp_pkts()
	elif ch == "6":
		scan_all_ports()
	elif ch == "7":
		scan_verbose()
	elif ch == "8":
		break;

	
