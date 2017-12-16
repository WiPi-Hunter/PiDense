# coding=utf-8

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon
from termcolor import colored
import argparse
import time

banner = """

██████╗ ██╗██████╗ ███████╗███╗   ██╗███████╗███████╗
██╔══██╗██║██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝
██████╔╝██║██║  ██║█████╗  ██╔██╗ ██║███████╗█████╗
██╔═══╝ ██║██║  ██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝
██║     ██║██████╔╝███████╗██║ ╚████║███████║███████╗
╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
-----------------------------------------------------
"""

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface',required=True, help="Interface (Monitor Mode)", type=str)
args = parser.parse_args()


def logging(log):
    with open("/var/log/pidens.log", "a") as f:
        f.write(str(log)+"\n")
        f.flush()
        f.close()


def sniff_channel_hop(iface):
    for i in range(1, 14):
        os.system("iwconfig " + iface + " channel " + str(i))
        sniff(iface=iface, count=15, prn=air_scan)


def air_scan(pkt):
    """
    Scan all network with channel hopping
    Collected all ssid and mac address information
    :param pkt:  result of sniff function
    """
    if pkt.haslayer(Dot11Beacon):
       ssid, bssid = pkt.info, pkt.addr2
       capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
						  {Dot11ProbeResp:%Dot11ProbeResp.cap%}") 
       enc = "Y"
       if "privacy" not in capability: 
          enc = 'N'
	  info = "{}=*={}".format(enc, ssid)
          if info not in info_list and info_list_2:
	     info_list.append(info)
	     info_list_2.append(info)
       else:
          info = "{}=*={}".format(enc, ssid)
          if info not in info_list_2:
             info_list_2.append(info)

def pidens(info_list_2, pineapple):
    for i in range(0, len(info_list_2)):
       for j in range(i+1, len(info_list_2)):
          ssid1 = info_list_2[i].split("=*=")[1]
          ssid2 = info_list_2[j].split("=*=")[1]
          enc1= info_list_2[i].split("=*=")[0]
	  enc2= info_list_2[j].split("=*=")[0]
	  if ssid1 == ssid2 and enc1 != enc2 and (ssid1 or ssid2) != '':
	     threat = "[*] Find same SSID, encrypted and unecryped network: " + ssid1
	     print colored(threat, 'blue', attrs=['reverse', 'blink'])
	     log = "[*]", time.strftime("%c")," Find same SSID: ", ssid1
             logging(log)
             pineapple += 1
    return pineapple


if __name__ == '__main__':
    iface = args.interface
    mode  = "Monitor"
    os.system("reset")
    now = time.strftime("%c")
    print banner
    print "Information about test:"
    print "---------"*7
    print "[*]",now
    print """[*] Analysis unencrypted network number and makes control \n--- between unencrypted and encrypted wireless networks"""
    print "---------"*7
    while True:
       time.sleep(15)
       pineapple = 0
       info_list = []
       info_list_2= []
       sniff_channel_hop(iface)
       p = pidens(info_list_2, pineapple)
       opn = "[*] Total unecrypted networks: " + str(len(info_list))
       opn = colored(opn, 'green', attrs=['reverse', 'blink'])
       opn += colored("--THREAT !!!", 'red', attrs=['reverse', 'blink'])
       if len(info_list) >=10:
          print opn
	  print "-----------"*5
          if p >= 2:
	     print colored("[*] More than defined threshold SSID info", 'green', attrs=['reverse', 'blink'])
	     print colored("[*] May be THREAT !", 'red', attrs=['reverse', 'blink'])
	     print colored("[*] Logging was done.", 'green', attrs=['reverse', 'blink'])
	     log = "[*]", time.strftime("%c"), " More than defined threshold SSID info"
             logging(log)
             print "-------------"*5

