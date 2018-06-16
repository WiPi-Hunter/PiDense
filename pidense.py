# coding=utf-8

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon
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
       if ssid not in ssidlist:
           ssidlist.append(ssid)
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

    elif pkt.haslayer(Dot11ProbeResp):
        ssid, bssid = pkt.info, pkt.addr2
        info = "{}=*={}".format(bssid, ssid)
        if info not in info_list:
            karmalist.append(info)

    elif pkt.haslayer(Dot11Deauth):
        pass
        #if pkt.reason == 7:
         #   deauth_list.append(pkt.reason)


def same_ssid(info_list_2, same_ssids):
    for i in range(0, len(info_list_2)):
       for j in range(i+1, len(info_list_2)):
          ssid1 = info_list_2[i].split("=*=")[1]
          ssid2 = info_list_2[j].split("=*=")[1]
          enc1= info_list_2[i].split("=*=")[0]
	  enc2= info_list_2[j].split("=*=")[0]
	  if ssid1 == ssid2 and enc1 != enc2 and (ssid1 or ssid2) != '':
             same_ssids += 1
             print u"\n\u001b[41;1mCritical\u001b[0m\t\033[1mFakeAP\t\t\u001b[41;1msame ssid, different encryption\u001b[0m\t" + "\033[1mSSID: ", ssid1
    return same_ssids

def karma_attack_check(karmalist, karma):
    for i in karmalist:
        bssid, ssid= i.split("=*=")
        if bssid not in karma.keys():
            karma[bssid] = []
            karma[bssid].append(ssid)
        elif bssid in karma.keys() and ssid not in karma[bssid]:
            karma[bssid].append(ssid)
    for v in karma.keys():
        if len(karma[v]) >= 2 and v not in karma_mac_address:
            print u"\n\u001b[41;1mCritical\u001b[0m\t\033[1mFakeAP\t\t\u001b[41;1mKARMA Attacks\u001b[0m\t\t\t" + "\033[1mMAC: ", v
            karma_mac_address.append(v)

def blackssid_check(ssidlist):
    blackssids = open("blacklist.txt","r").readlines()
    blackssids = [black[:-1].lower() for black in blackssids]
    for black in blackssids:
        for info in info_list_2:
	    ssid = info.split("=*=")[1]
	    enc  = info.split("=*=")[0]
            if black in ssid.lower() and enc == "N":
                print u"\n\u001b[41;1mCritical\u001b[0m\t\033[1mCritical SSID\t\u001b[41;1mBlacklist\u001b[0m\t\t" + "\033[1mSSID: ", ssid

if __name__ == '__main__':
    density = 5
    iface = args.interface
    mode  = "Monitor"
    os.system("reset")
    now = time.strftime("%c")
    print banner
    print "Information about test:"
    print "---------"*7
    print "[*]",now
    print """[*] Monitor illegal wireless network activities. (Fake Access Points)"""
    print "---------"*7
    print u"\u001b[40;1m T \u001b[41;1m H \u001b[42;1m R \u001b[43;1m E \u001b[45;1m A \u001b[46;1m T \u001b[41;1m S \u001b[0m____________________________________________________\n"
    print u"\u001b[4m\u001b[240;1mSeverity\tAttack Type\tDescription\t\t\tContent\u001b[0m"
    while True:
       threat_time = time.strftime("%c")
       time.sleep(300)
       karmalist = []
       karma_mac_address = []
       karma = {}
       same_ssids = 0
       info_list = []
       info_list_2 = []
       ssidlist = []
       deauth_list = []
       sniff_channel_hop(iface)
       p = same_ssid(info_list_2, same_ssids)
       blackssid_check(info_list_2)
       karma_attack_check(karmalist, karma)
       if p >= 3:
           print u"\n\u001b[41;1mCritical\u001b[0m\t\033[1mPineapple\t\u001b[41;1mUnencrypted WiFi\u001b[0m\t\t" + "\033[1mCount: ", p
       elif len(info_list) >= density:
           print u"\n\u001b[43;1mMEDIUM\t\u001b[0m\t\033[1mDensity\t\t\u001b[43;1mOPN Networks\u001b[0m\t\t\t" + "\033[1mCount: ", len(info_list)
       #elif len(deauth_list) >=0:
       #    print u"\n\u001b[44;1mInformation\u001b[0m\t\033[1mDeauth Packets\t\u001b[44;1mDeauthentication Attacks\u001b[0m\t" + "\033[1mCount: ", len(deauth_list)
       print "______________________________________________________________________________: ", threat_time
