import scapy.all as scapy
import sys
import csv


# call script with input file and output file as argumetns
#  e.g. $ python anonymize.py input.pcap output.pcap [metadata_location]
if (len(sys.argv) < 3):
	print("provide an input file and an output file")
	exit()


# input and output file
inputFile = sys.argv[1]
outputFile = sys.argv[2]

# dictionary holding all MAC addresses and their anonymized version
#  broadcast address remains
macDict = {"ff:ff:ff:ff:ff:ff": "ff:ff:ff:ff:ff:ff"}


# dictionary holding all SSID's and their anonymized version
ssidDict = {}


# provided a MAC address, returns the anonymized version or generates one
#  the generated MAC is a hex number preceded by 0 (E.g. 00:00:00:00:00:01)
def changeMAC(m):
	if m in macDict:
		return macDict[m]
	else:
		# generate a new MAC
		num = hex(len(macDict) + 1)[2:].zfill(12)
		newMac = num[0:2] + ":" + num[2:4] + ":" + num[4:6] + ":" + num[6:8] + ":" + num[8:10] + ":" + num[10:12]
		# add it to the dict
		macDict[m] = newMac
		return newMac


# provided a SSID, gives the anonymized version or generates one
#  the generated SSID is nw_ formatted by a number and padded with . (E.g. nw_1...)
def changeSSID(s):
	if s in ssidDict:
		return ssidDict[s], len(s) - len(ssidDict[s])
	else:
		# adding padding to keep the original SSID string length
		newSsid = ("NETWORK_" + str(len(ssidDict) + 1))
		ssidDict[s] = newSsid
		return newSsid, len(s) - len(newSsid)


# Filters all 802.11 beacon and probe frames
def filterDot11(p):
	if (p.haslayer(scapy.Dot11ProbeReq)):
		return True
	elif (p.haslayer(scapy.Dot11ProbeResp)):
		return True
	elif (p.haslayer(scapy.Dot11Beacon)):
		return True
	else:
		return False


# read the packets from the input pcap
packets = scapy.rdpcap(inputFile)

# Define the CSV file
with open(inputFile + '.csv', 'w', newline='') as file:
	writer = csv.writer(file)
	writer.writerow(['Timestamp', 'type', 'MAC_timestamp', 'rssi', 'addr1', 'addr2', 'addr3', 'SSID'])


# remove all MAC addresses and SSID if present
for packet in packets:
	if packet.haslayer(scapy.Dot11):
		# Modify the source and destination MAC addresses
		packet.addr1 = changeMAC(packet.addr1)
		packet.addr2 = changeMAC(packet.addr2)
		packet.addr3 = changeMAC(packet.addr3)
		# skip broadcasted packtes (no SSID supplied)
		if packet.addr2 != "ff:ff:ff:ff:ff:ff":
			try:
				if packet.info != b'':
					packet.info, letterDiff = changeSSID(packet.info)
					packet[scapy.Dot11].len = packet[scapy.Dot11].len - letterDiff
					# packet.len = packet.len - letterDiff
					# packet[Dot11Elt][0].len = packet[Dot11Elt][0].len - letterDiff
					# packet[Dot11Beacon].payload.payload.infoelt_len = packet[Dot11Beacon].payload.payload.infoelt_len - letterDiff
			except:
				pass

		# remove all informational layers
		if packet.haslayer(scapy.Dot11Elt): # and packet.getlayer(scapy.Dot11Elt).ID == 221:
			packet[scapy.Dot11Elt].remove_payload()

		# define 802.11 management frame type
		if (packet.haslayer(scapy.Dot11ProbeReq)):
			frameType =  'Dot11ProbeReq'
		elif (packet.haslayer(scapy.Dot11ProbeResp)):
			frameType =  'Dot11ProbeResp'
		elif (packet.haslayer(scapy.Dot11Beacon)):
			frameType =  'Dot11Beacon'


		# add packet to CSV
		with open(inputFile + '.csv', 'a', newline='') as file:
			writer = csv.writer(file)
			writer.writerow([packet.time, # timestamp 
				frameType, # type
				packet[scapy.RadioTap].timestamp, # MAC timestamp
				packet[scapy.RadioTap].dBm_AntSignal, # rssi
				packet.addr1,
				packet.addr2,
				packet.addr3,
				packet.info])

# apply the filter and write the packets
filteredPackets = filter(filterDot11, packets)
scapy.wrpcap(outputFile, filteredPackets)


# Create Json metadata files
if (len(sys.argv) > 3):
	import json
	def convert_bytecodes_to_strings(bytecode_dict):
		return {str(key)[2:-1]: value for key, value in bytecode_dict.items()}
	with open(sys.argv[3] + '-MAC.json', 'w') as f:
		json.dump(convert_bytecodes_to_strings(macDict), f)
	with open(sys.argv[3] + '-SSID.json', 'w') as f:
		json.dump(convert_bytecodes_to_strings(ssidDict), f)