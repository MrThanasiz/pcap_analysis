#!/usr/bin/env python
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import dpkt
from dpkt.compat import compat_ord
from os import path
import datetime
import time
import socket
import json


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))


def preparePacketDistribution(packetDistribution):
    ipMap = packetDistribution["ipMap"]
    nonIpMap = packetDistribution["nonIpMap"]
    tcpCount = ipMap['6']
    udpCount = ipMap['17']
    icmpCount = ipMap['1']
    arpCount = nonIpMap['ARP']
    ipOtherCount = 0
    nonIpOtherCount = 0
    for key in ipMap:
        if key not in ['1','6', '17']:
            ipOtherCount += ipMap[key]
    for key in nonIpMap:
        if key != "ARP":
            nonIpOtherCount += nonIpMap[key]
    return [tcpCount,udpCount,icmpCount,arpCount,ipOtherCount,nonIpOtherCount]


def getPacketDistribution(filename):
    distributionFilename = filename + "-distribution.json"
    if not path.exists(distributionFilename):
        with open(filename, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            generatePacketDistribution(filename,pcap)
    else:
        print("cache found loading packet distribution...")
    packetDistibution = json.load(open(distributionFilename))
    #print(packetDistibution["count"])
    packetDistibutionClean = preparePacketDistribution(packetDistibution)

    return packetDistibutionClean

#Distribution of packets TCP/UDP/ARP/etc

def generatePacketDistribution(filename,pcap):
    distributionFilename = filename + "-distribution.json"
    protocolMap = {}
    nonIpMap = {}
    packetCount = 0
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        if not packetCount % 100000:
            print(packetCount)
        packetCount += 1
        # Print out the timestamp in UTC
        #print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
        packetType = eth.data.__class__.__name__
        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            #packetType = eth.data.__class__.__name__
            #print('Non IP Packet type not supported %s\n' % packetType)
            if packetType not in nonIpMap:
                nonIpMap[packetType] = 1
            else:
                nonIpMap[packetType] = nonIpMap[packetType] + 1
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
        
        if ip.p not in protocolMap:
            protocolMap[ip.p] = 1
        else:
            protocolMap[ip.p] = protocolMap[ip.p] + 1
    packetDistibution = {"ipMap":protocolMap, "nonIpMap": nonIpMap, "count":packetCount}
    json.dump( packetDistibution, open( distributionFilename, 'w' ) )
    print("Wrote ",len(packetDistibution), "to ", filename)
    



def loadFlows(pcap,filename):
    if not path.exists(filename):
        print("No cache of flows, loading from pcap file...")
        generateFlows(pcap,filename)
    else:
        print("Cache of data found... loading...")
    flowData = json.load(open(filename))
    print("loaded ", len(flowData), " flows...")
    return flowData

#First flow data grouping based on 5 characteristics, saved to json
#so we don't have to go through the 1M entries every time
#format is a dict where the key is made up combining the unique identifiers
#value is a timestamp, packetsize
def generateFlows(pcap,filename):
    flowData = {}
    packetCount = 0
    tcpUdpCount = 0
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        if not packetCount % 100000:
            print(packetCount)
        sampleRun = 0
        if packetCount > 1000 and sampleRun:
            break
        packetCount += 1

        # Print out the timestamp in UTC
        
        #print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)), timestamp)
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        #print(eth.__hdr__,eth.data.src)
        ip = eth.data
        #print(ip.__hdr__)

        # Saving flows based on the 5 characteristics required (Source/Destination IP/Port & TCP/UDP Protocol)
        
        try:
            if ip.p in {6,17}:
                tcpUdpCount += 1
                sport = str(ip.data.sport)
                dport = str(ip.data.dport)
                # We create a unique key is made by combining those characteristics
                flowKey = str(ip.p)+"-"+inet_to_str(ip.src)+":"+sport+"-"+inet_to_str(ip.dst)+":"+dport 
                #Examples:
                #6-41.177.117.184:1618-41.177.3.224:51332
                #6-90.218.72.95:10749-244.3.160.239:80
                #6-244.3.160.239:80-90.218.72.95:10749
                
                # Then we save all packets that match this key
                # This is a first step and the data is still unfiltered
                if flowKey not in flowData:
                    flowData[flowKey] = [[timestamp,ip.len]]
                else:
                    t = flowData[flowKey]
                    t.append([timestamp,ip.len])
                    flowData[flowKey] = t
        except Exception as e:
            print(ip.p, e)
        
        #print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #      (inet_to_str(ip.src)+":"+sport, inet_to_str(ip.dst)+":"+dport, ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
    json.dump( flowData, open( filename, 'w' ) )
    print("Wrote ",len(flowData), "to ", filename)
    #VERIFY
    #flowDataCopy = json.load(open("flowsRaw.json"))
    #print("is data the same?: ", flowData == flowDataCopy)

# Remove flows that only have less than cap packets
def removeFlowsUnderPackets(flowData,cap):
    print("Removed flows with less than ", cap, " packets...")
    tempFlowData = {}
    for flowKey in flowData:
        if len(flowData[flowKey]) >= cap:
            tempFlowData[flowKey] = flowData[flowKey]
    
    print("Flows Before: ", len(flowData), " Flows Now: ", len(tempFlowData))
    return tempFlowData

def expandFlowsOnInactivity(flowData, seconds):
    print("Splitting flows every inactivity over ", seconds, " seconds")
    tempFlowData = {}
    extraFlowsCount = 0
    for flowKey in flowData: 
        flowPack = flowData[flowKey]

        #print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(flowPack[0][0])), flowPack[0][0])
        
        subFlowCount = 0 
        lastTs = flowPack[0][0]
        tempFlow = [flowPack[0]]
        #print("Packets in flow: ", len(flowPack))
        for i in range(1,len(flowPack)):
            ts = flowPack[i][0]
            if lastTs+(seconds) < ts:
                tempFlowData[flowKey+"-F"+ str(subFlowCount)] = tempFlow
                tempFlow = [flowPack[i]]
                subFlowCount += 1
            else:
                tempFlow.append(flowPack[i])
            lastTs = ts
        tempFlowData[flowKey+"-F"+ str(subFlowCount)] = tempFlow
        subFlowCount += 1
        
        if subFlowCount > 1:
            extraFlowsCount += subFlowCount - 1
            #print(subFlowCount) #extra flow introduced by splitting every 1 min
    print("Old size: ", len(flowData), " New size: ", len(tempFlowData), " Extra flows introduced: ", extraFlowsCount)
    return tempFlowData,extraFlowsCount

def sameFlowDataContents(flowDataS, flowDataE,extraFlowsCount):
    print("Verifying flow data contents are the same...")
    t1 = []
    for flowKey in flowDataS: 
        flowPack = flowDataS[flowKey]
        for item in flowPack:
            t1.append(item)
    t2 = []
    for tempFlowKey in flowDataE:
        for item in flowDataE[tempFlowKey]:
            t2.append(item)
    if not t1 == t2:
        print(t1)
        print("ERROR",t2==t1)
        print(t2)
    #print("Flow Count (New): ", len(flowDataE))
    #print("Flow Count (Old): ", len(flowDataS))
    print("Extra Flows: ", extraFlowsCount, "Sum Okay: ", 0 == len(flowDataE)-len(flowDataS)-extraFlowsCount)
    return 0 == len(flowDataE)-len(flowDataS)-extraFlowsCount

def cleanFlows(flowData):
    print("started cleaning flows data...")
    #Remove flows with less than 5 packets
    flowData = removeFlowsUnderPackets(flowData,5)

    #Split flows if there's a 60 second inactivity
    tempFlowData,extraFlowsCount = expandFlowsOnInactivity(flowData,60)

    #Validate that the 2 groups still contain the same packets
    sameFlowDataContents(flowData,tempFlowData,extraFlowsCount)

    #Remove flows with less than 5 packets
    tempFlowData = removeFlowsUnderPackets(tempFlowData,5)
    print("flow data cleaned...")
    return tempFlowData
    
def extractFlowsMetadata(flowData):
    print("Generating  flows metadata [flowDuration,flowSize]")
    outList = []

    for flowKey in flowData:
        currentFlow = flowData[flowKey]
        if len(currentFlow) == 1:
            outList.append([0,currentFlow[0][1]])
        else:
            startTimestamp = currentFlow[0][0]
            endTimestamp = currentFlow[len(currentFlow)-1][0]
            flowDuration = endTimestamp-startTimestamp
            flowDuration = flowDuration * 1000 * 1000 # convertion to useconds

            flowSize = 0
            for i in range(0,len(currentFlow)):
                flowSize += currentFlow[i][1]
            outList.append([int(flowDuration),int(flowSize)])
    print("Flow metadata generated, size: ", len(outList))
    return outList

def getAllPackets(flowData):
    outList = []
    for flowKey in flowData:
        currentFlow = flowData[flowKey]
        for packet in currentFlow:
            outList.append(packet)
    #print(outList[:10])
    return outList



def getFlows(filename):
    print("Started loading and cleaning data...")
    startTime = time.time()
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        flowData = loadFlows(pcap,filename+"-clean.json")
        cleanFlowData = cleanFlows(flowData)
    print("--- %.4f seconds --- to load data, generate flows and return flow metadata" % (time.time() - startTime))
    return cleanFlowData

def getFlowsMetadata(flows):
    flowMetadata = extractFlowsMetadata(flows)
    return flowMetadata



if __name__ == '__main__':
    getFlowsMetadata()
