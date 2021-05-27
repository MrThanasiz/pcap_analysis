import numpy as np
import matplotlib.pyplot as plt
from statistics import median


def plotPacketCategoryPie(packetDistribution):
    # Pie chart, where the slices will be ordered and plotted counter-clockwise:
    labels = 'TCP','UDP','ICMP','ARP','IP (Other)','non-IP (Other)'
    sizes = packetDistribution #tcp,udp,icmp,arp,ipother, nonipother
    explode = (0, 0, 0, 0, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%',
            shadow=True, startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    plt.show()

def plotPacketSizeDistribution(packets):
    packetSizes = getArrayCol(packets, 1)
    #print(packetSizes[:10])
    #print(len(packetSizes))
    x = np.array(packetSizes)
    plt.hist(x, bins=20)
    plt.gca().set(title='Packet Size Frequency Histogram', ylabel='Frequency', xlabel='Packet Size')
    #axs[1].hist(y, bins=n_bins)
    plt.show()


def plotDurationSizeCdf(flowMetadata):
    
    flowDurations = getArrayCol(flowMetadata,0)
    flowSizes = getArrayCol(flowMetadata,1)
    
    #scale options: 'linear', 'log', 'symlog'
    plotArrayCdf(flowSizes,"log","Flow Sizes (in Bytes)")
    plotArrayCdf(flowDurations,"log","Flow Lengths (in usecs)")

def plotArrayCdf(array,scale,label):
    inp = array
    inp.sort()
    data = np.array(inp)
    dataCdf = np.array(arrayToCdf(inp))

    plt.step(data, dataCdf)
    plt.xscale(scale)
    plt.title(label)
    plt.xlabel(label)
    plt.ylabel("CDF")
    plt.show()


def minmaxavg(array):
    avg = 0 if len(array) == 0 else sum(array)/len(array)
    print( min(array),max(array),avg,median(array))

def arrayToCdf(array):
    arraySum = sum(array)
    prev = array[0]/arraySum
    outList = [prev]
    for i in range(1,len(array)):
        outList.append(prev+(array[i]/arraySum))
        prev = outList[-1]
    outList[-1] = 1
    return outList

def getArrayCol(array,col):
    outList = []
    for item in array:
        outList.append(item[col])
    return outList


def plotWithOffset():
    print('ok')