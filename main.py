import analyze
import plot
from os import path

inputFilename = 'univ1_pt1'
if not path.exists(inputFilename):
    print(inputFilename, " Not found, make sure you have the corrent file")
    exit()

flows = analyze.getFlows(inputFilename)
packetDistribution = analyze.getPacketDistribution(inputFilename)


plot.plotPacketCategoryPie(packetDistribution) #shows packet category pie

packets = analyze.getAllPackets(flows)

plot.plotPacketSizeDistribution(packets) #shows packet size distribution histogram

flowsMetadata = analyze.getFlowsMetadata(flows)

plot.plotDurationSizeCdf(flowsMetadata) #plots flow size/duration

