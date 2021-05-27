import analyze
import plot

inputFilename = 'univ1_pt1'

flows = analyze.getFlows(inputFilename)
packetDistribution = analyze.getPacketDistribution(inputFilename)


plot.plotPacketCategoryPie(packetDistribution) #shows packet category pie

packets = analyze.getAllPackets(flows)

plot.plotPacketSizeDistribution(packets) #shows packet size distribution histogram

flowsMetadata = analyze.getFlowsMetadata(flows)

plot.plotDurationSizeCdf(flowsMetadata) #plots flow size/duration

