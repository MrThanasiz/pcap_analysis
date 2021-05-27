import analyze
import plot

inputFilename = 'univ1_pt1.pcap'

flows = analyze.getFlows(inputFilename)
packetDistribution = analyze.getPacketDistribution(inputFilename)


plot.plotPacketCategoryPie(packetDistribution)

packets = analyze.getAllPackets(flows)
plot.plotPacketSizeDistribution(packets)
flowsMetadata = analyze.getFlowsMetadata(flows)
plot.plotDurationSizeCdf(flowsMetadata)

