# PCAP Analyser
## Extract data distribution of packets, flows and more.

A small python project based on the homework assingment for Cloud Computing - University of Macedonia 20-21.


## Features

- Filter packets into flows based on the following: 
    - Origin IP
    - Destination IP
    - Origin Port
    - Destination Port
    - Protocol (TCP/UDP)
- Extract information about those flows such as:
    - Size of flow (bytes)
    - Duration of flow (sec)
- Extract distribution of packets in the following categories:
    - TCP
    - UDP
    - ICMP
    - ARP
    - OTHER (IP)
    - OTHER (NON-IP)
 - Extract graphs for the following:
    - Distribution of Packets
    - Packet size frequency
    - CDF Graph of flow size (bytes)
    - CDF Graph of flow duration (usecs)


## Tech

The project is written entierly on Python3 and uses the following external libraries:

- dpkt - To initially extract data from pcap file.
- numpy - To help prepare data for the graphs/plots.
- matplotlib (pyplot) - To create the graphs/plots.

## Installation - Usage

Before running the script:

Install the required libraries with pip:

```
pip install dpkt
pip install numpy
pip install matplotlib
```

After installing the libraries you can run the script by executing main.py, make sure you have the pcap file (you can change the filename in main.py) and all 3 project files (analyze.py, plot.py, main.py) in the same directory before executing.

You can change which graphs/plots are shown by commenting out the corresponding lines in the main file.

## Thoughts

I've implemented caching so that if the data has been extracted once there's no need to go through that again, simply just saving the extracted data in a json file, and loading it if it exists. 
This really sped up the development of the project as the time it took to go through the file initially was quite high (15-30seconds). 

Currently the packet distribution and flow data are extracted seperately, and go through the same data twice, due to time/code quality constraints I chose to leave it this way.
