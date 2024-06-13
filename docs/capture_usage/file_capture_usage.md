<h1> <strong>FileCapture Usage</strong></h1>
---

<p align="justify"> 

<strong>FileCapture</strong> is designed to query a Packet Capture (PCAP) file.  This mode has various filters that can be applied to the packets being processed. 

</p>


### FileCapture basic usage


```python

import pyshark

capture = pyshark.FileCapture(input_file='your pcap file')
for packet in capture:
   # do something with the packet

```

### FileCapture with bpf_filter

<p align="justify"> 

<strong>FileCapture</strong> has a featured named <i>BPF_Filter</i> (Berkeley Packet Filter) that allows you to prefilter the packets being captured. The example below show how to parse Domain Name System (DNS) packets from a FileCapture session.

</p>

```python

import pyshark

capture = pyshark.FileCapture(input_file='your pcap file', bpf_filter='udp port 53')
for packet in capture:
   # do something with the packet

```

### FileCapture with display_filter

<p align="justify"> 

<strong>FileCapture</strong> has a featured named <i>display_filter</i> that allows you to prefilter the packets being captured. The example below show how to parse Domain Name System (DNS) packets using <i>display_filter</i> from a FileCapture session.

</p>

```python

import pyshark

capture = pyshark.FileCapture(input_file='your pcap file', display_filter='dns')
for packet in capture:
   # do something with the packet

```





