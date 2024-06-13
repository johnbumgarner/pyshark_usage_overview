<h1> <strong>LiveCapture Usage</strong></h1>
---

<p align="justify"> 

<strong>LiveCapture</strong> is designed to perform a live capture from a network interface. This mode has various filters that can be applied to the packets being collected and processed. 

</p>


### LiveCapture basic usage


```python

import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
   # do something with the packet

```

### LiveCapture with packet count

<p align="justify"> 

<strong>LiveCapture</strong> has a featured named sniff_continuously that allows you to limit the number of packets captured.

</p>


```python

import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture.sniff_continuously(packet_count=10):
   # do something with the packet

```

### LiveCapture with timeout

<p align="justify"> 

<strong>LiveCapture</strong> has a featured named sniff that allows you to set a capture timeout period.

</p>

```python

import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
capture.sniff(timeout=10)
packets = [pkt for pkt in capture._packets]
capture.close()
for packet in packets:
   # do something with the packet

```

### LiveCapture with bpf_filter

<p align="justify"> 

<strong>LiveCapture</strong> has a featured named <i>BPF_Filter</i> (Berkeley Packet Filter) that allows you to prefilter the packets being captured. The example below show how to parse Domain Name System (DNS) packets from a LiveCapture session.

</p>

```python

import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', bpf_filter='udp port 53')
for packet in capture:
   # do something with the packet

```

### LiveCapture with display_filter

<p align="justify"> 

<strong>LiveCapture</strong> has a featured named <i>display_filter</i> that allows you to prefilter the packets being captured. The example below show how to parse Domain Name System (DNS) packets using <i>display_filter</i> from a LiveCapture session.

</p>

```python

import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', display_filter='dns')
for packet in capture:
   # do something with the packet

```





