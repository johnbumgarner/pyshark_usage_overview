# Overview

<p align="justify">
This repository contains <a href="https://pyshark-packet-analysis.readthedocs.io/en/latest/">usage documentation</a> for the <b>Python</b> module <a href="https://github.com/KimiNewt/pyshark">PyShark</a>. This <b>Python</b> module is a wrapper for <b>TShark</b>, which is command-line interface (CLI) for <b>Wireshark</b>. The latter is used to sniff and capture packets from a network interface. The real power of <b>PyShark</b> is its capability to access all of the packet decoders built into <b>TShark</b>.
</p>

<p align="justify">
This repository also contains some basic parsing examples, which are also contained in the usage documentation that I developed for <b>PyShark</b>.
</p>


# LiveCapture Usage examples

## Basic Capture

```python
import pyshark 

# Create a LiveCapture object to capture packets from the specified interface
capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
   # do something with the packet
```

## LiveCapture with packet count

<p align="justify">

<b>PyShark LiveCapture</b> has a featured named <i>sniff_continuously</i> that allows you to limit the number of packets captured. 

</p>

```python
import pyshark 

# Create a LiveCapture object to capture packets from the specified interface
capture = pyshark.LiveCapture(interface='your capture interface')

# Start capturing packets for a specified number of packets
for packet in capture.sniff_continuously(packet_count=10):
   # do something with the packet
```

## LiveCapture with timeout

<p align="justify">
<b>PyShark LiveCapture</b> also has a featured named <i>sniff</i> that allows you to set a capture timeout period. 
</p>

```python
import pyshark

# Create a LiveCapture object to capture packets from the specified interface
capture = pyshark.LiveCapture(interface='your capture interface')

# Start capturing packets for a specified duration (in seconds)
capture.sniff(timeout=10)

packets = [pkt for pkt in capture._packets]
capture.close()
for packet in packets:
   # do something with the packet
```

## LiveCapture with BPF_Filter

<p align="justify">
The <b>PyShark LiveCapture</b> mode has a <i>BPF_Filter</i> that allows you to prefilter the packets being captured. The example below show how to parse Domain Name System (DNS) packets from a LiveCapture session.
</p>

```python
import pyshark 

# Create a LiveCapture object to capture packets from the specified interface with a bpf_filter
capture = pyshark.LiveCapture(interface='your capture interface', bpf_filter='udp port 53')
for packet in capture:
   # do something with the packet
```

## LiveCapture with Display_Filter

<p align="justify">
The <b>PyShark LiveCapture</b> mode has a <i>Display_Filter</i> that allows you to prefilter the packets being captured. The example below show how to parse Domain Name System (DNS) packets from a LiveCapture session.
</p>

```python
import pyshark 

# Create a LiveCapture object to capture packets from the specified interface with a display_filter
capture = pyshark.LiveCapture(interface='your capture interface', display_filter='dns')
for packet in capture:
   # do something with the packet
```

# Additional parsing examples

<p align="justify"> 

Here are some additional parsing examples within this repository.
  
</p>

* <a href="https://github.com/johnbumgarner/pyshark_usage_overview/blob/master/examples/dns_filtering_examples.py">Extract DNS elements from a PCAP packet</a>

* <a href="https://github.com/johnbumgarner/pyshark_usage_overview/blob/master/examples/ftp_filtering_examples.py">Extract FTP elements from a PCAP packet</a>

* <a href="https://github.com/johnbumgarner/pyshark_usage_overview/blob/master/examples/frame_filtering_example.py">Extract FRAME elements from a PCAP packet</a>

* <a href="https://github.com/johnbumgarner/pyshark_usage_overview/blob/master/examples/https_filtering_examples.py">Extract HTTPS/TLS elements from a PCAP packet</a>

* <a href="https://github.com/johnbumgarner/pyshark_usage_overview/blob/master/examples/ip_filtering_examples.py">Filter PCAP packet based on Source or Destination</a>

* <a href="https://github.com/johnbumgarner/pyshark_usage_overview/blob/master/examples/snmp_filtering_examples.py">Extract SNMP elements from a PCAP packet</a>

* <a href="https://github.com/johnbumgarner/pyshark_usage_overview/blob/master/examples/async_operations.py">Asyncio programming with PyShark</a>

<p align="justify"> 

Here are some additional parsing examples that I posted to <b>GitHub Gist</b>.
  
</p>

* <a href="https://gist.github.com/johnbumgarner/b758aa24c768655940cd3352ce2a0921">Extract the conversation header information from a PCAP packet</a>

* <a href="https://gist.github.com/johnbumgarner/166b6371f975c8e0a0aeae2516771039">Extract DNS elements from a PCAP packet</a>

* <a href="https://gist.github.com/johnbumgarner/ff8c463dc668648dd9ffb0a9a9d939bc">Extract the HTTP information from IPv4 and ICMPv6 packets</a>

* <a href="https://gist.github.com/johnbumgarner/9594e36a31bf1e220838160c37bfc7d4">Extract specific IPv6 elements from a PCAP packet</a>


# Stack Overflow answers

<p align="justify"> 

Here are some <a href="https://stackoverflow.com/search?q=user%3A6083423+pyshark">Stack Overflow answers</a> that I posted for questions about <b>PyShark<b>. 

</p>


# Prerequisites

<p align="justify">

<b>TShark</b> has to be installed and accessible via your $PATH, which <b>Python</b> queries for <b>PyShark</b>.  Reference the installation section of the usage documentation for details on how to install <b>TShark</b>. 

</p>

# References

* [PyShark:](https://kiminewt.github.io/pyshark) &nbsp; Is the <b>Python</b>. wrapper for <b>TShark</b>., that allows <b>Python</b>. packet parsing using <b>Wireshark</b>. dissectors.

* [TShark:](https://www.wireshark.org/docs/man-pages/tshark.html) &nbsp; <b>TShark</b>. is a terminal oriented version of <b>Wireshark</b>. designed for capturing and displaying packets when an interactive user interface isn't necessary or available.

* [Wireshark:](https://www.wireshark.org) &nbsp; <b>Wireshark</b> is a network packet analysis tool that captures packets in real time and displays them in a graphic interface.

* [Homebrew:](https://brew.sh) &nbsp; Package Manager for macOS and Linux.

* [Berkeley Packet Filter (BPF) syntax](https://biot.com/capstats/bpf.html)

* [Display Filter syntax](https://wiki.wireshark.org/DisplayFilters)

# Notes

<p align="justify">

<b>PyShark</b> has limited documentation, so that is the reason why I developed the <b>PyShark</b> usage documentation within this repository for others to use. 

</p>

_The code within this repository is **not** production ready. It was **strictly** designed for experimental testing purposes only._
