# Overview Packet Analysis

<p align="justify">
This repository contains code related to the Python module PyShark, which is a wrapper for the Wireshark command-line interface (CLI) for TShark. The latter using the Wireshark dissectors to sniff and capture packets from a network inteface. The real power of PyShark is its capability to access to all of the packet decoders built into TShark.
</p>

<p align="justify">
PyShark can operate in either LiveCapture or FileCapture modes. Both modes have methods that can be used to parse specific
packet level attributes, which includes protocols and their associated ports. 
</p>

<p align="justify">
PyShark has two primary filters. The <i><b>BPF_Filter</b></i> is used in LiveCapture mode. The <i><b>Display_Filter</b></i> is used in FileCapture mode.
</p>

### Usage examples:
<p align="justify">
The examples below show how to parse Domain Name System (DNS) packets from either a TShark live capture session or from a Packet Capture (PCAP) file.
</p>

<p align="justify">
<i><b>BPF_Filter</b></i>

`capture = pyshark.LiveCapture(interface='en0', bpf_filter='udp port 53')`<br>
`capture.sniff(timeout=50)`<br>
`for raw_packet in capture.sniff_continuously():`<br>
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; `do something`
</p>


<p align="justify">
<i><b>Display_Filter</b></i>
  
`capture = pyshark.FileCapture(pcap_file, display_filter='dns')`<br>
`for raw_packet in capture:`<br>
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`do something`
</p>

<i><b>Function Level Filtering</b></i>
<p align="justify">
This type of packet filtering does not use the built-in PyShark's functions BPF_Filter or Display_Filter.<br>

`if hasattr(packet, 'udp') and packet[packet.transport_layer].dstport == '53':`<br>

or

`if hasattr(packet, 'tcp'):`<br>
&nbsp; &nbsp; &nbsp; &nbsp;`if packet[packet.transport_layer].dstport == '80' or packet[packet.transport_layer].dstport == '443':`<br>
</p>

### Accessing packet data:
<p align="justify">
All packets have layers, but these layers vary based on the packet type. These layers can be queried and the data elements within these layers can be extracted. Layer types can be accessed using the following parameter:
<br>

`packet.layers`<br>

<b>Common Layers:</b>
<br>
* ETH Layer - Ethernet
* IP Layer - Internet Protocol
* TCP Layer - Transmission Control Protocol
* UDP Layer - User Datagram Protocol
* ARP Layer - Address Resolution Protocol

<b>Other Layers:</b>
<br>
* BROWSER Layer - Web browser
* DATA Layer - Normal data payload of a protocol
* DB-LSP-DISC Layer - Dropbox LAN Sync Discovery
* DHCP Layer - Dynamic Host Configuration Protocol
* HTTP Layer - Hypertext Transfer Protocol
* LLMNR Layer - Link-Local Multicast Name Resolution
* MAILSLOT Layer - Mailslot protocol is part of the SMB protocol family
* MSNMS Layer - Microsoft Network Messenger Service
* NAT-PMP Layer - NAT Port Mapping Protocol
* NBDGM Layer - NetBIOS Datagram Service
* NBNS Layer - NetBIOS Name Service
* SMB Layer - Server Message Block
* SNMP Layer - Simple Network Management Protocol 
* SSDP Layer - Simple Service Discovery Protocol 
* TLS Layer - Transport Layer Security,
* XML Layer - Extensible Markup Language
</p>

### Parsing examples:
<p align="justify">
PyShark has a lot of flexibility to parse various types of information from an individual network packet. Below are some of the items that can be parsed using the transport_layer and IP layer.
<br>

<b>Example One:</b>
<br>

`protocol = packet.transport_layer`<br>
`source_address = packet.ip.src`<br>
`source_port = packet[packet.transport_layer].srcport`<br>
`destination_address = packet.ip.dst` <br>
`destination_port = packet[packet.transport_layer].dstport`<br>
`packet_time = packet.sniff_time`<br>
`packet_timestamp = packet.sniff_timestamp`<br>

<b>Output Example One:</b>
<br>

`Protocol type: UDP`<br>
`Source address: 192.168.3.1`<br>
`Source port: 53`<br>
`Destination address: 192.168.3.131`<br>
`Destination port: 58673`<br>
`Date and Time: 2011-01-25 13:57:18.356677`<br>
`Timestamp: 1295981838.356677000`<br>

<b>Example Two:</b>
<br>
`cap_file = 'traffic_flows_small.pcap'`<br>
`capture = pyshark.FileCapture(pcap_file)`<br>
`for packet in capture:`<br>
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`if hasattr(packet, 'http'):`<br>
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`field_names = packet.http._all_fields`<br>
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`field_values = packet.http._all_fields.values()`<br>
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`for field_name in field_names:`<br>
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`for field_value in field_values:`<br>
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`if field_name == 'http.request.full_uri' and field_value.startswith('http'):`<br>
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`print(f'{field_value}')`<br>
</p>

## Prerequisites
<p align="justify">
TShark has to be installed and accessible via your $PATH, which Python queries for PyShark. For this experiment TShark was installed using [homebrew](https://brew.sh).<br>

The package Wireshark installs the command line utility TShark. The command used to install Wireshark was:<br>

`brew install wireshark`
</p>

## References:

* [PyShark:](https://kiminewt.github.io/pyshark) Is the Python wrapper for TShark, that allows Python packet parsing using wireshark dissectors.

* [TShark:](https://www.wireshark.org/docs/man-pages/tshark.html) TShark is a terminal oriented version of Wireshark designed for capturing and displaying packets when an interactive user interface isn't necessary or available.

* [Wireshark:](https://www.wireshark.org) Wireshark is a network packet analysis tool that captures packets in real time and displays them in a graphic interface.

## Notes:

_The code within this repository is **not** production ready. It was **strictly** designed for experimental testing purposes only._
