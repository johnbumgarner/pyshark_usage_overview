<h1> <strong>Packet Layers</strong></h1>
---

### OSI model overview 

<p align="justify"> 

The <strong>Open Systems Interconnection (OSI) model</strong> is a conceptual model created by the International Organization for Standardization which enables communication systems to communicate using standard protocols.
</br>
</br>
The OSI Model can be seen as a universal language for computer networking, which allows network traffic to be transferred and displayed between systems. 
</br>
</br>
This conceptual model is broken down into <strong><i>seven abstract layers</i></strong>, each one stacked upon the last.
</p>

#### OSI model layers

<ul>
   <li><strong>Application (Layer 7)</strong> - Displays the graphical User Interface (UI) - what the end-user sees</li>

   <li><strong>Presentation (Layer 6)</strong> - Formats data to achieve effective communication between networked applications</li>

   <li><strong>Session Layer (Layer 5)</strong> - Ensures connections between end-points are continuous and uninterrupted</li>

   <li><strong>Transports Layer (Layer 4)</strong> - Ensures error-free data transfer between each endpoint by processing <a href="https://www.rfc-editor.org/rfc/rfc793">TCP</a> and <a href="https://www.rfc-editor.org/rfc/rfc768">UDP</a> protocols. At this layer, <strong>Pyshark</strong> can be used to analyze TCP traffic between two IP addresses</li>

   <li><strong>Network Layer (Layer 3)</strong> - Ensures routing data for routers residing on this network are error-free</li>

   <li><strong>Data Link Layer (Layer 2)</strong> - Identifies physical servers through two sub-layers, Media Access Control (MAC), and Logical Link Control (LLC)</li>

   <li><strong>Physical Layer (Layer 1)</strong> - Comprised of all the physical hardware that processes network activity</li>
</ul>


#### OSI model layer protocol standards 

<ul>
   <li><strong>Application (Layer 7)</strong> - FTP, HTTP, POP3, SMTP, SNMP</li>

   <li><strong>Presentation (Layer 6)</strong>  - ASCH, MPEG, SSL, TLS</li>

   <li><strong>Session Layer (Layer 5)</strong> - NetBIOS, SAP</li>

   <li><strong>Transports Layer (Layer 4)</strong> - TCP, UDP</li>

   <li><strong>Network Layer (Layer 3)</strong> - ARP, ICMP, IPSEC, IPV5, IPV6, MPLS</li>

   <li><strong>Data Link Layer (Layer 2)</strong> - ATM, Fiber Cable, Frame Relay, PPP, RAPA</li>

   <li><strong>Physical Layer (Layer 1)</strong> - ISDN, RS232, 100BaseTX</li>
</ul>


### PyShark packet layer

<p align="justify"> 

All packets processed with <strong>PyShark</strong> have layers, but these layers vary based on the packet type. These layers can be queried and the data elements within these layers can be extracted. Layer types can be accessed using the following parameter: 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
    layers = packet.layers
    print(layers)
```


#### Common Layers:

<ul>
   <li>ETH Layer - Ethernet</li>
   <li>IP Layer - Internet Protocol</li>
   <li>TCP Layer - Transmission Control Protocol</li>
   <li>UDP Layer - User Datagram Protocol</li>
   <li>ARP Layer - Address Resolution Protocol</li>
</ul>


#### Other Layers:

<ul>
   <li>BROWSER Layer - Web browser</li>
   <li>DATA Layer - Normal data payload of a protocol</li>
   <li>DB-LSP-DISC Layer - Dropbox LAN Sync Discovery</li>
   <li>DHCP Layer - Dynamic Host Configuration Protocol</li>
   <li>HTTP Layer - Hypertext Transfer Protocol</li>
   <li>LLMNR Layer - Link-Local Multicast Name Resolution</li>
   <li>MAILSLOT Layer - Mailslot protocol is part of the SMB protocol family</li>
   <li>MSNMS Layer - Microsoft Network Messenger Service</li>
   <li>NAT-PMP Layer - NAT Port Mapping Protocol</li>
   <li>NBDGM Layer - NetBIOS Datagram Service</li>
   <li>NBNS Layer - NetBIOS Name Service</li>
   <li>SNMP Layer - Simple Network Management Protocol</li>
   <li>SSDP Layer - Simple Service Discovery Protocol</li>
   <li>TLS Layer - Transport Layer Security</li>
   <li>XML Layer - Extensible Markup Language</li>
</ul>
