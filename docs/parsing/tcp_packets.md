<h1> <strong>Parsing TCP Packets</strong></h1>

---

<p align="justify"> 

<strong>PyShark</strong> has a lot of flexibility to parse various types of information from an individual network packet. Below are some of the ways that Transmission Control Protocol (TCP) items can be parsed.

</p>

#### Filtering TCP Packets by source and destination

<p align="justify"> 

This example shows how to filter TCP packets by source and destination IP addresses. 

</p>


```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', display_filter='tcp')
for packet in capture:
   protocol = packet.transport_layer
   source_address = packet.ip.src
   source_port = packet[packet.transport_layer].srcport
   destination_address = packet.ip.dst
   destination_port = packet[packet.transport_layer].dstport 
   packet_time = packet.sniff_time
   packet_timestamp = packet.sniff_timestamp
```

Output:

```
Protocol type: TCP
Source address: 3.161.193.27
Source port: 443
Destination address: 192.168.86.22
Destination port: 58805
Date and Time: 2024-06-12 10:15:00.533168
Timestamp: 1718201700.533168000
```


#### Filtering HTTPS Packets

<p align="justify"> 

This example shows how to access the field elements within the TCP Layer.  It also show how to filter the packets for TCP Port 443, which is used 
by the Hypertext Transfer Protocol Secure (HTTPS) protocol that is used for secures communication. 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
    if hasattr(packet, 'tcp') and packet[packet.transport_layer].dstport == '443':
      print(packet)

```

Output:

```plaintext
Layer ETH:
   Destination: 28:bd:89:cf:9d:21
   Address: 28:bd:89:cf:9d:21
   .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
   .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
   Source: f8:ff:c2:50:40:95
   .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
   .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
   Type: IPv4 (0x0800)
   Address: f8:ff:c2:50:40:95
Layer IP:
   0100 .... = Version: 4
   .... 0101 = Header Length: 20 bytes (5)
   Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
   0000 00.. = Differentiated Services Codepoint: Default (0)
   .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
   Total Length: 82
   Identification: 0x0000 (0)
   010. .... = Flags: 0x2, Don't fragment
   0... .... = Reserved bit: Not set
   .1.. .... = Don't fragment: Set
   ..0. .... = More fragments: Not set
   ...0 0000 0000 0000 = Fragment Offset: 0
   Time to Live: 64
   Protocol: TCP (6)
   Header Checksum: 0x2507 [validation disabled]
   Header checksum status: Unverified
   Source Address: 192.168.86.139
   Destination Address: 140.82.114.25
Layer TCP:
   Source Port: 53871
   Destination Port: 443
   Stream index: 9
   Conversation completeness: Incomplete (12)
   TCP Segment Len: 30
   Sequence Number: 2    (relative sequence number)
   Sequence Number (raw): 2977936731
   Next Sequence Number: 32    (relative sequence number)
   Acknowledgment Number: 27    (relative ack number)
   Acknowledgment number (raw): 1788271858
   1000 .... = Header Length: 32 bytes (8)
   Flags: 0x018 (PSH, ACK)
   000. .... .... = Reserved: Not set
   ...0 .... .... = Accurate ECN: Not set
   .... 0... .... = Congestion Window Reduced: Not set
   .... .0.. .... = ECN-Echo: Not set
   .... ..0. .... = Urgent: Not set
   .... ...1 .... = Acknowledgment: Set
   .... .... 1... = Push: Set
   .... .... .0.. = Reset: Not set
   .... .... ..0. = Syn: Not set
   .... .... ...0 = Fin: Not set
   TCP Flags: ·······AP···
   Window: 2048
   Calculated window size: 2048
   Window size scaling factor: -1 (unknown)
   Checksum: 0x1528 [unverified]
   Checksum Status: Unverified
   Urgent Pointer: 0
   Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
   TCP Option - No-Operation (NOP)
   Kind: No-Operation (1)
   TCP Option - Timestamps
   Length: 10
   Timestamp value: 1749519908: TSval 1749519908, TSecr 1741751960
   Timestamp echo reply: 1741751960
   Timestamps
   Time since first frame in this TCP stream: 14.819388000 seconds
   Time since previous frame in this TCP stream: 0.000061000 seconds
   TCP payload (30 bytes)
   TCP Option - No-Operation (NOP)
   Kind: No-Operation (1)
   Kind: Time Stamp Option (8)
Layer TLS:
   TLSv1.2 Record Layer: Application Data Protocol: Hypertext Transfer Protocol
   Content Type: Application Data (23)
   Version: TLS 1.2 (0x0303)
   Length: 25
   Encrypted Application Data: d6c30b735ac2bb8038c9903b7c9205c8cf4cd4b13cbb8895bb
   Application Data Protocol: Hypertext Transfer Protocol

```


#### HTTPS Filtering with bpf_filter

<p align="justify"> 

This example shows how to filter Hypertext Transfer Protocol Secure (HTTPS) protocol packets using the <i>bpf_filter</i> option.

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', bpf_filter='tcp port 443')
for packet in capture:
      print(packet)

```

Output:

```plaintext
Packet (Length: 1514)
Layer ETH
:  Destination: 28:bd:89:cf:9d:21
   Address: 28:bd:89:cf:9d:21
   .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
   .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
   Source: f8:ff:c2:50:40:95
   .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
   .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
   Type: IPv4 (0x0800)
   Address: f8:ff:c2:50:40:95
Layer IP
:  0100 .... = Version: 4
   .... 0101 = Header Length: 20 bytes (5)
   Differentiated Services Field: 0x02 (DSCP: CS0, ECN: ECT(0))
   0000 00.. = Differentiated Services Codepoint: Default (0)
   .... ..10 = Explicit Congestion Notification: ECN-Capable Transport codepoint '10' (2)
   Total Length: 1500
   Identification: 0x0000 (0)
   010. .... = Flags: 0x2, Don't fragment
   0... .... = Reserved bit: Not set
   .1.. .... = Don't fragment: Set
   ..0. .... = More fragments: Not set
   ...0 0000 0000 0000 = Fragment Offset: 0
   Time to Live: 64
   Protocol: TCP (6)
   Header Checksum: 0x2cc9 [validation disabled]
   Header checksum status: Unverified
   Source Address: 192.168.86.22
   Destination Address: 52.96.189.50
Layer TCP
:  Source Port: 53995
   Destination Port: 443
   Stream index: 0
   Conversation completeness: Incomplete (0)
   ..0. .... = RST: Absent
   ...0 .... = FIN: Absent
   .... 0... = Data: Absent
   .... .0.. = ACK: Absent
   .... ..0. = SYN-ACK: Absent
   .... ...0 = SYN: Absent
   Completeness Flags: [ Null ]
   TCP Segment Len: 1448
   Sequence Number: 1    (relative sequence number)
   Sequence Number (raw): 1499305713
   Next Sequence Number: 1449    (relative sequence number)
   Acknowledgment Number: 1    (relative ack number)
   Acknowledgment number (raw): 132473324
   1000 .... = Header Length: 32 bytes (8)
   Flags: 0x010 (ACK)
   000. .... .... = Reserved: Not set
   ...0 .... .... = Accurate ECN: Not set
   .... 0... .... = Congestion Window Reduced: Not set
   .... .0.. .... = ECN-Echo: Not set
   .... ..0. .... = Urgent: Not set
   .... ...1 .... = Acknowledgment: Set
   .... .... 0... = Push: Not set
   .... .... .0.. = Reset: Not set
   .... .... ..0. = Syn: Not set
   .... .... ...0 = Fin: Not set
   TCP Flags: ·······A····
   Window: 1915
   Calculated window size: 1915
   Window size scaling factor: -1 (unknown)
   Checksum: 0x925a [unverified]
   Checksum Status: Unverified
   Urgent Pointer: 0
   Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
   TCP Option - No-Operation (NOP)
   Kind: No-Operation (1)
   TCP Option - Timestamps: TSval 2735122551, TSecr 49907491
   Length: 10
   Timestamp value: 2735122551
   Timestamp echo reply: 49907491
   Timestamps
   Time since first frame in this TCP stream: 0.000000000 seconds
   Time since previous frame in this TCP stream: 0.000000000 seconds
   SEQ/ACK analysis
   Bytes in flight: 1448
   Bytes sent since last PSH flag: 1448
   TCP payload (1448 bytes)
   TCP segment data (1448 bytes)
   TCP Option - No-Operation (NOP)
   Kind: No-Operation (1)
   Kind: Time Stamp Option (8)
Layer TLS
:  TLS segment data (1448 bytes)


```

#### HTTP Filtering with bpf_filter and display_filter


<p align="justify"> 

This example shows how to filter Hypertext Transfer Protocol (HTTP) protocol packets using both the <i>bpf_filter</i> and <i>display_filter</i>options.

</p>


```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', bpf_filter='tcp', display_filter='http')
for packet in capture:
      print(packet)

```

```plaintext
Layer HTTP
:  HTTP/1.1 200 OK\r\n
   Expert Info (Chat/Sequence): HTTP/1.1 200 OK\r\n
   HTTP/1.1 200 OK\r\n
   Severity level: Chat
   Group: Sequence
   Response Version: HTTP/1.1
   Status Code: 200
   Status Code Description: OK
   Response Phrase: OK
   Accept-Ranges: bytes\r\n
   Cache-Control: max-age=7200\r\n
   Content-Type: application/ocsp-response\r\n
   Date: Wed, 12 Jun 2024 18:37:29 GMT\r\n
   Last-Modified: Wed, 12 Jun 2024 18:17:16 GMT\r\n
   Server: ECAcc (agc/7F39)\r\n
   Content-Length: 471\r\n
   Content length: 471
   HTTP response 1/1
   Time since request: 0.023253000 seconds
   Request in frame: 24857
   Request URI: http://ocsp.digicert.com/ME8wTTBLMEkwRzAHBgUrDgMCGgQUOdKLcf4dGbZfs%2FEojyO8BFlcQ5UEFE4iVCAYlebjbuYP%2Bvq5Eu0GF485AhAE8i7MIfy0OCrCi48tZB%2FA
   File Data: 471 bytes
   \r\n
   Age: 1213\r\n
   X-Cache: HIT\r\n
```


#### HTTP Layer Filtering

<p align="justify"> 

This example shows how to access the field elements within the HTTP layer. The code below queries a Packet Capture (PCAP) file for all the URLs within the HTTP layer with the field name request.full_uri.

</p>


```python
import pyshark

capture = pyshark.FileCapture(pcap_file)
for packet in capture:
   if 'HTTP' in str(packet.layers):
     field_names = packet.http._all_fields
     field_values = packet.http._all_fields.values()
     for field_name in field_names:
        for field_value in field_values:
           if field_name == 'http.request.full_uri' and field_value.startswith('http'):
             print(f'{field_value}')

```

Output:

```plaintext
http://eu.httpbin.org
http://www.neverssl.com
http://www.testingmcafeesites.com
```

```

