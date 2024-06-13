<h1> <strong>Parsing IP Packets</strong></h1>

---


<p align="justify"> 

<strong>PyShark</strong> has a lot of flexibility to parse various types of information from an individual network packet. Below are some of the items that can be parsed from the IP layer.  

</p>

#### IP Address filtering with display_filter


```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', display_filter='ip')
for packet in capture:
    try:
        # obtain all the field names within the IP packets
        field_names = packet.ip._all_fields

        # obtain all the field values
        field_values = packet.ip._all_fields.values()

        # enumerate the field names and field values
        for field_name, field_value in zip(field_names, field_values):
            print(f'{field_name}:  {field_value}')
    except AttributeError as error:

```

Output:

```plaintext
ip.version:  4
ip.hdr_len:  20
ip.dsfield:  0x00
ip.dsfield.dscp:  0
ip.dsfield.ecn:  0
ip.len:  88
ip.id:  0x1cf3
ip.flags:  0x02
ip.flags.rb:  False
ip.flags.df:  True
ip.flags.mf:  False
ip.frag_offset:  0
ip.ttl:  1
_ws.expert:  Expert Info (Note/Sequence): "Time To Live" != 255 for a packet sent to the Local Network Control Block (see RFC 3171)
ip.ttl.lncb:  "Time To Live" != 255 for a packet sent to the Local Network Control Block (see RFC 3171)
_ws.expert.message:  "Time To Live" != 255 for a packet sent to the Local Network Control Block (see RFC 3171)
_ws.expert.severity:  4194304
_ws.expert.group:  33554432
ip.proto:  17
ip.checksum:  0x649b
ip.checksum.status:  2
ip.src:  192.168.86.99
ip.addr:  192.168.86.99
ip.src_host:  192.168.86.99
ip.host:  192.168.86.99
ip.dst:  224.0.0.251
ip.dst_host:  224.0.0.251

```


#### Source and destination IP Address filtering 

<p align="justify"> 

This example shows how to access packet elements, such the source and destination IP addresses. 

</p>


```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
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

```paintext
Protocol type: TCP
Source address: 192.168.86.139
Source port: 63187
Destination address: 192.168.86.56
Destination port: 32206
Date and Time: 2023-01-25 10:55:18.625206
Timestamp: 1674662118.625206000
```




