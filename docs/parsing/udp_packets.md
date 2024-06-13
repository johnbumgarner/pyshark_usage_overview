<h1> <strong>Parsing UDP Packets</strong></h1>

---

<p align="justify"> 

<strong>PyShark</strong> has a lot of flexibility to parse various types of information from an individual network packet. Below are some of the ways that User Datagram Protocol (UDP) items can be parsed.

</p>


#### DNS Filtering

<p align="justify"> 

This example shows how to filter the packets for UDP Port 53, which is used by the Domain Name System (DNS) service. 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
   try:
      if hasattr(packet, 'udp') and packet[packet.transport_layer].dstport == '53':
         if packet.dns.qry_name:
            source_address = packet.ip.src
            dns_location = packet.dns.qry_name
            print(f'DNS Request from IP: {source_address} to DNS Name: {dns_location}')
         elif packet.dns.resp_name:
            source_address = packet.ip.src
            dns_location = packet.dns.resp_name
            print(f'DNS Response from IP: {source_address} to DNS Name: {dns_location}')
   except AttributeError as error:
      pass

```

Output:

```
DNS Request from IP: 192.168.86.22 to DNS Name: www.google.com
DNS Request from IP: 192.168.86.22 to DNS Name: weather-data.apple.com
DNS Request from IP: 192.168.86.22 to DNS Name: stocks-data-service.apple.com
DNS Request from IP: 192.168.86.22 to DNS Name: alive.github.com
DNS Request from IP: 192.168.86.22 to DNS Name: www.cnn.com
```


#### DNS Filtering with display_filter

<p align="justify"> 

This example shows how to filter Domain Name System (DNS) packets using the <i>display_filter</i> option. 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', display_filter='dns')
for packet in capture:
   try:
      # obtain all the field names within the DNS packets
      field_names = packet.dns._all_fields

      # obtain all the field values
      field_values = packet.dns._all_fields.values()

      # enumerate the field names and field values
      for field_name, field_value in zip(field_names, field_values):
         print(f'{field_name}:  {field_value}')
   except AttributeError as error:
      pass

```

Output:

```paintext
dns.id:  0x588b
dns.flags:  0x8180
dns.flags.response:  True
dns.flags.opcode:  0
dns.flags.authoritative:  False
dns.flags.truncated:  False
dns.flags.recdesired:  True
dns.flags.recavail:  True
dns.flags.z:  False
dns.flags.authenticated:  False
dns.flags.checkdisable:  False
dns.flags.rcode:  0
dns.count.queries:  1
dns.count.answers:  4
dns.count.auth_rr:  0
dns.count.add_rr:  0
:  Queries
dns.qry.name:  cnn.com
dns.qry.name.len:  7
dns.count.labels:  2
dns.qry.type:  1
dns.qry.class:  0x0001
dns.resp.name:  cnn.com
dns.resp.type:  1
dns.resp.class:  0x0001
dns.resp.ttl:  53
dns.resp.len:  4
dns.a:  151.101.3.5
dns.response_to:  1729
dns.time:  0.030207000
```

#### DNS Filtering with bpf_filter

<p align="justify"> 

This example shows how to filter Domain Name System (DNS) packets using the <i>bpf_filter</i> option. 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', bpf_filter='port 53')
for packet in capture:
   try:
      # obtain all the field names within the DNS packets
      field_names = packet.dns._all_fields

      # obtain all the field values
      field_values = packet.dns._all_fields.values()

      # enumerate the field names and field values
      for field_name, field_value in zip(field_names, field_values):
         print(f'{field_name}:  {field_value}')
   except AttributeError as error:
      pass

```

Output:

```paintext
dns.id:  0xc9c1
dns.flags:  0x8180
dns.flags.response:  True
dns.flags.opcode:  0
dns.flags.authoritative:  False
dns.flags.truncated:  False
dns.flags.recdesired:  True
dns.flags.recavail:  True
dns.flags.z:  False
dns.flags.authenticated:  False
dns.flags.checkdisable:  False
dns.flags.rcode:  0
dns.count.queries:  1
dns.count.answers:  4
dns.count.auth_rr:  0
dns.count.add_rr:  0
:  Queries
dns.qry.name:  cnn.com
dns.qry.name.len:  7
dns.count.labels:  2
dns.qry.type:  1
dns.qry.class:  0x0001
dns.resp.name:  cnn.com
dns.resp.type:  1
dns.resp.class:  0x0001
dns.resp.ttl:  3
dns.resp.len:  4
dns.a:  151.101.195.5
dns.response_to:  1
dns.time:  0.067113000
```

#### DHCP Filtering with packet.layers

<p align="justify"> 

This example shows how to filter DHCP (Dynamic Host Configuration Protocol) packets using <i>packet.layers</i>.

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
   if 'DHCP' in str(packet.layers):
        try:
            # obtain all the field names within the DHCP packets
            field_names = packet.dhcp._all_fields

            # obtain all the field values
            field_values = packet.dhcp._all_fields.values()

            # enumerate the field names and field values
            for field_name, field_value in zip(field_names, field_values):
                print(f'{field_name}:  {field_value}')
         except AttributeError as error:
            pass

```

Output:

```paintext
dhcp.type:  1
dhcp.hw.type:  0x01
dhcp.hw.len:  6
dhcp.hops:  0
dhcp.id:  0x666719b8
dhcp.secs:  1
dhcp.flags:  0x8000
dhcp.flags.bc:  True
dhcp.flags.reserved:  0x0000
dhcp.ip.client:  0.0.0.0
dhcp.ip.your:  0.0.0.0
dhcp.ip.server:  0.0.0.0
dhcp.ip.relay:  0.0.0.0
dhcp.hw.mac_addr:  28:bd:89:cf:9d:21
dhcp.hw.addr_padding:  00:00:00:00:00:00:00:00:00:00
dhcp.server:  gwifi_rouge_dhcp_detection
dhcp.file:  0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
dhcp.cookie:  99.130.83.99
dhcp.option.type:  53
dhcp.option.length:  1
dhcp.option.value:  01
dhcp.option.dhcp:  1
dhcp.option.end:  255

```

#### DHCP Filtering with display_filter

<p align="justify"> 

This example shows how to filter DHCP (Dynamic Host Configuration Protocol) packets using the <i>display_filter</i> option. 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', display_filter='dhcp')
for packet in capture:
   try:
      # obtain all the field names within the DHCP packets
      field_names = packet.dhcp._all_fields

      # obtain all the field values
      field_values = packet.dhcp._all_fields.values()

      # enumerate the field names and field values
      for field_name, field_value in zip(field_names, field_values):
         print(f'{field_name}:  {field_value}')
   except AttributeError as error:
      pass

```

Output:

```paintext
dhcp.type:  1
dhcp.hw.type:  0x01
dhcp.hw.len:  6
dhcp.hops:  0
dhcp.id:  0x66671c2e
dhcp.secs:  1
dhcp.flags:  0x8000
dhcp.flags.bc:  True
dhcp.flags.reserved:  0x0000
dhcp.ip.client:  0.0.0.0
dhcp.ip.your:  0.0.0.0
dhcp.ip.server:  0.0.0.0
dhcp.ip.relay:  0.0.0.0
dhcp.hw.mac_addr:  28:bd:89:cf:9d:21
dhcp.hw.addr_padding:  00:00:00:00:00:00:00:00:00:00
dhcp.server:  gwifi_rouge_dhcp_detection
dhcp.file:  0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
dhcp.cookie:  99.130.83.99
dhcp.option.type:  53
dhcp.option.length:  1
dhcp.option.value:  01
dhcp.option.dhcp:  1
dhcp.option.end:  255

```

#### DHCP Filtering with bpf_filter

<p align="justify"> 

This example shows how to filter DHCP (Dynamic Host Configuration Protocol) packets using the <i>bpf_filter</i> option. 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', bpf_filter='port 67 and port 68')
for packet in capture:
   try:
      # obtain all the field names within the DHCP packets
      field_names = packet.dhcp._all_fields

      # obtain all the field values
      field_values = packet.dhcp._all_fields.values()

      # enumerate the field names and field values
      for field_name, field_value in zip(field_names, field_values):
         print(f'{field_name}:  {field_value}')
   except AttributeError as error:
      pass

```

Output:

```paintext
dhcp.type:  1
dhcp.hw.type:  0x01
dhcp.hw.len:  6
dhcp.hops:  0
dhcp.id:  0x66671c4c
dhcp.secs:  1
dhcp.flags:  0x8000
dhcp.flags.bc:  True
dhcp.flags.reserved:  0x0000
dhcp.ip.client:  0.0.0.0
dhcp.ip.your:  0.0.0.0
dhcp.ip.server:  0.0.0.0
dhcp.ip.relay:  0.0.0.0
dhcp.hw.mac_addr:  28:bd:89:cf:9d:21
dhcp.hw.addr_padding:  00:00:00:00:00:00:00:00:00:00
dhcp.server:  gwifi_rouge_dhcp_detection
dhcp.file:  0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
dhcp.cookie:  99.130.83.99
dhcp.option.type:  53
dhcp.option.length:  1
dhcp.option.value:  01
dhcp.option.dhcp:  1
dhcp.option.end:  255

```

#### NTP Filtering

<p align="justify"> 

This example shows how to filter the packets for UDP Port 123, which is used by the Network Time Protocol protocol.

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
   try:
      if hasattr(packet, 'udp') and packet[packet.transport_layer].dstport == '123':
         print(packet.layers)
         field_names = packet.ntp._all_fields
         field_values = packet.ntp._all_fields.values()
         for field_name, field_value in zip(field_names, field_values):
         print(f'Field Name: {field_name} -- Field Value: {field_value}')
   except AttributeError as error:
      pass

```

Output:

```paintext
Field Name: ntp.flags -- Field Value: 0xe3
Field Name: ntp.flags.li -- Field Value: 3
Field Name: ntp.flags.vn -- Field Value: 4
Field Name: ntp.flags.mode -- Field Value: 3
Field Name: ntp.stratum -- Field Value: 0
Field Name: ntp.ppoll -- Field Value: 8
Field Name: ntp.precision -- Field Value: 0
Field Name: ntp.rootdelay -- Field Value: 0
Field Name: ntp.rootdispersion -- Field Value: 0
Field Name: ntp.refid -- Field Value: 00:00:00:00
Field Name: ntp.reftime -- Field Value: NULL
Field Name: ntp.org -- Field Value: NULL
Field Name: ntp.rec -- Field Value: NULL
Field Name: ntp.xmt -- Field Value: Jan 29, 2023 23:43:52.523570988 UTC

```
