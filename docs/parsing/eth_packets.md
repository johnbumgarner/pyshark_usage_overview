<h1> <strong>Parsing Ethernet Packets</strong></h1>

---


<p align="justify"> 

<strong>PyShark</strong> has a lot of flexibility to parse various types of information from an individual network packet. Below are some of the items that can be parsed from the Ethernet layer of a packet.  

</p>

#### Ethernet filtering with display_filter


```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface', display_filter='eth')
for packet in capture:
    try:
        # obtain all the field names within the ETH packets
        field_names = packet.eth._all_fields

        # obtain all the field values
        field_values = packet.eth._all_fields.values()

        # enumerate the field names and field values
        for field_name, field_value in zip(field_names, field_values):
            print(f'{field_name}:  {field_value}')
    except AttributeError as error:

```

Output:

```plaintext
eth.dst:  01:00:5e:00:00:fb
eth.dst_resolved:  01:00:5e:00:00:fb
eth.dst.oui:  65630
eth.dst.oui_resolved:  ICANN, IANA Department
eth.addr:  01:00:5e:00:00:fb
eth.addr_resolved:  01:00:5e:00:00:fb
eth.addr.oui:  65630
eth.addr.oui_resolved:  ICANN, IANA Department
eth.dst.lg:  False
eth.lg:  False
eth.dst.ig:  True
eth.ig:  True
eth.src:  00:18:dd:54:00:a2
eth.src_resolved:  00:18:dd:54:00:a2
eth.src.oui:  6365
eth.src.oui_resolved:  Silicondust Engineering Ltd
eth.src.lg:  False
eth.src.ig:  False
eth.type:  0x0800

```