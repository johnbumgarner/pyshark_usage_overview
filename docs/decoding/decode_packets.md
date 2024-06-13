<h1> <strong>Decoding Packets</strong></h1>

---


<p align="justify"> 

<strong>PyShark</strong> has a lot of flexibility to parse various types of information from an individual network packet. Some of this information can decoded into a more human readable form. Below are some examples of decoding specific information within packets. 

</p>

#### Decoding TCP packets used for Telnet


```python
import pyshark

capture_file = os.path.abspath(r'telnet-raw.pcap')
capture = pyshark.FileCapture(input_file=capture_file)
for packet in capture:
    try:
        if hasattr(packet, 'tcp') and 'TELNET' in str(packet.layers):
            payload = packet.tcp.payload
            print(f'TCP payload: {payload}')
            hex_split = payload.split(':')
            hex_as_chars = map(lambda hex: chr(int(hex, 16)), hex_split)
            human_readable = ''.join(hex_as_chars)
            print(f'Decoded payload: {human_readable}')
    except AttributeError as error:
        pass


```

Output:

```plaintext

TCP payload: 6c:6f:67:69:6e:3a:20
Decoded payload: login: 

truncated...

TCP payload: 50:61:73:73:77:6f:72:64:3a
Decoded payload: Password:

truncated...

TCP payload: 50:49:4e:47:20:77:77:77:2e:79:61:68:6f:6f:2e:63:6f:6d:20:28:32:30:34:2e:37:31:2e:32:30:30:2e:37:34:29:3a:20:35:36:20:64:61:74:61:20:62:79:74:65:73:0d:0a
Decoded payload: PING www.yahoo.com (204.71.200.74): 56 data bytes


```