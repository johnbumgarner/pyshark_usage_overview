<script src="https://cdnjs.cloudflare.com/ajax/libs/clipboard.js/2.0.8/clipboard.min.js"></script>

<h1> <strong>Basic Usage</strong></h1>

<hr>

<p align="justify"> 

<strong>PyShark</strong> has several capture modes to process and dissect packet data.  These modes are <i>FileCapture</i>, <i>LiveCapture</i>, <i>RemoteCapture</i>, <i>InMemCapture</i> and <i>PipeCapture</i>. Each capture mode has various filters that can be applied to the packets being collected. 

</p>


### FileCapture Usage

<p align="justify"> 

<strong>FileCapture</strong> is designed to read and process data from a packet capture (PCAP) file. 

</p>


```python

import pyshark

capture = pyshark.FileCapture(input_file='your pcap file')
for packet in capture:
   # do something with the packet

```

### LiveCapture Usage

<p align="justify"> 

<strong>LiveCapture</strong> is designed to perform a live capture from a network interface. 

</p>

```python
import pyshark

capture = pyshark.LiveCapture(interface='your capture interface')
for packet in capture:
   # do something with the packet

```


### RemoteCapture Usage

<p align="justify"> 

<strong>RemoteCapture</strong> is designed to perform a live capture from a network interface on a remote machine which has a <a href="https://www.tcpdump.org/manpages/rpcapd.8.html">rpcapd</a> service running.

</p>


```python
import pyshark

capture = pyshark.RemoteCapture(remote_host='192.168.1.1', remote_interface='eth0')
for packet in capture:
   # do something with the packet
```

### LiveRingCapture Usage


<p align="justify"> 

<strong>LiveRingCapture</strong> is designed to perform a live capture from a network interface. 

</p>

```python
import pyshark

capture = pyshark.LiveRingCapture(interface='your capture interface')
for packet in capture:
   # do something with the packet

```

### InMemCapture Usage

<p align="justify"> 

<strong>InMemCapture</strong> is designed to perform a live capture directly in memory instead of saving them to a file. 
This capture method can be useful for real-time packet analysis or when you want to process packets as soon as they are captured.

</p>


```python
import pyshark

capture = pyshark.InMemCapture()
for packet in capture:
   # do something with the packet

```


### PipeCapture Usage

<p align="justify"> 

<strong>PipeCapture</strong> is designed to perform a capture from a named pipe rather than directly from a network interface or a file. A named pipe is a special file that is used to transfer data between unrelated processes.

Here is a <a href="https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes">Microsoft reference</a> on named pipes.

</p>


```python
import pyshark

capture = pyshark.PipeCapture(pipe='your pipe path')
for packet in capture:
   # do something with the packet

```





