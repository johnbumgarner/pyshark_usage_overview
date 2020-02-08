# Overview Packet Analysis

<p align="justify">
This repository contains code related to the Python module PyShark, which is a wrapper for the Wireshark CLI (TShark). The latter using the Wireshark dissectors to sniff and capture packets from a network inteface. The real power of PyShark is its capability to access to all of the packet decoders built into TShark.
</p>

<p align="justify">
PyShark can operate in either LiveCapture or FileCapture modes. Both modes have methods that can be used to parse specific
packet level attributes, which includes protocols and their associated ports. 
</p>

<p align="justify">
PyShark has two primary filters. The <i><b>BPF_Filter</b></i>, which is used in LiveCapture mode and the <i><b>Display_Filter</b></i> that is used in FileCapture mode.
</p>

<p align="justify">
<i><b>BPF_Filter</b></i>

`capture = pyshark.LiveCapture(interface=network_interface)
 capture.sniff(timeout=50)
 for raw_packet in capture.sniff_continuously():`

</p>


## Prerequisites
<p align="justify">
TShark has to be installed and accessible via your $PATH, which Python queries. 
</p>

## References:

* [PyShark:](https://kiminewt.github.io/pyshark) Is the Python wrapper for TShark, that allows Python packet parsing using wireshark dissectors.

* [TShark:](https://www.wireshark.org/docs/man-pages/tshark.html) TShark is a terminal oriented version of Wireshark designed for capturing and displaying packets when an interactive user interface isn't necessary or available.

* [Wireshark:](https://www.wireshark.org) Wireshark is a network packet analysis tool that captures packets in real time and displays them in a graphic interface.

## Notes:

_The code within this repository is **not** production ready. It was **strictly** designed for experimental testing purposes only._
