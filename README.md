# Overview Packet Analysis

<p align="justify">
This repository contains code related to the Python module PyShark, which is a wrapper for the Wireshark CLI (TShark). The latter using the Wireshark dissectors to sniff and capture packets from a network inteface. The real power of PyShark is its capability to access to all of the packet decoders built into TShark.
</p>

<p align="justify">
PyShark can operate in either LiveCapture or FileCapture modes. Both modes have methods that can be used to parse specific
packet level attributes, which includes protocols and their associated ports. 
</p>

<p align="justify">
PyShark has two primary filters. The <b>BPF_Filter</b> is used in LiveCapture mode and the <b>Display_Filter</b> is used in the FileCapture mode.
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
