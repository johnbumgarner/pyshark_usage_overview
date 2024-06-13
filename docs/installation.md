
<h1><strong>PyShark Installation</strong></h1>

---

<h3>Installation Overview</h3>

<p align="justify"> 

There are multiple ways to install <i>PyShark</i> on systems running Microsoft Windows, Apple macOS or various flavors of Linux. An installation of <i>TShark</i> is also required for <i>PyShark</i> to function correctly.  <i>TShark</i> is the command-line interface (CLI) tool from <i>Wireshark</i>. In most cases it is beneficial to install <i>Wireshark</i>, which includes <i>TShark</i>. The binaries for <i>Wireshark</i> are <a href="https://www.wireshark.org/download.html">here.</a> 
</p>


<h3>PIP Installation Procedures</h3>

```
pip install pyshark

```
<p align="justify"> 
Use the following <i>pip</i> command to see the dependencies for <i>PyShark</i> prior to installing the package.
</p>

```
pip install --dry-run pyshark
```

<h3>Brew Installation Procedures</h3>

```
 brew install --cask wireshark

```

<p align="justify"> 
On Apple macOS systems <i>ChmodBPF</i> is also required to interact for network interfaces.
</p>

```
 brew install --cask wireshark-chmodbpf

```

<p align="justify"> 
Use the following <i>brew</i> command to see the dependencies for <i>Wireshark</i> prior to installing the package.
</p>

```
brew deps --tree  wireshark
```
