<h1> <strong>RemoteCapture Parameters</strong> </h1>
---

<p align="justify"> 

The <strong>RemoteCapture</strong> module within <strong>PyShark</strong> has several parameters that are configurable.  
</p>


```python

import pyshark

capture = pyshark.RemoteCapture(remote_host=None,
	                            remote_interface=None,
	                            remote_port=2002,
	                            bpf_filter=None,
	                            only_summaries=False,
	                            decryption_key=None,
	                            encryption_type="wpa-pwk",
	                            decode_as=None,
	                            disable_protocol=None,
	                            tshark_path=None,
	                            override_prefs=None,
	                            eventloop=None,
	                            debug=False,)
for packet in capture:
   # do something with the packet

```


<ul>

<li><strong>remote_host:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: required argument</li>
		<li>description: The remote host to capture on (IP or hostname). Should be running rpcapd.</li>  
</ul>
</li>

<li><strong>remote_interface:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: required argument</li>
		<li>description: The remote interface on the remote machine to capture on.</li>  
</ul>
</li>

<li><strong>remote_port:</strong>
	<ul>
		<li>type: int</li> 
		<li>default: 2002</li>
		<li>description: The remote port the rpcapd (remote daemon) service is listening on.</li>  
</ul>
</li>

<li><strong>bpf_filter:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: BPF filter to use on packets.</li>  
</ul>
</li>

<li><strong>only_summaries:</strong>
	<ul>
		<li>type: boolean</li> 
		<li>default: False</li>
		<li>description: Only produce packet summaries, much faster but includes very little information.</li>  
</ul>
</li>

<li><strong>decryption_key:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: Optional key used to encrypt and decrypt captured traffic.</li>  
</ul>
</li>

<li><strong>encryption_type:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: wpa-pwk</li>
		<li>description: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or 'WPA-PWK'.</li>  
</ul>
</li>

<li><strong>decode_as:</strong>
	<ul>
		<li>type: dictionary</li> 
		<li>default: None</li>
		<li>description: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell TShark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See TShark documentation for details.</li>  
</ul>
</li>

<li><strong>tshark_path:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: ath of the TShark binary.</li>  
</ul>
</li>

<li><strong>override_prefs:</strong>
	<ul>
		<li>type: dictionary</li> 
		<li>default: None</li>
		<li>description: A dictionary of TShark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}</li>  
</ul>
</li>

<li><strong>disable_protocol:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: Tells TShark to remove a dissector for a specific protocol.</li>  
</ul>
</li>

<li><strong>debug:</strong>
	<ul>
		<li>type: boolean</li> 
		<li>default: False</li>
		<li>description: Whether to enable debug mode.</li>  
</ul>
</li>

</ul>


















