<h1> <strong>InMemCapture Parameters</strong> </h1>
---

<p align="justify"> 

The <strong>InMemCapture</strong> module within <strong>PyShark</strong> has several parameters that are configurable.  
</p>


```python

import pyshark

capture = pyshark.InMemCapture(bpf_filter=None, 
	                           display_filter=None, 
	                           only_summaries=False,
	                           decryption_key=None, 
	                           encryption_type='wpa-pwk', 
	                           decode_as=None,
	                           disable_protocol=None, 
	                           tshark_path=None, 
	                           override_prefs=None, 
	                           use_json=False, 
	                           use_ek=False,
	                           linktype=LinkTypes.ETHERNET, 
	                           include_raw=False, 
	                           eventloop=None, 
	                           custom_parameters=None,
	                           debug=False)
for packet in capture:
   # do something with the packet

```

<ul>


<li><strong>bpf_filter:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: BPF filter to use on packets.</li>  
</ul>
</li>

<li><strong>display_filter:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: Display (wireshark) filter to use.</li>  
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
		<li>description: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or 'WPA-PWK'. Defaults to WPA-PWK.</li>  
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

<li><strong>disable_protocol:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: Tells TShark to remove a dissector for a specific protocol.</li>  
</ul>
</li>

<li><strong>tshark_path:</strong>
	<ul>
		<li>type: string</li> 
		<li>default: None</li>
		<li>description: Path of the TShark binary.</li>  
</ul>
</li>

<li><strong>override_prefs:</strong>
	<ul>
		<li>type: dictionary</li> 
		<li>default: None</li>
		<li>description: A dictionary of TShark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}</li>  
</ul>
</li>

<li><strong>use_json:</strong>
	<ul>
		<li>type: boolean</li> 
		<li>default: False</li>
		<li>description: DEPRECATED. Use use_ek instead.</li>  
</ul>
</li>

<li><strong>use_ek:</strong>
	<ul>
		<li>type: boolean</li> 
		<li>default: False</li>
		<li>description: Uses TShark in EK JSON mode. It is faster than XML but has slightly less data.</li>  
</ul>
</li>

<li><strong>linktype:</strong>
	<ul>
		<li>type: class variable</li> 
		<li>default: LinkTypes.ETHERNET</li>
		<li>linktype variables:</li> 
		<ul>
			<li>LinkTypes.NULL</li>  
			<li>LinkTypes.ETHERNET</li> 
			<li>LinkTypes.IEEE802_5</li> 
			<li>LinkTypes.PPP</li> 
			<li>LinkTypes.IEEE802_11</li> 
		</ul>
		<li>description: Defines different link types with their corresponding numeric values.</li>

</ul>
</li>

<li><strong>include_raw:</strong>
	<ul>
		<li>type: boolean</li> 
		<li>default: False</li>
		<li>description: Whether to include raw packet data.</li>  
</ul>
</li>

<li><strong>eventloop:</strong>
	<ul>
		<li>type: event loop object</li> 
		<li>default: None</li>
		<li>description: Event loop to use for asynchronous operations.</li>  
</ul>
</li>

<li><strong>custom_parameters:</strong>
	<ul>
		<li>type: dictionary</li> 
		<li>default: None</li>
		<li>description: A dict of custom parameters to pass to TShark, i.e. {"--param": "value"} or
        else a list of parameters in the format ["--foo", "bar", "--baz", "foo"]</li>  
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


















