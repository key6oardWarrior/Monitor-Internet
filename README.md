<!DOCTYPE-html>
 <html>
<body>

<h1>Monitor-Internet</h1>

<p>Allow users to monitor the internet connection of all devices on their network. Log any packet that is found in the searh params</p>

<h2>Command Line Args</h2>
<ol>
	<li><code>-i</code> (optional) which physical medium should be used to read packets being sent over the internet. Default for Windows is wi-fi and for Linux it is wlan0</li>
	<li><code>-f</code> (optionl) file location to store log files. Each log file will be the current date and time. The default is whatever path Monitor.py is in</li>
	<li><code>-c</code> (optional) which country or contries server(s) orign should logged</li>
	<li><code>-si</code> (optional) what source IP addresses should be logged if found. Regular expressions are allowed for example: 192.168.1.*</li>
	<li><code>-di</code> (optional) what destion IP addresses should be logged if found. Regular expressions are allowed for example: 192.168.*.12</li>
	<li><code>-sp</code> (optional) what source ports should be logged if found</li>
	<li><code>-dp</code> (optional) what destion ports should be logged if found</li>
	<li><code>-t</code> (optional) what transportation layer protocol should be logged if found</li>
	<li><code>-a</code> (optional) what app layer protocol should be logged if found</li>
</ol>