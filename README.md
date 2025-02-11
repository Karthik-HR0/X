<div align="center">

<h3>
  <b>

  <kbd>[**✖️**](https://github.com/Karthik-HR0/X)</kbd>

<kbd> Beta -0.1 V </kbd>
  </b>
</h3>

<h6>AUTOMATED XSS TARGET FINDER + XSS VULN SCANNER </h6>



</div>

<br>
<br>
<br>

> [!NOTE]  
> **_THIS IS IN BETA ( -0.1 V )._**

<br>
<br>
<br>

---
<kbd> 
<h3>ufxss</h3>
<table>
  <thead>
    <tr>
      <th>Argument</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>-d DOMAIN</code></td>
      <td>Target domain to scan (e.g., example.com)</td>
      <td>None</td>
    </tr>
    <tr>
      <td><code>-o OUTPUT</code></td>
      <td>Save results to the specified output file</td>
      <td>None</td>
    </tr>
    <tr>
      <td><code>-sp SPECIFIC_PATTERN</code></td>
      <td>Scan using a specific pattern (e.g., q=)</td>
      <td> xss pattern</td>
    </tr>
    <tr>
      <td><code>--filter</code></td>
      <td>Filter URLs using s0md3v's uro tool</td>
      <td><code>false</code></td>
    </tr>
  </tbody>
</table>


<div align="center">

| Category              | Core Capabilities                                  | Advanced Functionality                              | Intelligent Automation                               |
|-----------------------|----------------------------------------------------|---------------------------------------------------|---------------------------------------------------|
| **Historical URL Fetching** | • _`Wayback Machine Integration`_ <br>• _`AlienVault API Support`_ | • _`Duplicate URL Filtering`_ <br>• _`Domain-wide Coverage`_ | • _`Error Handling for Network Issues`_ <br>• _`Efficient URL Parsing`_ |
| **Pattern Matching**   | • _`Predefined Patterns for XSS Detection`_ <br>• _`Custom Pattern Support`_ | • _`Advanced Query Analysis`_ <br>• _`Heuristic-based Matching`_ | • _`Automatic Parameter Detection`_ <br>• _`Multi-pattern Matching`_ |
| **Ease of Use**        | • _`Command-Line Interface (CLI)`_ <br>• _`Single-command Execution`_ | • _`Optional Output File Generation`_ <br>• _`Custom Pattern Filtering`_ | • _`Simplified Workflow`_ <br>• _`Dynamic URL Filtering with uro`_ |
| **Extensibility**      | • _`Modular Design for URL Fetching`_ <br>• _`Python Package Integration`_ | • _`Easily Extendable for New Patterns`_ <br>• _`Centralized Pattern Module`_ | • _`Continuous Tool Updates`_ <br>• _`Custom Integration with APIs`_ |

</div>

</kbd>



<h6 align="center">
  USAGE 
</h6>

<kbd> # Scan a domain and display results </kbd>
```bash
python3 ufx.py -d example.com
``` 
<kbd> # Scan a domain and save results to a file </kbd>
```bash
python3 ufx.py -d example.com -o results.txt
``` 
<kbd> # Scan with a specific pattern (e.g., 'q=') </kbd>
```bash
python3 ufx.py -d example.com -sp q=
``` 
<kbd> # Scan with filtering enabled </kbd>
```bash
python3 ufx.py -d example.com --filter
``` 
---
<kbd>
<h3>XSS SCANNER</h3>
<table>
  <thead>
    <tr>
      <th>Argument</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>-url</code></td>
      <td>Specify a single URL to scan</td>
      <td>None</td>
    </tr>
    <tr>
      <td><code>-file</code></td>
      <td>Specify a file containing URLs</td>
      <td>None</td>
    </tr>
    <tr>
      <td><code>-payload</code></td>
      <td>Specify a payload file</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>



<div align="center">

| Category              | Core Capabilities                                  | Advanced Functionality                              | Intelligent Automation                               |
|-----------------------|----------------------------------------------------|---------------------------------------------------|---------------------------------------------------|
| **Payload Management** | • _`Custom Payload Support`_ <br>• _`Payload File Integration`_ | • _`Dynamic Payload URL Generation`_ <br>• _`Multiple Payload Handling`_ | • _`Automatic Payload Injection`_ <br>• _`Alert-based XSS Detection`_ |
| **Browser Automation** | • _`Selenium-based Testing`_ <br>• _`ChromeDriver Integration`_ | • _`Headless Scanning Mode`_ <br>• _`Automatic Alert Handling`_ | • _`Real-time Alert Capture`_ <br>• _`Advanced Timeout Management`_ |
| **Ease of Use**        | • _`Command-Line Interface (CLI)`_ <br>• _`Simple URL and File Input`_ | • _`Concurrency Support for Faster Scans`_ <br>• _`Streamlined Workflow`_ | • _`Custom Timeout Settings`_ <br>• _`Comprehensive Scan Summaries`_ |
| **Extensibility**      | • _`Python-based Modular Design`_ <br>• _`Integration with Other Tools`_ | • _`Expandable for New Vulnerabilities`_ <br>• _`Centralized Payload Management`_ | • _`Continuous Updates for New Techniques`_ <br>• _`Customizable Scanning Options`_ |

</div>
</kbd>

---


<div align="center">
<kbd> USAGE:↓ </kbd>
</div>

<kbd> # Scan a single URL with a payload file </kbd>
```bash
python3 xss.py -url https://example.com?search= -payload payloads.txt
```
<kbd> # Scan multiple URLs from a file </kbd>
```bash
python3 xss.py -file urls.txt -payload payloads.txt
```

<kbd> # Use piped input for URLs and scan with a payload file </kbd>
```bash
cat urls.txt | python3 xss.py -payload payloads.txt
```

