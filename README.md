# Network mapping like Qualys does it a.k.a NmaplikeQualys

This is a Python-based network scanning tool that uses Nmap for network discovery and vulnerability detection, and visualizes the results using NetworkX, Matplotlib, and PyQt. The tool scans a network range (CIDR) or a specific target domain, visualizes the network as a graph, and allows users to interact with the results by highlighting nodes and displaying detailed information for each host.

## Features

Asynchronous Nmap Scanning: Runs network scans asynchronously, ensuring the GUI remains responsive during the scan process.

Real-time Scan Progress: A progress bar displays the real-time status of the scan (0-100%).

Network Visualization: Visualizes the scanned network as a graph using NetworkX and Matplotlib, with nodes representing hosts and edges representing connections.

Host Interaction: Clicking on a host in the list highlights its corresponding node on the network graph and displays detailed information about the host, including open ports, services, and detected vulnerabilities.

Vulnerability Detection: Hosts with detected vulnerabilities are marked in red for quick identification.

Filtering and Sorting: Host list can be filtered by IP/hostname and sorted by the number of open ports.




## Prerequisites

Before running the application, make sure you have the following dependencies installed:

Python 3.6+
python-nmap
networkx
matplotlib
PyQt5


### Installing Dependencies

You can install the required dependencies by running the following command:

`bash
pip install python-nmap networkx matplotlib pyqt5`

Additionally, Nmap must be installed on your system. You can download and install Nmap from here.

How to Run

1. Clone the repository to your local machine:

`git clone https://github.com/your-username/network-map-scanning-tool.git
cd network-map-scanning-tool`


2. Install the dependencies as mentioned above.


3. Run the Python script:

python network_map.py


4. Enter a target domain or CIDR (e.g., 192.168.1.0/24) in the input field and click Run.


5. The progress bar will display the progress of the scan. Once the scan is complete, the network map and host list will be displayed.


6. Clicking on a host in the list will highlight its corresponding node on the map and display detailed information about the host in a pop-up window.



## Features in Detail

1. Asynchronous Scanning

The tool uses QThread to run Nmap scans in the background, keeping the UI responsive during the scan. As the scan progresses, the progress bar and status label are updated to reflect the current progress.

2. Real-time Network Visualization

Once the scan is complete, the network is visualized as a graph where each node represents a host, and edges represent subnets or logical connections. Hosts with vulnerabilities are colored red, HTTP/HTTPS servers are yellow, DNS servers are purple, and gateway devices are orange.

3. Interactive Host List

The host list on the right side of the window displays all the detected hosts. You can filter this list using the search box or sort it by the number of open ports. Clicking on a host highlights its corresponding node on the network map and shows detailed information in a pop-up.

4. Detailed Host Information

Clicking on a host displays a pop-up with detailed information about the host, including open ports, services, service versions, and detected vulnerabilities.

Example Use Case

This tool can be used for network discovery, vulnerability assessment, and network visualization in a simple and interactive manner. It's particularly useful for:

Bug bounty hunters looking to visualize network infrastructures.

Pentesters who need a graphical representation of network scans.

Network administrators looking to understand network structure and potential vulnerabilities.



