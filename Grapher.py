import nmap
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QVBoxLayout, QListWidget, QSplitter, QLabel, QMessageBox, QLineEdit, QPushButton, QFileDialog, QProgressBar, QHBoxLayout
import random
import operator
import json
import time


class NmapScannerThread(QtCore.QThread):
    progress_update = QtCore.pyqtSignal(int)
    scan_complete = QtCore.pyqtSignal(object)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        nm = nmap.PortScannerYield()
        total_hosts = 0
        scanned_hosts = 0
        scan_results = {}

        for progress, scan_data in enumerate(nm.scan(hosts=self.target, arguments='-T4 -A -O --script vuln -vv')):
            scan_results = scan_data
            total_hosts += 1
            scanned_hosts += 1
            # Update progress
            percentage = int((scanned_hosts / total_hosts) * 100) if total_hosts > 0 else 0
            self.progress_update.emit(percentage)
            time.sleep(0.1)  # Simulate delay

        # Return full scan result
        self.scan_complete.emit(nmap.PortScanner()._scan_result)


# Function to detect gateways/routers/firewalls based on OS detection and open ports
def detect_gateways_and_subnets(scan_data):
    subnets = {}
    for host in scan_data.all_hosts():
        if 'hostnames' in scan_data[host]:
            hostname = scan_data[host]['hostnames'][0]['name'] if scan_data[host]['hostnames'] else "Unknown"
        else:
            hostname = "Unknown"
        
        # Check for OS detection to determine if the host is a router/gateway
        os_type = None
        if 'osclass' in scan_data[host]:
            os_type = scan_data[host]['osclass'][0]['type'] if scan_data[host]['osclass'] else None
            is_gateway = os_type in ['router', 'firewall', 'WAP']  # Wireless Access Points, Firewalls, Routers as gateways
        else:
            is_gateway = False

        # Detect based on common open ports (e.g., port 53, 67/68, 80/443)
        open_ports = scan_data[host]['tcp'] if 'tcp' in scan_data[host] else {}
        if any(port in [53, 67, 68, 80, 443] for port in open_ports.keys()):
            is_gateway = True

        # If TTL is high, it may indicate a router or gateway
        ttl = scan_data[host]['osclass'][0]['ttl'] if 'osclass' in scan_data[host] and scan_data[host]['osclass'] else random.randint(50, 150)

        if ttl not in subnets:
            subnets[ttl] = []
        subnets[ttl].append((host, hostname, is_gateway, os_type, open_ports))
    
    return subnets


# Function to create a graph from Nmap scan data with enhanced service-based visualization
def create_network_graph(scan_data):
    G = nx.Graph()
    subnets = detect_gateways_and_subnets(scan_data)
    
    starting_ip = scan_data.all_hosts()[0]
    G.add_node(starting_ip, color='red', label='Localhost', size=700)

    # Iterate through the detected subnets and add nodes/edges to the graph
    for ttl, hosts in subnets.items():
        subnet_node = f"Subnet-{ttl}"  # Name subnets based on TTL value for simplicity
        G.add_node(subnet_node, color='green', label=f"Subnet-{ttl}", size=500)  # Gateways are colored green
        
        for host, hostname, is_gateway, os_type, open_ports in hosts:
            # Customize nodes based on services they expose and vulnerabilities
            if 80 in open_ports or 443 in open_ports:  # HTTP/HTTPS Servers
                node_color = 'yellow'
            elif 53 in open_ports:  # DNS Servers
                node_color = 'purple'
            else:
                node_color = 'blue' if not is_gateway else 'orange'  # Gateways are colored orange

            # Vulnerability-based color customization
            if 'script' in scan_data[host] and 'vuln' in scan_data[host]['script']:
                node_color = 'red'  # Critical vulnerability detected

            node_size = 700 + len(open_ports) * 20  # Size based on number of open ports

            G.add_node(host, color=node_color, label=hostname, size=node_size)
            G.add_edge(subnet_node, host)  # Connect each host to its subnet

        # Link subnets to the starting IP for visualization
        G.add_edge(starting_ip, subnet_node)

    return G


# Function to visualize the graph in the PyQt5 window
def visualize_graph(graph, scan_data, highlight_node=None):
    fig, ax = plt.subplots(figsize=(7, 5))

    # Custom layout to group nodes hierarchically based on gateway/router relationships
    pos = nx.shell_layout(graph, nlist=[list(graph.neighbors(n)) for n in graph.nodes if 'Subnet' in n], rotate=True)
    
    # Draw nodes with colors and labels, and adjust node sizes
    colors = [graph.nodes[n]['color'] if n != highlight_node else 'lime' for n in graph.nodes]  # Highlight node in lime color
    sizes = [graph.nodes[n]['size'] for n in graph.nodes]
    labels = {n: graph.nodes[n]['label'] if 'label' in graph.nodes[n] else n for n in graph.nodes}
    
    nx.draw(graph, pos, ax=ax, node_color=colors, node_size=sizes, with_labels=True, labels=labels, font_size=9)

    # Draw edges with different line widths and colors based on their connections (e.g., subnets)
    edge_colors = ['green' if 'Subnet' in e[0] or 'Subnet' in e[1] else 'blue' for e in graph.edges]
    nx.draw_networkx_edges(graph, pos, edge_color=edge_colors, width=2)

    return fig, ax, pos


# Function to show node information in a pop-up
def show_node_info(node, scan_data):
    if node not in scan_data.all_hosts():
        QMessageBox.information(None, "Details", f"{node} is a subnet or gateway.")
        return

    open_ports = scan_data[node]['tcp'] if 'tcp' in scan_data[node] else {}
    vuln_info = scan_data[node].get('script', {}).get('vuln', {})
    vuln_summary = "\n".join([f"{vuln['id']}: {vuln['summary']}" for vuln in vuln_info.values()])

    ports_info = "\n".join([f"Port: {p}, Service: {open_ports[p]['name']}, Version: {open_ports[p]['version']}"
                            for p in open_ports])
    if not ports_info:
        ports_info = "No open ports found"

    if vuln_summary:
        ports_info += f"\n\nVulnerabilities:\n{vuln_summary}"

    QMessageBox.information(None, f"Details for {node}", ports_info)


# PyQt5 application setup
class NetworkMapApp(QtWidgets.QWidget):
    def __init__(self, previous_scan=None):
        super().__init__()
        self.previous_scan = previous_scan
        self.scan_data = None
        self.graph = None
        self.host_list = None
        self.search_box = None
        self.sort_button = None
        self.target_input = None
        self.progress_bar = None
        self.scan_status_label = None
        self.highlighted_node = None

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Network Map")

        # Create main layout
        layout = QVBoxLayout(self)

        # Add input field, run button, and progress bar at the top
        top_layout = QHBoxLayout()
        self.target_input = QLineEdit(self)
        self.target_input.setPlaceholderText("Enter target domain or CIDR")
        top_layout.addWidget(self.target_input)

        run_button = QPushButton("Run")
        run_button.clicked.connect(self.start_scan)
        top_layout.addWidget(run_button)

        # Progress Bar and Scan Status Label
        self.scan_status_label = QLabel("0% done")
        top_layout.addWidget(self.scan_status_label)
# Progress Bar and Scan Status Label
        self.scan_status_label = QLabel("0% done")
        top_layout.addWidget(self.scan_status_label)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        top_layout.addWidget(self.progress_bar)

        layout.addLayout(top_layout)

        # Splitter to separate graph and list
        splitter = QSplitter(QtCore.Qt.Horizontal)

        # Placeholder canvas for the network map
        self.canvas = QLabel("Network map will be displayed here.")
        splitter.addWidget(self.canvas)

        # Host list on the right
        host_panel = QtWidgets.QWidget()
        host_layout = QVBoxLayout()

        # Search Box
        self.search_box = QLineEdit(self)
        self.search_box.setPlaceholderText("Search by IP or Hostname")
        self.search_box.textChanged.connect(self.filter_host_list)
        host_layout.addWidget(self.search_box)

        # Host List
        self.host_list = QListWidget()
        self.host_list.itemClicked.connect(self.on_host_click)  # Connect the host click event
        host_layout.addWidget(self.host_list)

        # Sort Button
        self.sort_button = QPushButton("Sort by Open Ports")
        self.sort_button.clicked.connect(self.sort_host_list)
        host_layout.addWidget(self.sort_button)

        host_panel.setLayout(host_layout)
        splitter.addWidget(host_panel)

        layout.addWidget(splitter)
        self.setLayout(layout)

    # Function to start the scan
    def start_scan(self):
        target = self.target_input.text()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target domain or CIDR.")
            return

        self.scan_status_label.setText("Starting scan...")
        self.progress_bar.setValue(0)

        # Start the scan asynchronously using the NmapScannerThread
        self.scan_thread = NmapScannerThread(target)
        self.scan_thread.progress_update.connect(self.update_progress)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.start()

    # Progress update function
    def update_progress(self, percentage):
        self.progress_bar.setValue(percentage)
        self.scan_status_label.setText(f"{percentage}% done")

    # Called when the scan is complete
    def on_scan_complete(self, scan_data):
        self.scan_status_label.setText("Scan complete!")
        self.progress_bar.setValue(100)

        self.scan_data = scan_data
        # Create the network graph based on the scan data
        self.graph = create_network_graph(self.scan_data)
        fig, ax, _ = visualize_graph(self.graph, self.scan_data)

        # Update the canvas with the new graph
        self.canvas = FigureCanvas(fig)
        splitter = self.layout().itemAt(1).widget()  # Find the splitter in the layout
        splitter.widget(0).deleteLater()  # Delete the old placeholder widget
        splitter.insertWidget(0, self.canvas)  # Add the canvas with the new graph

        self.populate_host_list()

    # Populating the host list
    def populate_host_list(self):
        self.host_list.clear()
        for host in self.scan_data.all_hosts():
            open_ports = len(self.scan_data[host]['tcp']) if 'tcp' in self.scan_data[host] else 0
            vuln_info = self.scan_data[host].get('script', {}).get('vuln', {})
            vuln_indicator = '⚠️' if vuln_info else '✅'
            hostname = self.scan_data[host].hostname() or "Unknown"
            host_label = f"{vuln_indicator} {host} ({hostname}) - {open_ports} open ports"
            self.host_list.addItem(host_label)

    # Filter host list based on search input
    def filter_host_list(self):
        filter_text = self.search_box.text().lower()
        for index in range(self.host_list.count()):
            item = self.host_list.item(index)
            if filter_text in item.text().lower():
                item.setHidden(False)
            else:
                item.setHidden(True)

    # Sort host list by the number of open ports
    def sort_host_list(self):
        host_data = []
        for index in range(self.host_list.count()):
            item = self.host_list.item(index)
            host_text = item.text().split(' ')[1]  # Extract IP
            open_ports = len(self.scan_data[host_text]['tcp']) if 'tcp' in self.scan_data[host_text] else 0
            host_data.append((item, open_ports))

        # Sort the host data by the number of open ports in descending order
        host_data.sort(key=operator.itemgetter(1), reverse=True)

        # Clear the existing host list and repopulate it in the sorted order
        self.host_list.clear()
        for item, _ in host_data:
            self.host_list.addItem(item.text())

    # Handle host click event
    def on_host_click(self, item):
        # Extract the host's IP from the list item text
        host = item.text().split(' ')[1]  # Extract host IP from list item text

        # Highlight the node on the map
        self.highlighted_node = host
        fig, ax, _ = visualize_graph(self.graph, self.scan_data, highlight_node=host)

        # Update the canvas with the highlighted node
        self.canvas = FigureCanvas(fig)
        splitter = self.layout().itemAt(1).widget()  # Find the splitter in the layout
        splitter.widget(0).deleteLater()  # Delete the old placeholder widget
        splitter.insertWidget(0, self.canvas)  # Add the canvas with the new graph

        # Show detailed information about the selected host
        show_node_info(host, self.scan_data)


def main():
    import sys

    # Load previous scan data if available
    previous_scan_file = 'previous_scan.json'
    try:
        with open(previous_scan_file, 'r') as f:
            previous_scan = json.load(f)
    except FileNotFoundError:
        previous_scan = None

    app = QtWidgets.QApplication(sys.argv)
    window = NetworkMapApp(previous_scan=previous_scan)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
