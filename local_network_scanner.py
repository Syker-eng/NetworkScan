import subprocess
import sys
import socket
import fcntl
import struct
import ipaddress
from scapy.all import ARP, Ether, srp, conf
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import paramiko
import platform
import re

try:
    import paramiko
except ImportError:
    print("The 'paramiko' module is required for SSH features.")
    print("Install with: sudo pip3 install paramiko")
    sys.exit(1)

class NetworkScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Local Network Scanner for Windows Computers")
        self.geometry("900x650")

        self.device_type = "Unknown"
        self.create_widgets()
        threading.Thread(target=self.scan_local_network, daemon=True).start()

    def create_widgets(self):
        devices_frame = ttk.LabelFrame(self, text="Devices Found (Windows PCs Only)")
        devices_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.devices_text = scrolledtext.ScrolledText(devices_frame, height=15, font=("Courier", 10))
        self.devices_text.pack(fill=tk.BOTH, expand=True)

        interact_frame = ttk.LabelFrame(self, text="Interact with Windows PC")
        interact_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(interact_frame, text="Enter IP (IPv4):").pack(side=tk.LEFT, padx=5)
        self.ip_entry = ttk.Entry(interact_frame, width=30)
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        self.type_label = ttk.Label(interact_frame, text="Device Type: Unknown")
        self.type_label.pack(side=tk.LEFT, padx=10)

        self.check_type_button = ttk.Button(interact_frame, text="Check if Windows PC", command=self.check_device_type)
        self.check_type_button.pack(side=tk.LEFT, padx=5)

        self.ping_button = ttk.Button(interact_frame, text="Ping", command=self.ping_device)
        self.ping_button.pack(side=tk.LEFT, padx=5)

        self.portscan_button = ttk.Button(interact_frame, text="Port Scan (IPv4 only)", command=self.port_scan_device)
        self.portscan_button.pack(side=tk.LEFT, padx=5)

        self.upload_button = ttk.Button(interact_frame, text="Upload & Execute", command=self.upload_and_execute_file)
        self.upload_button.pack(side=tk.LEFT, padx=5)
        self.upload_button.config(state=tk.DISABLED)

        self.shutdown_button = ttk.Button(interact_frame, text="Shutdown via SSH", command=self.ssh_shutdown_device)
        self.shutdown_button.pack(side=tk.LEFT, padx=5)

        self.exit_button = ttk.Button(interact_frame, text="Exit", command=self.quit)
        self.exit_button.pack(side=tk.RIGHT, padx=5)

        output_frame = ttk.LabelFrame(self, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=20, font=("Courier", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)

    def append_output(self, text):
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.configure(state='disabled')

    def clear_output(self):
        self.output_text.configure(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state='disabled')

    def scan_local_network(self):
        conf.verb = 0

        try:
            ip, netmask, interface = get_local_ip_and_netmask()
        except Exception as e:
            self.devices_text.insert(tk.END, f"Error detecting network info: {e}\n")
            return

        cidr = ip_netmask_to_cidr(ip, netmask)

        self.devices_text.insert(tk.END, f"Detected interface: {interface}\n")
        self.devices_text.insert(tk.END, f"Local IP: {ip}\n")
        self.devices_text.insert(tk.END, f"Netmask: {netmask}\n")
        self.devices_text.insert(tk.END, f"Scanning subnet: {cidr}\n\n")

        devices = scan_network(cidr)
        if not devices:
            self.devices_text.insert(tk.END, "No devices found.\n")
            return

        windows_devices = []
        for device in devices:
            if is_windows_device(device['ip']):
                windows_devices.append(device)

        if not windows_devices:
            self.devices_text.insert(tk.END, "No Windows devices found.\n")
            return

        header = f"{'IPv4 Address':<16} {'MAC Address':<18} {'Hostname':<30}\n"
        self.devices_text.insert(tk.END, header)
        self.devices_text.insert(tk.END, "-" * 70 + "\n")

        for device in windows_devices:
            hostname = get_hostname(device['ip'])
            line = f"{device['ip']:<16} {device['mac']:<18} {hostname:<30}\n"
            self.devices_text.insert(tk.END, line)

    def check_device_type(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IPv4 address.")
            return
        if not validate_ipv4(ip):
            messagebox.showerror("Input Error", "Invalid IPv4 address format.")
            return

        self.type_label.config(text="Device Type: Checking...")

        def check_thread():
            if is_windows_device(ip):
                self.device_type = "Windows PC"
                self.type_label.config(text="Device Type: Windows PC")
                self.upload_button.config(state=tk.NORMAL)
            else:
                self.device_type = "Not Windows PC"
                self.type_label.config(text="Device Type: Not Windows PC")
                self.upload_button.config(state=tk.DISABLED)

        threading.Thread(target=check_thread, daemon=True).start()

    def ping_device(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IP address.")
            return
        if not validate_ipv4(ip):
            messagebox.showerror("Input Error", "Invalid IPv4 address format.")
            return

        self.clear_output()
        self.append_output(f"Pinging {ip} ...")

        def do_ping():
            try:
                output = subprocess.check_output(["ping", "-c", "4", ip], universal_newlines=True)
                self.append_output(output)
            except subprocess.CalledProcessError:
                self.append_output(f"Failed to ping {ip}")

        threading.Thread(target=do_ping, daemon=True).start()

    def port_scan_device(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IP address.")
            return
        if not validate_ipv4(ip):
            messagebox.showerror("Input Error", "Port scan supported only for IPv4 addresses.")
            return

        self.clear_output()
        self.append_output(f"Port scanning {ip} ...")

        def do_port_scan():
            common_ports = [21,22,23,25,53,80,110,139,143,443,445,3389]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.append_output(f"Port {port} is open")
                sock.close()
            self.append_output("Port scan completed.")

        threading.Thread(target=do_port_scan, daemon=True).start()

    def upload_and_execute_file(self):
        if self.device_type != "Windows PC":
            messagebox.showinfo("Not Supported", "Upload & execute is only supported for Windows PCs.")
            return

        ip = self.ip_entry.get().strip()
        username = simpledialog.askstring("SSH Username", "Enter SSH username:", parent=self)
        if username is None:
            return
        password = simpledialog.askstring("SSH Password", "Enter SSH password:", parent=self, show='*')
        if password is None:
            return

        file_path = filedialog.askopenfilename(title="Select file to upload and execute")
        if not file_path:
            return

        self.clear_output()
        self.append_output(f"Uploading and executing file on Windows PC {ip} ...")

        def do_upload_execute():
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)
                sftp = ssh.open_sftp()

                remote_path = f"C:\\Users\\{username}\\{os.path.basename(file_path)}"
                sftp.put(file_path, remote_path)

                cmd = f'start "" "{remote_path}"'
                ssh.exec_command(f'cmd /c {cmd}')

                sftp.close()
                ssh.close()

                self.append_output(f"File uploaded and executed on {ip} at {remote_path}")

            except Exception as e:
                self.append_output(f"Upload or execution failed: {e}")

        threading.Thread(target=do_upload_execute, daemon=True).start()

    def ssh_shutdown_device(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IP address.")
            return
        if not validate_ipv4(ip):
            messagebox.showerror("Input Error", "Invalid IPv4 address format.")
            return

        username = simpledialog.askstring("SSH Username", "Enter SSH username:", parent=self)
        if username is None:
            return
        password = simpledialog.askstring("SSH Password", "Enter SSH password:", parent=self, show='*')
        if password is None:
            return

        self.clear_output()
        self.append_output(f"Attempting SSH shutdown on {ip} ...")

        def do_ssh_shutdown():
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)

                cmd = "shutdown /s /t 0"
                ssh.exec_command(f'cmd /c {cmd}')

                ssh.close()

                self.append_output(f"Shutdown command sent successfully to {ip}.")

            except Exception as e:
                self.append_output(f"SSH shutdown failed: {e}")

        threading.Thread(target=do_ssh_shutdown, daemon=True).start()


def is_windows_device(ip):
    ports = [445, 3389]
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
        except Exception:
            pass
        sock.close()
    return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_local_ip_and_netmask(interface=None):
    if interface is None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            raise Exception("Failed to detect local IP address automatically.")
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ip = fcntl.ioctl(
                s.fileno(),
                0x8915,
                struct.pack('256s', interface.encode('utf-8')[:15])
            )[20:24]
            ip = socket.inet_ntoa(ip)
        except Exception:
            raise Exception(f"Failed to get IP for interface {interface}")

    if interface is None:
        interface = None
        with open('/proc/net/route') as f:
            for line in f.readlines():
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                interface = fields[0]
                break
        if interface is None:
            raise Exception("Failed to find default interface from /proc/net/route.")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        netmask = fcntl.ioctl(
            s.fileno(),
            0x891b,
            struct.pack('256s', interface.encode('utf-8')[:15])
        )[20:24]
        netmask = socket.inet_ntoa(netmask)
    except Exception:
        raise Exception(f"Failed to get netmask for interface {interface}")

    return ip, netmask, interface

def ip_netmask_to_cidr(ip, netmask):
    ip_int = struct.unpack('>I', socket.inet_aton(ip))[0]
    netmask_int = struct.unpack('>I', socket.inet_aton(netmask))[0]
    network_int = ip_int & netmask_int
    network = socket.inet_ntoa(struct.pack('>I', network_int))
    cidr = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
    return str(cidr)

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def validate_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def main():
    app = NetworkScannerApp()
    app.mainloop()

if __name__ == "__main__":
    conf.verb = 0
    main()
