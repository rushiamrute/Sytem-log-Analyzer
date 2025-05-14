import os
import platform
import subprocess
import psutil
import win32evtlog
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox

# Get user accounts
def get_user_accounts():
    users = []
    system_type = platform.system()
    if system_type == "Linux":
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) > 2 and parts[0] and parts[2].isdigit():
                    uid = int(parts[2])
                    if uid >= 1000 or parts[0] == "root":
                        users.append(parts[0])
    elif system_type == "Windows":
        result = subprocess.check_output("net user", shell=True, text=True)
        lines = result.splitlines()
        capture = False
        for line in lines:
            line = line.strip()
            if line.startswith("-----"):
                capture = True
                continue
            if capture:
                if "The command completed successfully." in line:
                    break
                users += line.split()
    return users

# Get logs for Windows
def get_windows_logs(max_lines=100):
    logs = []
    try:
        server = 'localhost'
        log_type = 'System'
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events[:max_lines]:
            logs.append(str(event.SourceName) + ": " + str(event.StringInserts))
    except Exception as e:
        logs.append(f"Error reading logs: {e}")
    return logs

# Count system logs
def count_logs():
    if platform.system() == "Windows":
        return get_windows_logs(50)
    return []

# Analyze suspicious logs
def analyze_logs(logs):
    suspicious_keywords = [
        'error', 'failed', 'denied', 'unauthorized', 'malicious',
        'attack', 'refused', 'critical', 'crash', 'unexpected', 'shutdown'
    ]
    suspicious_logs = []
    for log in logs:
        if any(keyword in log.lower() for keyword in suspicious_keywords):
            suspicious_logs.append(log)
    return suspicious_logs

# Get system services
def get_services():
    services = []
    if platform.system() == "Windows":
        for service in psutil.win_service_iter():
            services.append(service.name())
    elif platform.system() == "Linux":
        try:
            output = subprocess.check_output(["systemctl", "list-units", "--type=service", "--no-pager"], text=True)
            services = [line.split()[0] for line in output.splitlines() if ".service" in line]
        except Exception as e:
            services = [f"Error getting services: {e}"]
    return services

# Get service ports
def get_service_ports():
    service_ports = []
    seen = set()

    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        subnet_mask = None

        # Get subnet mask for the primary interface
        for iface_name, iface_addrs in psutil.net_if_addrs().items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    subnet_mask = addr.netmask

        connections = psutil.net_connections(kind='inet')

        for conn in connections:
            if conn.status == 'TIME_WAIT':
                continue  # Skip short-lived connections

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            status = conn.status
            pid = conn.pid
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            key = (laddr, raddr, status, protocol)

            if key in seen:
                continue
            seen.add(key)

            process_name = "N/A"
            if pid and pid != 0:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Access Denied / No Process"

            service_ports.append({
                "protocol": protocol,
                "local": laddr,
                "remote": raddr,
                "status": status,
                "pid": pid,
                "process": process_name,
                "subnet_mask": subnet_mask,
                "ip_address": local_ip
            })

    except Exception as e:
        service_ports.append({
            "protocol": "N/A",
            "local": "N/A",
            "remote": "N/A",
            "status": f"Error: {e}",
            "pid": None,
            "process": "Error",
            "subnet_mask": None,
            "ip_address": None
        })

    return service_ports





# ... [Unchanged functions: get_user_accounts, get_windows_logs, count_logs, analyze_logs, get_services, get_service_ports] ...

# GUI with tabs, export, styling, and live status

def launch_gui():
    root = tk.Tk()
    root.title("🛡️ System Risk Scanner")
    root.geometry("1000x800")
    root.configure(bg="#1e1e1e")

    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook", background="#2b2b2b", borderwidth=0)
    style.configure("TNotebook.Tab", background="#444", foreground="white", padding=10, font=("Arial", 10, "bold"))
    style.map("TNotebook.Tab", background=[("selected", "#1abc9c")])

    # Title
    title = tk.Label(root, text="🛡️ System Risk Scanner", font=("Helvetica", 20, "bold"), bg="#1e1e1e", fg="white")
    title.pack(pady=10)

    # Tabs
    tab_control = ttk.Notebook(root)
    scan_tab = ttk.Frame(tab_control)
    tab_control.add(scan_tab, text="🔍 Scan")
    tab_control.pack(expand=1, fill="both", padx=10, pady=5)

    # Text output area
    output_box = scrolledtext.ScrolledText(scan_tab, wrap=tk.WORD, width=115, height=38, font=("Courier", 10), bg="#121212", fg="lightgray")
    output_box.pack(padx=10, pady=10)

    # Status label
    status_var = tk.StringVar()
    status_var.set("Status: Idle")
    status_label = tk.Label(root, textvariable=status_var, font=("Arial", 10, "italic"), bg="#1e1e1e", fg="#cccccc")
    status_label.pack(pady=5)

    # Store suspicious logs for later check
    scan_result = {"suspicious_logs": []}

    def run_scan():
        output_box.delete(1.0, tk.END)
        status_var.set("Status: Scanning...")
        root.update_idletasks()

        os_name = platform.system()
        users = get_user_accounts()
        logs = count_logs()
        services = get_services()
        ports = get_service_ports()
        suspicious = analyze_logs(logs)
        scan_result["suspicious_logs"] = suspicious

        output = []
        output.append(f"🖥️ Operating System: {os_name}")
        output.append(f"🧑‍💻 User Accounts Found: {len(users)}")
        output.append(f"⚙️  Services Detected: {len(services)}")
        output.append(f"📄 Total Log Entries Scanned: {len(logs)}")
        output.append(f"⚠️ Suspicious Logs Detected: {len(suspicious)}\n")

        output.append("\n👥  Users:")
        output += [f"   - {user}" for user in users[:5]]

        output.append("\n🗃️ Logs:")
        output += [f"   - {log}" for log in logs[:5]]

        output.append("\n🔌 Services and Network Connections:")
        for port_info in ports[:30]:
            output.append(
                f"   - Service: {port_info['process']:<25} "
                f"Protocol: {port_info['protocol']}  "
                f"Port: {port_info['local'].split(':')[-1]:<5} "
                f"Local: {port_info['local']:<22} "
                f"Remote: {port_info['remote']:<22} "
                f"Status: {port_info['status']:<12} "
                f"IP: {port_info.get('ip_address', 'N/A')}  "
                f"Subnet: {port_info.get('subnet_mask', 'N/A')}"
            )

        if suspicious:
            output.append("\n🚨 Suspicious Log Highlights:")
            output += [f"   - {log}" for log in suspicious[:5]]
        else:
            output.append("\n✅ No suspicious log activity found.")

        output_box.insert(tk.END, "\n".join(output))
        status_var.set("Status: Scan Complete ✅")

    def check_suspicious():
        suspicious_logs = scan_result.get("suspicious_logs", [])
        if suspicious_logs:
            messagebox.showwarning("Suspicious Activity", f"⚠️ Detected {len(suspicious_logs)} suspicious log entries!")
        else:
            messagebox.showinfo("Clean", "✅ No suspicious activity detected.")

    def export_results():
        content = output_box.get("1.0", tk.END)
        if not content.strip():
            messagebox.showwarning("Export Error", "No scan results to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}")

    def close_app():
        root.destroy()

    # Buttons
    button_frame = tk.Frame(root, bg="#1e1e1e")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="🔍 Run System Scan", command=run_scan, font=("Arial", 12), bg="#4CAF50", fg="white", padx=10).grid(row=0, column=0, padx=10)
    tk.Button(button_frame, text="⚠️ Check Suspicious Activity", command=check_suspicious, font=("Arial", 12), bg="#f39c12", fg="white", padx=10).grid(row=0, column=1, padx=10)
    tk.Button(button_frame, text="📤 Export Results", command=export_results, font=("Arial", 12), bg="#3498db", fg="white", padx=10).grid(row=0, column=2, padx=10)
    tk.Button(button_frame, text="❌ Close Window", command=close_app, font=("Arial", 12), bg="#e74c3c", fg="white", padx=10).grid(row=0, column=3, padx=10)

    root.mainloop()

if __name__ == "__main__":
    launch_gui()

