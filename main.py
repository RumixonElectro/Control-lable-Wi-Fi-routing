import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import socket
import requests
from scapy.all import ARP, Ether, srp
import threading

# Dictionary to store Node MCU names and their IP addresses
node_mcu_ip_mapping = {}

# Predefined credentials
USERNAME = "admin"
PASSWORD = "password"

# Session timeout (in milliseconds)
SESSION_TIMEOUT = 2 * 60 * 1000  # 2 minutes
LOGIN_TIMEOUT = 30 * 1000        # 30 seconds

# Global variables for the timeout jobs and root window
timeout_job = None
login_timeout_job = None
root = None

# Log messages list
log_messages = []

def discover_node_mcus():
    global node_mcu_ip_mapping
    ip_range = "192.168.1.0/24"  # Replace this with your local network IP range
    
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        # Attempt to resolve the hostname (if available)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = None
        if hostname:
            node_mcu_ip_mapping[hostname] = ip

def resolve_node_pod_names():
    # Start the discovery process in a separate thread
    discovery_thread = threading.Thread(target=discover_node_mcus)
    discovery_thread.start()
    discovery_thread.join()

def clear_frame():
    for widget in main_frame.winfo_children():
        widget.destroy()

def create_node_pod_dropdown(frame):
    tk.Label(frame, text="Select Pod:").grid(row=0, column=0, padx=10, pady=10)
    node_pods = list(node_mcu_ip_mapping.keys())
    if not node_pods:
        node_pods = ["No Pods Found"]
    node_pod_var = tk.StringVar(frame)
    node_pod_var.set(node_pods[0])  # Set the first node pod as the default value
    node_pod_menu = tk.OptionMenu(frame, node_pod_var, *node_pods)
    node_pod_menu.grid(row=0, column=1, padx=10, pady=10)
    return node_pod_var

def Uplink():
    clear_frame()
    tk.Label(main_frame, text="Enter Uplink SSID:").grid(row=1, column=0, padx=10, pady=10)
    ssid_entry = tk.Entry(main_frame)
    ssid_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(main_frame, text="Enter Uplink Password:").grid(row=2, column=0, padx=10, pady=10)
    password_entry = tk.Entry(main_frame, show='*')
    password_entry.grid(row=2, column=1, padx=10, pady=10)

    def save_uplink_settings():
        ssid = ssid_entry.get().strip()
        password = password_entry.get().strip()
        if not ssid or not password:
            messagebox.showwarning("Input Error", "SSID and Password cannot be empty!")
            return

        progress_bar.start()
        log_message("Configuring uplink WiFi...")

        # Update Node MCU settings
        for name, ip in node_mcu_ip_mapping.items():
            url = f"http://{ip}/update"
            threading.Thread(target=send_to_node_mcu, args=(url, ssid, password)).start()

        progress_bar.stop()
        messagebox.showinfo("Info", f"Uplink WiFi configured with SSID: {ssid}")
        log_message(f"Uplink WiFi configured with SSID: {ssid}")

    save_button = tk.Button(main_frame, text="Save", command=save_uplink_settings)
    save_button.grid(row=3, columnspan=2, pady=10)

def NodeW():
    clear_frame()
    node_pod_var = create_node_pod_dropdown(main_frame)

    tk.Label(main_frame, text="Enter Pod SSID:").grid(row=1, column=0, padx=10, pady=10)
    ssid_entry = tk.Entry(main_frame)
    ssid_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(main_frame, text="Enter Pod Password:").grid(row=2, column=0, padx=10, pady=10)
    password_entry = tk.Entry(main_frame, show='*')
    password_entry.grid(row=2, column=1, padx=10, pady=10)

    def save_node_wifi_settings():
        node_pod = node_pod_var.get()
        ssid = ssid_entry.get().strip()
        password = password_entry.get().strip()
        if ssid == "" or password == "":
            messagebox.showwarning("Input Error", "SSID and Password cannot be empty!")
            return
        ip = node_mcu_ip_mapping.get(node_pod)
        if ip:
            url = f"http://{ip}/update"
            progress_bar.start()
            log_message(f"Configuring WiFi for {node_pod}...")
            threading.Thread(target=send_to_node_mcu, args=(url, ssid, password)).start()
            progress_bar.stop()
            messagebox.showinfo("Info", f"Pod WiFi configured for {node_pod} with SSID: {ssid}")
            log_message(f"Pod WiFi configured for {node_pod} with SSID: {ssid}")
        else:
            messagebox.showwarning("Error", f"IP address not found!!")
            log_message(f"Error: IP address not found for {node_pod}!!")

    save_button = tk.Button(main_frame, text="Save", command=save_node_wifi_settings)
    save_button.grid(row=3, columnspan=2, pady=10)

def NodeN():
    clear_frame()
    node_pod_var = create_node_pod_dropdown(main_frame)

    tk.Label(main_frame, text="Enter Pod Name:").grid(row=1, column=0, padx=10, pady=10)
    name_entry = tk.Entry(main_frame)
    name_entry.grid(row=1, column=1, padx=10, pady=10)

    def save_node_name():
        node_pod = node_pod_var.get()
        node_name = name_entry.get().strip()
        if not node_name:
            messagebox.showwarning("Input Error", "Node Name cannot be empty!")
            return
        ip = node_mcu_ip_mapping.get(node_pod)
        if ip:
            url = f"http://{ip}/update_name"
            progress_bar.start()
            log_message(f"Setting name for {node_pod}...")
            threading.Thread(target=send_to_node_mcu, args=(url, node_name, None)).start()
            progress_bar.stop()
            messagebox.showinfo("Info", f"Pod Name for {node_pod} set to: {node_name}")
            log_message(f"Pod Name for {node_pod} set to: {node_name}")
        else:
            messagebox.showwarning("Error", f"IP address not found!!")
            log_message(f"Error: IP address not found for {node_pod}!!")

    save_button = tk.Button(main_frame, text="Save", command=save_node_name)
    save_button.grid(row=2, columnspan=2, pady=10)

def NodeT():
    clear_frame()
    node_pod_var = create_node_pod_dropdown(main_frame)

    tk.Label(main_frame, text="Enter time in minutes:").grid(row=1, column=0, padx=10, pady=10)
    timer_entry = tk.Entry(main_frame)
    timer_entry.grid(row=1, column=1, padx=10, pady=10)

    def start_new_timer():
        node_pod = node_pod_var.get()
        timer_str = timer_entry.get().strip()
        if not timer_str.isdigit():
            messagebox.showwarning("Input Error", "Timer must be a positive integer!")
            return
        timer = int(timer_str)
        if timer <= 0:
            messagebox.showwarning("Input Error", "Timer must be a positive integer!")
            return
        ip = node_mcu_ip_mapping.get(node_pod)
        if ip:
            url = f"http://{ip}/start_timer"
            progress_bar.start()
            log_message(f"Starting timer for {node_pod}...")
            threading.Thread(target=send_to_node_mcu, args=(url, timer, None)).start()
            progress_bar.stop()
            messagebox.showinfo("Info", f"Timer for {node_pod} started for {timer} minutes")
            log_message(f"Timer for {node_pod} started for {timer} minutes")
        else:
            messagebox.showwarning("Error", f"IP address not found!!")
            log_message(f"Error: IP address not found for {node_pod}!!")

    start_button = tk.Button(main_frame, text="Start", command=start_new_timer)
    start_button.grid(row=2, columnspan=2, pady=10)

def send_to_node_mcu(url, ssid, password):
    try:
        payload = {'ssid': ssid, 'password': password} if password else {'name': ssid, 'timer': ssid}
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            log_message(f"Successfully sent to {url}")
        else:
            log_message(f"Failed to send to {url}. Status Code: {response.status_code}")
    except Exception as e:
        log_message(f"Error sending to {url}: {e}")

def log_message(message):
    log_messages.append(message)
    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, message + "\n")
    log_text.config(state=tk.DISABLED)

def show_intro_window():
    intro_window = tk.Tk()
    intro_window.title("Introduction")
    intro_window.geometry("500x300")
    intro_window.resizable(False, False)

    intro_text = (
        "Welcome to Pod Controller\n\n"
        "Creator Organisation: Rumixon IoTech\n"
        "Creator Person: Rishi Darade. (Shriraj)\n"
        "Software Name: Pod Controller\n"
        "Project: Controllable WiFi Pods or Controllable Internet Cafe"
    )
    tk.Label(intro_window, text=intro_text, wraplength=480, justify='left', font=('Arial', 12)).pack(padx=20, pady=20)

    def continue_to_login():
        intro_window.destroy()
        show_login_window()

    continue_button = tk.Button(intro_window, text="Continue", command=continue_to_login, font=('Arial', 12), bg='#4CAF50', fg='white')
    continue_button.pack(pady=10)

    intro_window.mainloop()

def show_login_window():
    global login_window, username_entry, password_entry, login_timeout_job
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("300x200")
    login_window.resizable(False, False)

    tk.Label(login_window, text="Username:").grid(row=0, column=0, padx=10, pady=10)
    username_entry = tk.Entry(login_window)
    username_entry.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(login_window, text="Password:").grid(row=1, column=0, padx=10, pady=10)
    password_entry = tk.Entry(login_window, show='*')
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    def login():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if username == USERNAME and password == PASSWORD:
            login_window.destroy()
            start_main_application()
        else:
            messagebox.showwarning("Login Failed", "Incorrect username or password. Please try again.")
            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)

    login_button = tk.Button(login_window, text="Login", command=login, font=('Arial', 12), bg='#4CAF50', fg='white')
    login_button.grid(row=2, columnspan=2, pady=10)

    def timeout():
        login_window.destroy()
        messagebox.showinfo("Session Expired", "Login session expired. Please restart the application.")
        root.quit()

    # Start the login timeout
    login_timeout_job = login_window.after(LOGIN_TIMEOUT, timeout)

    login_window.mainloop()

def start_main_application():
    global root, main_frame, progress_bar, log_text, timeout_job
    root = tk.Tk()
    root.title("Controllable Internet Cafe")

    fixed_width = 600
    fixed_height = 600
    root.geometry(f"{fixed_width}x{fixed_height}")
    root.resizable(False, False)  # Disable resizing

    main_frame = tk.Frame(root)
    main_frame.pack(padx=10, pady=10, fill='both', expand=True)

    menu_bar = tk.Menu(root)

    wifi_menu = tk.Menu(menu_bar, tearoff=0)
    wifi_menu.add_command(label="Uplink", command=Uplink)
    wifi_menu.add_command(label="NodeW", command=NodeW)
    menu_bar.add_cascade(label="WiFi Settings", menu=wifi_menu)

    node_menu = tk.Menu(menu_bar, tearoff=0)
    node_menu.add_command(label="NodeN", command=NodeN)
    node_menu.add_command(label="NodeT", command=NodeT)
    menu_bar.add_cascade(label="Node Settings", menu=node_menu)

    log_menu = tk.Menu(menu_bar, tearoff=0)
    log_menu.add_command(label="View Logs", command=show_log_window)
    menu_bar.add_cascade(label="Logs", menu=log_menu)

    root.config(menu=menu_bar)

    # Add progress bar
    progress_bar = ttk.Progressbar(root, mode='indeterminate')
    progress_bar.pack(side='bottom', fill='x')

    # Log window setup
    log_frame = tk.Frame(root)
    log_frame.pack(side='bottom', fill='both', expand=True)
    log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED, height=10)
    log_text.pack(fill='both', expand=True)

    resolve_node_pod_names()

    # Show Uplink settings by default
    Uplink()

    start_session_timeout()

    root.mainloop()

def show_log_window():
    log_window = tk.Toplevel(root)
    log_window.title("Log Window")
    log_window.geometry("600x400")

    log_text_window = scrolledtext.ScrolledText(log_window, state=tk.DISABLED)
    log_text_window.pack(fill='both', expand=True)

    log_text_window.config(state=tk.NORMAL)
    log_text_window.insert(tk.END, "\n".join(log_messages))
    log_text_window.config(state=tk.DISABLED)

def start_session_timeout():
    global timeout_job
    if timeout_job:
        root.after_cancel(timeout_job)
    timeout_job = root.after(SESSION_TIMEOUT, session_expired)

def session_expired():
    messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
    root.destroy()
    show_login_window()

# Start the application with the introduction window
show_intro_window()
