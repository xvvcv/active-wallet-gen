import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import urllib.request
import urllib.error
import time
import random
import csv
from bitcoin import privkey_to_address
from mnemonic import Mnemonic
from bitcoinlib.keys import HDKey
from tkinter.ttk import Progressbar

class BitcoinGenerator:
    def __init__(self, start_range, end_range, use_random, use_seed_phrases, gui):
        self.use_random = use_random
        self.use_seed_phrases = use_seed_phrases
        if use_random and not use_seed_phrases:
            self.current_key = random.randint(0x1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140)
            self.end_range = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
        else:
            self.current_key = start_range
            self.end_range = end_range
        self.gui = gui
        self.total_generated = 0
        self.total_no_balance = 0
        self.total_with_balance = 0
        self.counter_lock = threading.Lock()
        self.running = True
        self.mnemo = Mnemonic("english")

    def generate_private_key(self):
        with self.counter_lock:
            if self.current_key > self.end_range or not self.running:
                return None
            private_key_int = self.current_key
            if self.use_random:
                self.current_key = random.randint(0x1, self.end_range)
            else:
                self.current_key += 1
            self.total_generated += 1
            self.gui.update_progress(self.total_generated)
        return hex(private_key_int)[2:].zfill(64)

    def generate_seed_phrase(self):
        with self.counter_lock:
            if not self.running:
                return None
            seed = self.mnemo.generate(strength=256)
            self.total_generated += 1
            self.gui.update_progress(self.total_generated)
        return seed

    def derive_address_from_seed(self, seed):
        hd_key = HDKey.from_seed(self.mnemo.to_seed(seed))
        priv_key = hd_key.private_hex
        address = hd_key.address()
        return priv_key, address

    def check_balance(self, private_key_hex):
        try:
            generated_address = privkey_to_address(private_key_hex)
            url = f"https://blockchain.info/q/getreceivedbyaddress/{generated_address}"
            response = urllib.request.urlopen(url)
            balance = int(response.read().decode('UTF8'))

            self.gui.log_message(f"Generated Bitcoin address: {generated_address}", "blue")
            self.gui.log_message(f"Private Key: {private_key_hex}", "yellow")

            if balance > 0:
                with open('generated_address_with_balance.txt', 'a') as f:
                    f.write(f"Address: {generated_address}, Private Key: {private_key_hex}, Balance: {balance} BTC\n")
                with self.counter_lock:
                    self.total_with_balance += 1
                self.gui.log_message(f"Active wallet found: {balance} BTC!", "green")
            else:
                with self.counter_lock:
                    self.total_no_balance += 1
                self.gui.log_message("No balance found.", "red")

        except urllib.error.URLError as e:
            self.gui.log_message(f"URLError: {e}", "red")
        except Exception as e:
            self.gui.log_message(f"Unexpected error: {e}", "red")

    def check_balance_seed(self, seed):
        try:
            private_key_hex, generated_address = self.derive_address_from_seed(seed)
            url = f"https://blockchain.info/q/getreceivedbyaddress/{generated_address}"
            response = urllib.request.urlopen(url)
            balance = int(response.read().decode('UTF8'))

            self.gui.log_message(f"Generated Bitcoin address: {generated_address}", "blue")
            self.gui.log_message(f"Seed Phrase: {seed}", "yellow")

            if balance > 0:
                with open('generated_address_with_balance.txt', 'a') as f:
                    f.write(f"Address: {generated_address}, Seed Phrase: {seed}, Balance: {balance} BTC\n")
                with self.counter_lock:
                    self.total_with_balance += 1
                self.gui.log_message(f"Active wallet found: {balance} BTC!", "green")
            else:
                with self.counter_lock:
                    self.total_no_balance += 1
                self.gui.log_message("No balance found.", "red")

        except urllib.error.URLError as e:
            self.gui.log_message(f"URLError: {e}", "red")
        except Exception as e:
            self.gui.log_message(f"Unexpected error: {e}", "red")

    def generate_and_check_loop(self):
        try:
            while self.running:
                if self.use_seed_phrases:
                    seed = self.generate_seed_phrase()
                    if seed is None:
                        break
                    self.check_balance_seed(seed)
                else:
                    private_key_hex = self.generate_private_key()
                    if private_key_hex is None:
                        break
                    self.check_balance(private_key_hex)
                self.gui.update_status(f"Keys/Seeds Generated: {self.total_generated}")
                time.sleep(1)  # Adding a delay to avoid hitting the rate limit
        except KeyboardInterrupt:
            self.gui.update_status("Process stopped by user")

    def stop(self):
        with self.counter_lock:
            self.running = False

class BitcoinGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Active Wallet Searcher")
        self.root.configure(bg="black")

        self.create_login_screen()

    def create_login_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Username:", fg="white", bg="black").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.username_entry = tk.Entry(self.root)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        tk.Label(self.root, text="Password:", fg="white", bg="black").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(self.root, text="Login", command=self.authenticate_user, fg="white", bg="black").grid(row=2, column=0, columnspan=2, pady=10)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

    def authenticate_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == "admin" and password == "password":  # Simple authentication for demo purposes
            self.create_main_screen()
        else:
            messagebox.showerror("Authentication Failed", "Invalid username or password")

    def create_main_screen(self):
        self.clear_screen()

        self.use_random_var = tk.IntVar()
        self.use_seed_var = tk.IntVar()

        tk.Label(self.root, text="Start Range (hex):", fg="white", bg="black").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.start_range_entry = tk.Entry(self.root)
        self.start_range_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        tk.Label(self.root, text="End Range (hex):", fg="white", bg="black").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.end_range_entry = tk.Entry(self.root)
        self.end_range_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        self.random_checkbox = tk.Checkbutton(self.root, text="Use Random Range", variable=self.use_random_var, command=self.toggle_random_range, fg="white", bg="black", selectcolor="black")
        self.random_checkbox.grid(row=2, column=0, columnspan=2, pady=10)

        self.seed_checkbox = tk.Checkbutton(self.root, text="Generate Seed Phrases", variable=self.use_seed_var, command=self.toggle_seed_phrase, fg="white", bg="black", selectcolor="black")
        self.seed_checkbox.grid(row=3, column=0, columnspan=2, pady=10)

        tk.Label(self.root, text="Number of Threads:", fg="white", bg="black").grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.threads_entry = tk.Entry(self.root)
        self.threads_entry.grid(row=4, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(self.root, text="Start", command=self.start_process, fg="white", bg="black").grid(row=5, column=0, columnspan=2, pady=10)
        tk.Button(self.root, text="Stop", command=self.stop_process, fg="white", bg="black").grid(row=6, column=0, columnspan=2, pady=10)

        self.log_text = tk.Text(self.root, state='disabled', width=50, height=10, bg="black", fg="white")
        self.log_text.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.progress = Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        self.status_label = tk.Label(self.root, text="Status: Waiting to start", fg="white", bg="black")
        self.status_label.grid(row=9, column=0, columnspan=2, pady=10, sticky="ew")

        tk.Button(self.root, text="Export Results", command=self.export_results, fg="white", bg="black").grid(row=10, column=0, columnspan=2, pady=10)

        self.log_text.tag_config("yellow", foreground="yellow")
        self.log_text.tag_config("blue", foreground="blue")
        self.log_text.tag_config("green", foreground="green")
        self.log_text.tag_config("red", foreground="red")

        self.root.grid_rowconfigure(7, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def toggle_random_range(self):
        if self.use_random_var.get():
            self.start_range_entry.config(state='disabled')
            self.end_range_entry.config(state='disabled')
        else:
            self.start_range_entry.config(state='normal')
            self.end_range_entry.config(state='normal')

    def toggle_seed_phrase(self):
        if self.use_seed_var.get():
            self.random_checkbox.config(state='disabled')
            self.start_range_entry.config(state='disabled')
            self.end_range_entry.config(state='disabled')
        else:
            self.random_checkbox.config(state='normal')
            self.start_range_entry.config(state='normal')
            self.end_range_entry.config(state='normal')

    def start_process(self):
        if self.use_random_var.get():
            start_range = 0
            end_range = 0
            use_random = True
        else:
            start_range = int(self.start_range_entry.get(), 16)
            end_range = int(self.end_range_entry.get(), 16)
            use_random = False

        use_seed_phrases = bool(self.use_seed_var.get())
        num_threads = int(self.threads_entry.get())

        self.generator = BitcoinGenerator(start_range, end_range, use_random, use_seed_phrases, self)
        self.threads = []

        self.progress["maximum"] = end_range - start_range
        self.progress["value"] = 0

        for _ in range(num_threads):
            thread = threading.Thread(target=self.generator.generate_and_check_loop)
            thread.start()
            self.threads.append(thread)

        self.update_status("Process started")

    def stop_process(self):
        if hasattr(self, 'generator'):
            self.generator.stop()
        self.update_status("Stopping process...")

        for thread in self.threads:
            thread.join()

        self.update_status("Process stopped")

    def update_status(self, status):
        self.status_label.config(text=f"Status: {status}")

    def update_progress(self, value):
        self.progress["value"] = value

    def log_message(self, message, tag):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)  # Autoscroll to the end
        self.log_text.config(state='disabled')

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open('generated_address_with_balance.txt', 'r') as infile, open(file_path, 'w', newline='') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(["Address", "Private Key/Seed Phrase", "Balance"])
                for line in infile:
                    writer.writerow(line.strip().split(", "))

if __name__ == "__main__":
    root = tk.Tk()
    app = BitcoinGUI(root)
    root.mainloop()
