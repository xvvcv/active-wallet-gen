import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import urllib.request
import urllib.error
import time
import random
import csv
import logging
from bitcoin import privkey_to_address
from mnemonic import Mnemonic
from bitcoinlib.keys import HDKey

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

class BitcoinGenerator:
    def __init__(self, start_range, end_range, use_random, use_seed_phrases, use_random_within_range, target_address, gui):
        self.use_random = use_random
        self.use_seed_phrases = use_seed_phrases
        self.use_random_within_range = use_random_within_range
        self.target_address = target_address
        self.end_range = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140 if use_random and not use_seed_phrases else end_range
        self.current_key = random.randint(0x1, self.end_range) if use_random and not use_seed_phrases else start_range
        self.start_range = start_range
        self.gui = gui
        self.total_generated = 0
        self.total_no_balance = 0
        self.total_with_balance = 0
        self.counter_lock = threading.Lock()
        self.running = True
        self.mnemo = Mnemonic("english")
        logger.info("BitcoinGenerator initialized")

    def generate_private_key(self):
        with self.counter_lock:
            if self.current_key > self.end_range or not self.running:
                return None
            if self.use_random_within_range:
                private_key_int = random.randint(self.start_range, self.end_range)
            else:
                private_key_int = self.current_key
                self.current_key = random.randint(self.start_range, self.end_range) if self.use_random else self.current_key + 1
            self.total_generated += 1
            logger.info(f"Generated private key: {hex(private_key_int)[2:].zfill(64)}")
        return hex(private_key_int)[2:].zfill(64)

    def generate_seed_phrase(self):
        with self.counter_lock:
            if not self.running:
                return None
            seed = self.mnemo.generate(strength=256)
            self.total_generated += 1
            logger.info(f"Generated seed phrase: {seed}")
        return seed

    def derive_address_from_seed(self, seed):
        hd_key = HDKey.from_seed(self.mnemo.to_seed(seed))
        priv_key = hd_key.private_hex
        address = hd_key.address()
        logger.info(f"Derived address from seed: {address}")
        return priv_key, address

    def check_bitcoin_balance(self, private_key_hex):
        try:
            generated_address = privkey_to_address(private_key_hex)
            url = f"https://blockchain.info/q/getreceivedbyaddress/{generated_address}"
            response = urllib.request.urlopen(url)
            balance = int(response.read().decode('UTF8'))

            self.log_bitcoin_balance(generated_address, private_key_hex, balance)
            self.update_counters(balance > 0)

            if generated_address == self.target_address:
                self.handle_target_address_found()

        except urllib.error.URLError as e:
            self.log_error(f"URLError: {e}")
        except Exception as e:
            self.log_error(f"Unexpected error: {e}")

    def check_balance_seed(self, seed):
        try:
            private_key_hex, generated_address = self.derive_address_from_seed(seed)
            self.check_bitcoin_balance(private_key_hex)
        except urllib.error.URLError as e:
            self.log_error(f"URLError: {e}")
        except Exception as e:
            self.log_error(f"Unexpected error: {e}")

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
                    self.check_bitcoin_balance(private_key_hex)
                self.gui.update_status(f"Keys/Seeds Generated: {self.total_generated}")
                time.sleep(1)  # Adding a delay to avoid hitting the rate limit
        except KeyboardInterrupt:
            self.gui.update_status("Process stopped by user")

    def stop(self):
        with self.counter_lock:
            self.running = False
        logger.info("BitcoinGenerator stopped")

    def log_bitcoin_balance(self, address, private_key, balance):
        self.gui.log_message(f"Generated Bitcoin address: {address}", "blue")
        self.gui.log_message(f"Private Key: {private_key}", "yellow")
        if balance > 0:
            with open('generated_address_with_balance.txt', 'a') as f:
                f.write(f"Address: {address}, Private Key: {private_key}, Balance: {balance / 1e8} BTC\n")
            self.gui.log_message(f"Active wallet found: {balance / 1e8} BTC!", "green")
            logger.info(f"Active Bitcoin wallet found: {balance / 1e8} BTC at address {address}")
        else:
            self.gui.log_message("No balance found.", "red")

    def log_error(self, message):
        self.gui.log_message(message, "red")
        logger.error(message)

    def update_counters(self, has_balance):
        with self.counter_lock:
            if has_balance:
                self.total_with_balance += 1
                self.gui.update_wallet_counter(self.total_with_balance)
            else:
                self.total_no_balance += 1

    def handle_target_address_found(self):
        self.gui.log_message(f"Target address {self.target_address} found! Auto-stopping.", "green")
        self.stop()
        self.gui.auto_export_results()

class BitcoinGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Active Wallet Searcher")
        self.root.configure(bg="#1A237E")  # Dark navy blue

        self.main_frame = tk.Frame(self.root, bg="#1A237E")  # Dark navy blue
        self.main_frame.pack(fill="both", expand=True)

        self.create_menu()
        self.create_login_screen()

        self.threads = []  # Initialize threads list

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_login_screen(self):
        self.clear_screen()

        frame = tk.Frame(self.main_frame, bg="#1A237E")
        frame.pack(padx=20, pady=20)

        tk.Label(frame, text="Username:", fg="white", bg="#1A237E").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.username_entry = tk.Entry(frame)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        tk.Label(frame, text="Password:", fg="white", bg="#1A237E").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.password_entry = tk.Entry(frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(frame, text="Login", command=self.authenticate_user, fg="white", bg="red", activebackground="green", activeforeground="white").grid(row=2, column=0, columnspan=2, pady=10)

        frame.grid_columnconfigure(1, weight=1)

    def authenticate_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == "admin" and password == "password":  # Simple authentication for demo purposes
            self.create_main_screen()
        else:
            messagebox.showerror("Authentication Failed", "Invalid username or password")

    def create_main_screen(self):
        self.clear_screen()

        frame = tk.Frame(self.main_frame, bg="#1A237E")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        self.use_random_var = tk.IntVar()
        self.use_seed_var = tk.IntVar()
        self.use_random_within_range_var = tk.IntVar()

        tk.Label(frame, text="Start Range (hex):", fg="white", bg="#1A237E").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.start_range_entry = tk.Entry(frame)
        self.start_range_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        tk.Label(frame, text="End Range (hex):", fg="white", bg="#1A237E").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.end_range_entry = tk.Entry(frame)
        self.end_range_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        self.random_checkbox = tk.Checkbutton(frame, text="Use Random Range", variable=self.use_random_var, command=self.toggle_random_range, fg="white", bg="#1A237E", selectcolor="black")
        self.random_checkbox.grid(row=2, column=0, columnspan=2, pady=10)

        self.random_within_range_checkbox = tk.Checkbutton(frame, text="Use Random Keys Within Range", variable=self.use_random_within_range_var, fg="white", bg="#1A237E", selectcolor="black")
        self.random_within_range_checkbox.grid(row=3, column=0, columnspan=2, pady=10)

        self.seed_checkbox = tk.Checkbutton(frame, text="Generate Seed Phrases", variable=self.use_seed_var, command=self.toggle_seed_phrase, fg="white", bg="#1A237E", selectcolor="black")
        self.seed_checkbox.grid(row=4, column=0, columnspan=2, pady=10)

        tk.Label(frame, text="Number of Threads:", fg="white", bg="#1A237E").grid(row=5, column=0, padx=10, pady=10, sticky="w")
        self.threads_entry = tk.Entry(frame)
        self.threads_entry.grid(row=5, column=1, padx=10, pady=10, sticky="ew")

        tk.Label(frame, text="Target Address:", fg="white", bg="#1A237E").grid(row=6, column=0, padx=10, pady=10, sticky="w")
        self.target_address_entry = tk.Entry(frame)
        self.target_address_entry.grid(row=6, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(frame, text="Start", command=self.start_process, fg="white", bg="red", activebackground="green", activeforeground="white").grid(row=7, column=0, columnspan=2, pady=10)
        tk.Button(frame, text="Stop", command=self.stop_process, fg="white", bg="red", activebackground="green", activeforeground="white").grid(row=8, column=0, columnspan=2, pady=10)

        self.log_text = tk.Text(frame, state='disabled', width=50, height=10, bg="black", fg="white")
        self.log_text.grid(row=9, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.log_text.tag_config("blue", foreground="blue")
        self.log_text.tag_config("yellow", foreground="yellow")
        self.log_text.tag_config("green", foreground="green")
        self.log_text.tag_config("red", foreground="red")

        self.status_label = tk.Label(frame, text="Status: Waiting to start", fg="white", bg="#1A237E")
        self.status_label.grid(row=10, column=0, columnspan=2, pady=10, sticky="ew")

        self.wallet_counter_label = tk.Label(frame, text="Wallets Found with Balance: 0", fg="white", bg="#1A237E")
        self.wallet_counter_label.grid(row=11, column=0, columnspan=2, pady=10, sticky="ew")

        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(9, weight=1)

    def clear_screen(self):
        for widget in self.main_frame.winfo_children():
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
            self.random_within_range_checkbox.config(state='disabled')
            self.start_range_entry.config(state='disabled')
            self.end_range_entry.config(state='disabled')
        else:
            self.random_checkbox.config(state='normal')
            self.random_within_range_checkbox.config(state='normal')
            self.start_range_entry.config(state='normal')
            self.end_range_entry.config(state='normal')

    def validate_inputs(self):
        if not self.use_random_var.get():
            try:
                int(self.start_range_entry.get(), 16)
                int(self.end_range_entry.get(), 16)
            except ValueError:
                messagebox.showerror("Input Error", "Start and End Range must be valid hexadecimal numbers")
                return False

        if int(self.threads_entry.get()) <= 0:
            messagebox.showerror("Input Error", "Number of Threads must be greater than 0")
            return False

        return True

    def start_process(self):
        if not self.validate_inputs():
            return

        if self.use_random_var.get():
            start_range = 0
            end_range = 0
            use_random = True
        else:
            start_range = int(self.start_range_entry.get(), 16)
            end_range = int(self.end_range_entry.get(), 16)
            use_random = False

        use_seed_phrases = bool(self.use_seed_var.get())
        use_random_within_range = bool(self.use_random_within_range_var.get())
        num_threads = int(self.threads_entry.get())
        target_address = self.target_address_entry.get()

        self.generator = BitcoinGenerator(start_range, end_range, use_random, use_seed_phrases, use_random_within_range, target_address, self)
        self.threads = []

        for _ in range(num_threads):
            thread = threading.Thread(target=self.generator.generate_and_check_loop)
            thread.start()
            self.threads.append(thread)

        self.update_status("Process started")
        logger.info("Process started")

    def stop_process(self):
        if hasattr(self, 'generator'):
            self.generator.stop()
        self.update_status("Stopping process...")
        logger.info("Stopping process...")

        for thread in self.threads:
            thread.join()

        self.update_status("Process stopped")
        logger.info("Process stopped")

    def update_status(self, status):
        self.status_label.config(text=f"Status: {status}")

    def update_wallet_counter(self, value):
        self.wallet_counter_label.config(text=f"Wallets Found with Balance: {value}")

    def log_message(self, message, tag):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)  # Autoscroll to the end
        self.log_text.config(state='disabled')

    def auto_export_results(self):
        self.export_results()
        self.stop_process()

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open('generated_address_with_balance.txt', 'r') as infile, open(file_path, 'w', newline='') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(["Address", "Private Key/Seed Phrase", "Balance"])
                for line in infile:
                    writer.writerow(line.strip().split(", "))
            logger.info(f"Results exported to {file_path}")

    def show_about(self):
        messagebox.showinfo("About", "Active Wallet Searcher v1.0\nDeveloped by [Your Name]")

if __name__ == "__main__":
    root = tk.Tk()
    app = BitcoinGUI(root)
    root.mainloop()
