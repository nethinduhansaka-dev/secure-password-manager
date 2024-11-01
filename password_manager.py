import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import base64
import hashlib
import os
from cryptography.fernet import Fernet
from ttkthemes import ThemedTk

class PasswordManagerGUI:
    def __init__(self):
        self.root = ThemedTk(theme="arc")
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        self.key = None
        self.current_user = None
        
        self.main_container = ttk.Frame(self.root, padding="20")
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Initialize database and check if first run
        self.init_db()
        if self.is_first_run():
            self.show_signup_screen()
        else:
            self.show_login_screen()

    def is_first_run(self):
        conn = sqlite3.connect("passwords.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]
        conn.close()
        return count == 0

    def init_db(self):
        conn = sqlite3.connect("passwords.db")
        c = conn.cursor()
        
        # Drop existing tables if they exist to avoid schema conflicts
        c.execute("DROP TABLE IF EXISTS passwords")
        c.execute("DROP TABLE IF EXISTS users")
        
        # Create users table first (since it's referenced by passwords table)
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        """)
        
        # Create passwords table with proper user_id foreign key
        c.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
                ON DELETE CASCADE
                ON UPDATE CASCADE
        )
        """)
        
        conn.commit()
        conn.close()

    def generate_salt(self):
        return os.urandom(32)

    def hash_password(self, password, salt):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000
        ).hex()

    def show_signup_screen(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

        signup_frame = ttk.Frame(self.main_container, padding="20")
        signup_frame.pack(expand=True)
        
        # Title
        ttk.Label(signup_frame, text="Create Account",
                font=('Helvetica', 24, 'bold')).pack(pady=20)
        
        # Username
        ttk.Label(signup_frame, text="Username:").pack(anchor=tk.W)
        username_entry = ttk.Entry(signup_frame)
        username_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Password with visibility toggle
        ttk.Label(signup_frame, text="Password:").pack(anchor=tk.W)
        password_frame = ttk.Frame(signup_frame)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        password_entry = ttk.Entry(password_frame, show="*")
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        password_toggle = ttk.Button(password_frame, text="👁", width=3,
                                command=lambda: self.toggle_password_visibility(password_entry))
        password_toggle.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Confirm Password with visibility toggle
        ttk.Label(signup_frame, text="Confirm Password:").pack(anchor=tk.W)
        confirm_frame = ttk.Frame(signup_frame)
        confirm_frame.pack(fill=tk.X, pady=(0, 10))
        
        confirm_password_entry = ttk.Entry(confirm_frame, show="*")
        confirm_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        confirm_toggle = ttk.Button(confirm_frame, text="👁", width=3,
                                command=lambda: self.toggle_password_visibility(confirm_password_entry))
        confirm_toggle.pack(side=tk.RIGHT, padx=(5, 0))

        def handle_signup():
            username = username_entry.get()
            password = password_entry.get()
            confirm_password = confirm_password_entry.get()
            
            if not all([username, password, confirm_password]):
                messagebox.showerror("Error", "All fields are required!")
                return
            
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return
            
            salt = self.generate_salt()
            hashed_password = self.hash_password(password, salt)
            
            try:
                conn = sqlite3.connect("passwords.db")
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
                         (username, hashed_password, salt.hex()))
                conn.commit()
                conn.close()
                messagebox.showinfo("Success", "Account created successfully!")
                self.show_login_screen()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create account: {str(e)}")
        
        # Create Account button
        ttk.Button(signup_frame, text="Create Account",
                  command=handle_signup).pack(pady=20)

    def toggle_password_visibility(self, entry):
        if entry.cget('show') == '*':
            entry.configure(show='')
        else:
            entry.configure(show='*')

    def show_login_screen(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()
        
        login_frame = ttk.Frame(self.main_container, padding="20")
        login_frame.pack(expand=True)
        
        ttk.Label(login_frame, text="Password Manager",
                 font=('Helvetica', 24, 'bold')).pack(pady=20)
        
        # Username
        ttk.Label(login_frame, text="Username:").pack(anchor=tk.W)
        username_entry = ttk.Entry(login_frame)
        username_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Password
        ttk.Label(login_frame, text="Password:").pack(anchor=tk.W)
        password_entry = ttk.Entry(login_frame, show="*")
        password_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Login button
        ttk.Button(login_frame, text="Login",
                  command=lambda: self.login(username_entry.get(),
                                           password_entry.get())).pack(pady=10)
        
        # Reset password button
        ttk.Button(login_frame, text="Reset Password",
                  command=self.show_reset_password).pack(pady=5)

    def show_reset_password(self):
        reset_window = tk.Toplevel(self.root)
        reset_window.title("Reset Password")
        reset_window.geometry("400x300")
        
        frame = ttk.Frame(reset_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Username:").pack(anchor=tk.W)
        username_entry = ttk.Entry(frame)
        username_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="Current Password:").pack(anchor=tk.W)
        current_password_entry = ttk.Entry(frame, show="*")
        current_password_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="New Password:").pack(anchor=tk.W)
        new_password_entry = ttk.Entry(frame, show="*")
        new_password_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="Confirm New Password:").pack(anchor=tk.W)
        confirm_password_entry = ttk.Entry(frame, show="*")
        confirm_password_entry.pack(fill=tk.X, pady=(0, 10))
        
        def handle_reset():
            username = username_entry.get()
            current_password = current_password_entry.get()
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            
            if not all([username, current_password, new_password, confirm_password]):
                messagebox.showerror("Error", "All fields are required!")
                return
            
            if new_password != confirm_password:
                messagebox.showerror("Error", "New passwords do not match!")
                return
            
            try:
                conn = sqlite3.connect("passwords.db")
                c = conn.cursor()
                c.execute("SELECT password, salt FROM users WHERE username=?",
                         (username,))
                result = c.fetchone()
                
                if not result:
                    messagebox.showerror("Error", "Username not found!")
                    return
                
                stored_password, stored_salt = result
                stored_salt = bytes.fromhex(stored_salt)
                
                if self.hash_password(current_password, stored_salt) != stored_password:
                    messagebox.showerror("Error", "Current password is incorrect!")
                    return
                
                # Generate new salt and hash for the new password
                new_salt = self.generate_salt()
                new_hash = self.hash_password(new_password, new_salt)
                
                c.execute("UPDATE users SET password=?, salt=? WHERE username=?",
                         (new_hash, new_salt.hex(), username))
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "Password reset successfully!")
                reset_window.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset password: {str(e)}")
        
        ttk.Button(frame, text="Reset Password",
                  command=handle_reset).pack(pady=20)

    def login(self, username, password):
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required!")
            return
        
        try:
            conn = sqlite3.connect("passwords.db")
            c = conn.cursor()
            c.execute("SELECT id, password, salt FROM users WHERE username=?",
                     (username,))
            result = c.fetchone()
            
            if not result:
                messagebox.showerror("Error", "Invalid username or password!")
                return
            
            user_id, stored_password, stored_salt = result
            stored_salt = bytes.fromhex(stored_salt)
            
            if self.hash_password(password, stored_salt) == stored_password:
                self.current_user = user_id
                self.key = self.derive_key(password)
                self.show_main_screen()
            else:
                messagebox.showerror("Error", "Invalid username or password!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")

    def derive_key(self, master_password):
        salt = b"random_salt_here"  # In production, use a secure random salt
        kdf = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
        return base64.urlsafe_b64encode(kdf[:32])

    def encrypt_message(self, message):
        cipher = Fernet(self.key)
        return cipher.encrypt(message.encode())

    def decrypt_message(self, encrypted_message):
        cipher = Fernet(self.key)
        return cipher.decrypt(encrypted_message).decode()

    def show_main_screen(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        left_panel = ttk.Frame(self.main_container, padding="10")
        left_panel.pack(side=tk.LEFT, fill=tk.Y)
        
        ttk.Button(left_panel, text="Add Password",
                  command=self.show_add_password).pack(pady=5, fill=tk.X)
        ttk.Button(left_panel, text="Refresh List",
                  command=self.refresh_password_list).pack(pady=5, fill=tk.X)
        ttk.Button(left_panel, text="Logout",
                  command=self.show_login_screen).pack(pady=5, fill=tk.X)
        
        right_panel = ttk.Frame(self.main_container, padding="10")
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        search_frame = ttk.Frame(right_panel)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.search_entry.bind('<KeyRelease>', self.search_passwords)
        
        columns = ('Website', 'Username', 'Actions')
        self.tree = ttk.Treeview(right_panel, columns=columns, show='headings')
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(right_panel, orient=tk.VERTICAL,
                                command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.refresh_password_list()
        
    def search_passwords(self, event=None):
        search_term = self.search_entry.get().lower()
        for item in self.tree.get_children():
            website = self.tree.item(item)['values'][0].lower()
            username = self.tree.item(item)['values'][1].lower()
            if search_term in website or search_term in username:
                self.tree.reattach(item, '', 'end')
            else:
                self.tree.detach(item)

    def show_add_password(self):
        popup = tk.Toplevel(self.root)
        popup.title("Add Password")
        popup.geometry("400x300")
        
        form_frame = ttk.Frame(popup, padding="20")
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="Website:").pack(anchor=tk.W)
        website_entry = ttk.Entry(form_frame)
        website_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(form_frame, text="Username:").pack(anchor=tk.W)
        username_entry = ttk.Entry(form_frame)
        username_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(form_frame, text="Password:").pack(anchor=tk.W)
        password_frame = ttk.Frame(form_frame)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        password_entry = ttk.Entry(password_frame, show="*")
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        password_toggle = ttk.Button(password_frame, text="👁", width=3,
                                   command=lambda: self.toggle_password_visibility(password_entry))
        password_toggle.pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Button(form_frame, text="Save",
                  command=lambda: self.save_password(
                      website_entry.get(),
                      username_entry.get(),
                      password_entry.get(),
                      popup
                  )).pack(pady=20)

    def save_password(self, website, username, password, popup):
        if not all([website, username, password]):
            messagebox.showerror("Error", "All fields are required!")
            return
            
        try:
            conn = sqlite3.connect("passwords.db")
            c = conn.cursor()
            encrypted_password = self.encrypt_message(password)
            c.execute("""
                INSERT INTO passwords (user_id, website, username, password)
                VALUES (?, ?, ?, ?)
            """, (self.current_user, website, username, encrypted_password))
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Success", "Password saved successfully!")
            popup.destroy()
            self.refresh_password_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")
            
    def refresh_password_list(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Load passwords from database
        conn = sqlite3.connect("passwords.db")
        c = conn.cursor()
        c.execute("""
            SELECT id, website, username, password 
            FROM passwords 
            WHERE user_id=?
        """, (self.current_user,))
        passwords = c.fetchall()
        conn.close()
        
        # Add to treeview
        for pwd in passwords:
            id_, website, username, encrypted_password = pwd
            self.tree.insert('', tk.END, values=(
                website,
                username,
                "View | Delete"
            ), tags=(str(id_),))
            
        # Bind click event
        self.tree.bind('<ButtonRelease-1>', self.handle_click)
        
    def handle_click(self, event):
        if not self.tree.selection():
            return
            
        item = self.tree.selection()[0]
        col = self.tree.identify_column(event.x)
        
        # If clicked on Actions column
        if col == '#3':  # Actions column
            values = self.tree.item(item)['values']
            website = values[0]
            item_id = self.tree.item(item)['tags'][0]
            
            # Get coordinates for popup menu
            x, y = event.x_root, event.y_root
            
            # Create popup menu
            popup = tk.Menu(self.root, tearoff=0)
            popup.add_command(label="View Password",
                            command=lambda: self.view_password(item_id))
            popup.add_command(label="Delete",
                            command=lambda: self.delete_password(item_id, website))
            
            # Display popup menu
            popup.tk_popup(x, y)
            
    def view_password(self, item_id):
        conn = sqlite3.connect("passwords.db")
        c = conn.cursor()
        c.execute("""
            SELECT website, username, password 
            FROM passwords 
            WHERE id=? AND user_id=?
        """, (item_id, self.current_user))
        result = c.fetchone()
        conn.close()
        
        if result:
            website, username, encrypted_password = result
            try:
                password = self.decrypt_message(encrypted_password)
                # Create a custom dialog for displaying the password
                dialog = tk.Toplevel(self.root)
                dialog.title("Password Details")
                dialog.geometry("300x200")
                
                frame = ttk.Frame(dialog, padding="20")
                frame.pack(fill=tk.BOTH, expand=True)
                
                ttk.Label(frame, text=f"Website: {website}").pack(anchor=tk.W)
                ttk.Label(frame, text=f"Username: {username}").pack(anchor=tk.W)
                
                # Password frame with show/hide functionality
                pwd_frame = ttk.Frame(frame)
                pwd_frame.pack(fill=tk.X, pady=5)
                
                password_var = tk.StringVar(value="*" * len(password))
                show_password = tk.BooleanVar(value=False)
                
                pwd_label = ttk.Label(pwd_frame, text="Password: ")
                pwd_label.pack(side=tk.LEFT)
                
                pwd_display = ttk.Label(pwd_frame, textvariable=password_var)
                pwd_display.pack(side=tk.LEFT)
                
                def toggle_password():
                    if show_password.get():
                        password_var.set(password)
                    else:
                        password_var.set("*" * len(password))
                
                ttk.Checkbutton(frame, text="Show Password",
                               variable=show_password,
                               command=toggle_password).pack(pady=10)
                
                ttk.Button(frame, text="Close",
                          command=dialog.destroy).pack(pady=10)
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
        
    def delete_password(self, item_id, website):
        if messagebox.askyesno("Confirm Delete",
                              f"Delete password for {website}?"):
            try:
                conn = sqlite3.connect("passwords.db")
                c = conn.cursor()
                c.execute("""
                    DELETE FROM passwords 
                    WHERE id=? AND user_id=?
                """, (item_id, self.current_user))
                conn.commit()
                conn.close()
                self.refresh_password_list()
                messagebox.showinfo("Success", "Password deleted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete password: {str(e)}")
            
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordManagerGUI()
    app.run()