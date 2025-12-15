import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.fernet import Fernet
import webbrowser

class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Login")
        self.master.geometry("400x350")
        self.master.configure(bg="#4a536b")

        style = ttk.Style()
        style.configure("TLabel", background="#4a536b", foreground="#ffffff", font=("Berlin Sans Fb", 12))
        style.configure("TEntry", font=("Berlin Sans Fb", 12))
        style.configure("TButton", font=("Berlin Sans Fb", 12))

        self.label_username = ttk.Label(master, text="Username: Talha", anchor="center")
        self.label_username.pack(pady=10)

        self.label_password = ttk.Label(master, text="Password:", anchor="center")
        self.label_password.pack(pady=10)

        self.password_entry = ttk.Entry(master, show="*")
        self.password_entry.pack(pady=5, padx=20, ipadx=50, ipady=5)

        self.login_button = ttk.Button(master, text="Login", command=self.login)
        self.login_button.pack(pady=10, ipadx=20, ipady=5)
        self.login_button.bind("<Enter>", lambda event: self.on_enter(event, self.login_button))
        self.login_button.bind("<Leave>", lambda event: self.on_leave(event, self.login_button))

        self.forget_button = ttk.Button(master, text="Forget Password", command=self.forget_password)
        self.forget_button.pack(pady=5, ipadx=5, ipady=5)
        self.forget_button.bind("<Enter>", lambda event: self.on_enter(event, self.forget_button))
        self.forget_button.bind("<Leave>", lambda event: self.on_leave(event, self.forget_button))

        self.about_button = ttk.Button(master, text="About Developer", command=self.about_developer)
        self.about_button.pack(pady=10, ipadx=5, ipady=5)
        self.about_button.bind("<Enter>", lambda event: self.on_enter(event, self.about_button))
        self.about_button.bind("<Leave>", lambda event: self.on_leave(event, self.about_button))

    def on_enter(self, event, widget):
        widget.config(background="#5f6c7b")
        widget.config(relief=tk.RAISED)

    def on_leave(self, event, widget):
        widget.config(background="#4a536b")
        widget.config(relief=tk.FLAT)

    def login(self):
        password = self.password_entry.get()
        if password == "0000":
            self.master.destroy()
            app_window = tk.Tk()
            app_window.title("Talha's Cypher Software")
            app_window.geometry("800x600")
            app = EncryptionApp(app_window)
            app_window.mainloop()
        else:
            messagebox.showerror("Error", "Invalid password")

    def forget_password(self):
        messagebox.showinfo("Developer ID", "Contacting @Talha_Ghaffar_Ch on Linkedin...")
        self.master.after(2, self.redirect_to_instagram)

    def redirect_to_instagram(self):
        webbrowser.open("https://www.linkedin.com/in/talha-ghaffar/")

    def about_developer(self):
        messagebox.showinfo("About Developer",
                            "Developer: Talha Ghaffar\n"
                            "University: UMT Lahore\n"
                            "Department: BS Computer Science\n"
                            "Contact: +92 312 0000000")

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.configure(bg="#4a536b")
        self.master.title("Talha's Cypher Software")

        style = ttk.Style()
        style.configure("TLabel", background="#4a536b", foreground="#ffffff", font=("Berlin Sans Fb", 12))
        style.configure("TEntry", font=("Berlin Sans Fb", 12))
        style.configure("TButton", font=("Berlin Sans Fb", 12))

        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

        self.label = ttk.Label(master, text="Enter Text or Choose File:", anchor="center", font=("Berlin Sans Fb", 14, "bold"), foreground="#ffffff")
        self.label.pack(pady=20)

        self.text_entry = tk.Text(master, wrap=tk.WORD, height=10, width=60, font=("Arial", 12))
        self.text_entry.pack(pady=10, padx=20)
        
        self.browse_button = ttk.Button(master, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=10, ipadx=20, ipady=5)
        self.browse_button.bind("<Enter>", lambda event: self.on_enter(event, self.browse_button))
        self.browse_button.bind("<Leave>", lambda event: self.on_leave(event, self.browse_button))

        self.encrypt_button = ttk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=10, ipadx=30, ipady=5)
        self.encrypt_button.bind("<Enter>", lambda event: self.on_enter(event, self.encrypt_button))
        self.encrypt_button.bind("<Leave>", lambda event: self.on_leave(event, self.encrypt_button))

        self.decrypt_button = ttk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=10, ipadx=30, ipady=5)
        self.decrypt_button.bind("<Enter>", lambda event: self.on_enter(event, self.decrypt_button))
        self.decrypt_button.bind("<Leave>", lambda event: self.on_leave(event, self.decrypt_button))

    def on_enter(self, event, widget):
        widget.config(background="#5f6c7b")
        widget.config(relief=tk.RAISED)

    def on_leave(self, event, widget):
        widget.config(background="#4a536b")
        widget.config(relief=tk.FLAT)

    def browse_file(self):
        filename = filedialog.askopenfilename(title="Choose a file")
        if filename:
            with open(filename, "r") as file:
                self.text_entry.delete(1.0, tk.END)
                self.text_entry.insert(tk.END, file.read())

    def encrypt(self):
        plaintext = self.text_entry.get(1.0, tk.END).encode()
        encrypted_data = self.cipher.encrypt(plaintext)
        filename = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")], title="Save Encrypted File")
        if filename:
            with open(filename, "wb") as file:
                file.write(encrypted_data)
                messagebox.showinfo("Encryption Successful", f"Encrypted data saved to {filename}")

    def decrypt(self):
        try:
            encrypted_data = self.text_entry.get(1.0, tk.END).encode()
            decrypted_data = self.cipher.decrypt(encrypted_data).decode()
            decrypted_window = tk.Toplevel(self.master)
            decrypted_window.title("Decrypted Text")
            decrypted_window.geometry("600x400")
            decrypted_text = tk.Text(decrypted_window, wrap=tk.WORD, height=15, width=80, font=("Arial", 12))
            decrypted_text.pack(pady=20, padx=20)
            decrypted_text.insert(tk.END, decrypted_data)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Invalid or corrupted data.")

def main():
    login_window = tk.Tk()
    login_window.title("Talha's Cypher Software - Login")
    login_window.geometry("400x350")
    login_window.configure(bg="#4a536b")
    app = LoginWindow(login_window)
    login_window.mainloop()

if __name__ == "__main__":
    main()
