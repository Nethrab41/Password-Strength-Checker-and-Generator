import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import tempfile
import webbrowser
import os
import zxcvbn
import requests
import re
import hashlib
import random
import string
import pyperclip
root = tk.Tk()
root.title('Password Strength Checker')

try:
    image = Image.open("logo.png")
    tk_image = ImageTk.PhotoImage(image)
    logo_label = tk.Label(root, image=tk_image)
    logo_label.pack(pady=10)
except FileNotFoundError:
    messagebox.showerror("Error", "logo.png not found.")
    tk_image = None
    logo_label = None

win_width = 600
win_height = 500
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width // 2) - (win_width // 2)
y = (screen_height // 2) - (win_height // 2)
root.geometry(f'{win_width}x{win_height}+{x}+{y}')
root.configure(bg='#f0f0f0')
button_frame = tk.Frame(root, bg='#f0f0f0')
button_frame.pack(expand=True, fill='both', padx=20, pady=20)
#Project Info
def project_info():
    html_code = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Project Information</title>
        <style>
            .small-column { width: 30%; }
            .large-column { width: 70%; }
            .small { width: 30%; }
            .medium { width: 30%; }
            .large { width: 40%; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid black; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            body { font-family: sans-serif; }
        </style>
    </head>
    <body>
    <h1> Project Information </h1>
    <p> This is a Python application built with the **Tkinter** library that acts as a Password Strength Checker and Generator. It's designed to help users create and evaluate strong, secure passwords to prevent common cyberattacks like brute-force attempts and dictionary attacks.</p>

<p>
The program performs three main tasks:<br></br>

1.  Password Strength Check: When you type a password into the input box and click "Check Password," the application evaluates its strength. It checks for a minimum length of 16 characters and the inclusion of uppercase letters, lowercase letters, numbers, and special characters. It also uses the `zxcvbn` library to provide more detailed feedback on the password's quality and suggestions for improvement.<br></br>
2.  Password Breach Check: It checks if the entered password has been compromised in a known data breach. It does this by using the Have I Been Pwned? API. The program doesn't send your full password; instead, it sends the first five characters of a SHA-1 hash of the password to the API, which returns a list of hashes that start with the same five characters. The program then checks if the full hash of your password is in that list, ensuring your actual password is never exposed.<br></br>
3.  Password Generation: The application can generate random, strong passwords of 16, 24, or 32 characters with the click of a button. These passwords include a mix of letters, numbers, and special characters.<br></br>
4.  Clipboard Functionality: Users can easily copy the generated or entered password to their clipboard for use elsewhere by clicking the "Copy to Clipboard" button.<br></br>
 </p>
    
    </body>
    </html>
    '''
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as temp_file:
        temp_file.write(html_code.encode('utf-8'))
        temp_file_path = temp_file.name
    webbrowser.open(f'file://{temp_file_path}')

def is_password_breached(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    p, s = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{p}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for h in hashes:
                if h.split(':')[0] == s:
                    return True
    except requests.exceptions.RequestException as e:
        messagebox.showerror("API Error", f"Could not connect to the API: {e}")
    return False

def check_password():
    password = input_text.get()
    
    if not password or password == 'Enter your password here...':
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    password = input_text.get()
    if not password or password == 'Enter your password here...':
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    # Basic password complexity rules
    if len(password) < 8:
        messagebox.showwarning("Weak Password", "Password must be at least 16 characters long.")
    elif not re.search(r"[A-Z]", password):
        messagebox.showwarning("Weak Password", "Password must contain at least one uppercase letter.")
    elif not re.search(r"[a-z]", password):
        messagebox.showwarning("Weak Password", "Password must contain at least one lowercase letter.")
    elif not re.search(r"[0-9]", password):
        messagebox.showwarning("Weak Password", "Password must contain at least one digit.")
    elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        messagebox.showwarning("Weak Password", "Password must contain at least one special character.")
    result = zxcvbn.zxcvbn(password)
    suggestions = result['feedback']['suggestions']
    if is_password_breached(password):
        messagebox.showwarning("Password Breached","Please choose a different password.")
    else:
        messagebox.showinfo("Strong Password", "Your password is strong and secure!")

    if suggestions:
        messagebox.showinfo("Suggestions", "\n".join(suggestions))

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    input_text.delete(0, tk.END)
    input_text.insert(0, password)
    input_text.config(validate='key', validatecommand=(root.register(lambda P, L=length: len(P) <= L), '%P'))
    messagebox.showinfo("Password Generated", f"A {length}-character password has been generated.")

def copy_to_clipboard():
    password = input_text.get()
    if password and password != 'Enter your password here...':
        try:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        except pyperclip.PyperclipException:
            messagebox.showerror("Copy Error")
    else:
        messagebox.showwarning("No Password to copy")



info_button = tk.Button(root, text='Project Information', command=project_info, bg="#4C82AF", fg='white', font=('Arial', 12), width=20, height=2)
info_button.pack(pady=10)


input_text = tk.Entry(button_frame, width=50, font=('Arial', 14), bg='#ffffff', fg='#333333')
input_text.insert(0, 'Enter your password here...')
input_text.bind("<FocusIn>", lambda event: input_text.delete(0, tk.END) if input_text.get() == 'Enter your password here...' else None)
input_text.pack(pady=10, padx=50)

check_button = tk.Button(button_frame, text='Check Password', command=check_password, bg="#4C82AF", fg='white', font=('Arial', 12), width=20, height=2)
check_button.pack(pady=10)


generate_frame = tk.Frame(button_frame, bg='#f0f0f0')
generate_frame.pack(pady=10)

tk.Label(generate_frame, text="Generate Passwords:", bg='#f0f0f0', font=('Arial', 12)).pack(pady=5)


btn_16 = tk.Button(generate_frame, text="16 Characters", command=lambda: generate_password(16), bg="#4C82AF", fg='white', font=('Arial', 10))
btn_16.pack(side=tk.LEFT, padx=5)

btn_24 = tk.Button(generate_frame, text="24 Characters", command=lambda: generate_password(24), bg="#4C82AF", fg='white', font=('Arial', 10))
btn_24.pack(side=tk.LEFT, padx=5)

btn_32 = tk.Button(generate_frame, text="32 Characters", command=lambda: generate_password(32), bg="#4C82AF", fg='white', font=('Arial', 10))
btn_32.pack(side=tk.LEFT, padx=5)

copy_button = tk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard, bg="#4CAF50", fg='white', font=('Arial', 12))
copy_button.pack(pady=5)

root.mainloop()