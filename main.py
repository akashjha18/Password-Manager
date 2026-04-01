import json
import os
import base64

FILE = "data.json"

# Load data
def load_data():
    if not os.path.exists(FILE):
        return []
    try:
        with open(FILE, "r") as f:
            return json.load(f)
    except:
        return []

# Save data
def save_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=4)

# Encode password
def encode_password(password):
    return base64.b64encode(password.encode()).decode()

# Decode password
def decode_password(encoded):
    return base64.b64decode(encoded.encode()).decode()

# Add credential
def add_password():
    site = input("Enter website: ")
    user = input("Enter username: ")
    pwd = input("Enter password: ")

    data = load_data()
    encoded_pwd = encode_password(pwd)

    data.append({
        "site": site,
        "username": user,
        "password": encoded_pwd
    })

    save_data(data)
    print("✅ Saved successfully!")

# View credentials
def view_passwords():
    data = load_data()

    if not data:
        print("No data found!")
        return

    for entry in data:
        print(f"\n🌐 Site: {entry['site']}")
        print(f"👤 Username: {entry['username']}")
        print(f"🔑 Password: {decode_password(entry['password'])}")

# Main menu
def main():
    while True:
        print("\n1. Add Password")
        print("2. View Passwords")
        print("3. Exit")

        choice = input("Choose: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            view_passwords()
        elif choice == "3":
            break
        else:
            print("Invalid option!")

main()