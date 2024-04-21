# PAssword MAnager (Pama)
A simple password manager written in Go

# Overview

This is a simple password manager tool designed to securely store and manage passwords for various services. It utilizes AES encryption for securing the passwords stored in a file on the system.
Features

    AES Encryption: Uses Advanced Encryption Standard (AES) for strong encryption of passwords.
    Service-Based Password Storage: Allows users to store passwords for different services.
    Secure Storage: Passwords are stored encrypted in a file on the system.
    Command-Line Interface: Provides a simple command-line interface for adding, listing, and removing passwords.

# Usage

Adding a Password

To add a password for a service, run the following command:

pama add

Follow the prompts to enter the service name and password. The password will be securely encrypted and stored.
Listing Passwords

To list all stored passwords, run the following command:

pama list

This will display the service names and their corresponding decrypted passwords.
Removing Password File

To remove the password file and delete all stored passwords, run the following command:

pama remove

This will remove the password file from the system.
Encryption Key

# Disclaimer

The encryption key is generated based on the machine's ID to ensure security. It's essential to keep the password file and the machine secure to prevent unauthorized access to the stored passwords.