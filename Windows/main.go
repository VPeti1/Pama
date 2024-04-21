package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/howeyc/gopass"
)

// Set the path for the password file
var passwordFile = "C:\\pama.db"

// Function to get the machine ID and generate a valid AES key
func getIDForEncryption() (string, error) {
	// Get the MAC address of the first non-loopback network interface
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, intf := range interfaces {
		if intf.Flags&net.FlagLoopback == 0 && intf.HardwareAddr != nil {
			return strings.Replace(intf.HardwareAddr.String(), ":", "", -1), nil
		}
	}

	return "", fmt.Errorf("MAC address not found")
}

// Function to generate a key from the machine ID
func generateKey(machineID string) []byte {
	hash := sha256.Sum256([]byte(machineID))
	return hash[:]
}

func main() {
	// Check if the password file exists; if not, create it
	if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
		_, err := os.Create(passwordFile)
		if err != nil {
			fmt.Println("Error creating password file:", err)
			return
		}
	}

	// Check command-line arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./pama <add | remove | list>")
		return
	}

	command := os.Args[1]

	switch command {
	case "add":
		addPassword()
	case "list":
		listPasswords()
	case "remove":
		removeFile()
	default:
		fmt.Println("Invalid command. Usage: ./password-manager <add | remove | list>")
	}
}

// Function to remove the password file
func removeFile() {
	err := os.Remove(passwordFile)
	if err != nil {
		fmt.Println("Error removing password file:", err)
		return
	}
	fmt.Println("Password file removed successfully!")
}

// Function to add a new password
func addPassword() {
	// Prompt for the service name
	fmt.Print("Enter the service name: ")
	var serviceName string
	fmt.Scanln(&serviceName)

	// Prompt for the password (obscured)
	fmt.Print("Enter the password: ")
	password, err := gopass.GetPasswdMasked()
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}

	// Encrypt the password
	encryptedPassword, err := encrypt([]byte(password))
	if err != nil {
		fmt.Println("Error encrypting password:", err)
		return
	}

	// Open the password file for appending
	file, err := os.OpenFile(passwordFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening password file:", err)
		return
	}
	defer file.Close()

	// Write the new password to the file
	_, err = file.WriteString(fmt.Sprintf("%s:%s\n", serviceName, encryptedPassword))
	if err != nil {
		fmt.Println("Error writing to password file:", err)
		return
	}

	fmt.Println("Password saved successfully!")
}

// Function to list existing passwords
func listPasswords() {
	// Open the password file for reading
	file, err := os.Open(passwordFile)
	if err != nil {
		fmt.Println("Error opening password file:", err)
		return
	}
	defer file.Close()

	// Read passwords from the file and print them
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			service, encryptedPassword := parts[0], parts[1]

			// Decrypt the password
			decryptedPassword, err := decrypt(encryptedPassword)
			if err != nil {
				fmt.Println("Error decrypting password:", err)
				return
			}

			fmt.Printf("Service: %s, Password: %s\n", service, decryptedPassword)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading password file:", err)
		return
	}
}

// Encrypt function
func encrypt(data []byte) (string, error) {
	machineID, err := getIDForEncryption()
	if err != nil {
		return "", err
	}

	key := generateKey(machineID)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt function
func decrypt(encrypted string) (string, error) {
	machineID, err := getIDForEncryption()
	if err != nil {
		return "", err
	}

	key := generateKey(machineID)

	// Decode the base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
