import os
import hashlib
import csv

def get_sha256(filepath):

    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def main():
    malware_dir = os.path.join("data", "malware")
    output_csv = os.path.join("output", "malware_submission_list.csv")
    
    results = []
    
    print("[*] Scanning malware directories and calculating hashes...")
    
    # Walk through the malware directory and its subfolders
    if os.path.exists(malware_dir):
        for root, dirs, files in os.walk(malware_dir):
            for file in files:
                file_path = os.path.join(root, file)
                
                # The folder name is the malware class (e.g., trojan, ransomware)
                family_label = os.path.basename(root)
                
                # Calculate the hash
                file_hash = get_sha256(file_path)
                
                # Append to our list
                results.append({
                    "Filename": file,
                    "SHA-256 Hash": file_hash,
                    "Malware Class": family_label.capitalize()
                })
    else:
        print(f"[-] Directory not found: {malware_dir}")
        return
                
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    # Write everything to a CSV
    print(f"[*] Formatting into CSV document...")
    with open(output_csv, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["Filename", "SHA-256 Hash", "Malware Class"])
        writer.writeheader()
        writer.writerows(results)
        
    print(f"[+] Complete! Successfully exported {len(results)} samples to {output_csv}")
    print("[!] You can open this CSV in Excel and copy/paste it directly into your Word report.")

if __name__ == "__main__":
    main()