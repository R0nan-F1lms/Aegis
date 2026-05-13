import pefile
import os
import csv
import math
import hashlib
import requests
import time
import json

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
HEADERS = { "Auth-Key": "" }

# Calculates the SHA-256 hash of a file
def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Queries the MalwareBazaar API for family names and extra data
def query_malwarebazaar(file_hash):
    data = {'query': 'get_info', 'hash': file_hash}
    try:
        response = requests.post(MB_API_URL, data=data, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            json_response = response.json()
            if json_response.get("query_status") == "ok":
                file_info = json_response["data"][0]
                return {
                    "Family": file_info.get("signature", "Unknown_Family"),
                    "MB_File_Size": file_info.get("file_size", 0)
                }
            elif json_response.get("query_status") == "hash_not_found":
                return {"Family": "Unknown_Not_In_DB"}
        return {"Family": "API_Error"}
    except Exception as e:
        print(f"[-] Connection error for {file_hash}: {e}")
        return {"Family": "Connection_Error"}

# Define standard section names to detect anomalies
STANDARD_NAMES = ['.text', '.data', '.rdata', '.idata', '.edata', '.pdata', '.rsrc', '.bss', '.reloc']

# Calculates the Shannon entropy of a byte sequence
def calculate_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    entropy = 0
    length = len(data_bytes)
    # Count frequency of each byte
    byte_counts = [0] * 256
    for byte in data_bytes:
        byte_counts[byte] += 1
        
    for count in byte_counts:
        if count > 0:
            probability = float(count) / length
            entropy -= probability * math.log(probability, 2)
    return entropy

# Checks if a section name is standard, stripping null bytes.
def is_section_name_standard(name):
    clean_name = name.decode('utf-8', 'ignore').strip('\x00')
    return clean_name.lower() in STANDARD_NAMES

def detect_packing(entropy, weird_name_count):
    if entropy > 7.0 or weird_name_count > 0:
        return 1
    return 0

# Extracts structural and import features from a single PE file.
def extract_features_from_pe(file_path, class_label):
    features = {}
    
    try:
        pe = pefile.PE(file_path)
        
        # 1. Base Class Label
        features['Malware Class Name'] = class_label
        
        # 2. Structural Features
        features['Number_of_Sections'] = len(pe.sections)
        
        mismatch_count = 0
        weird_name_count = 0
        
        for section in pe.sections:
            # Check for size mismatches (Virtual Size vs Raw Size)

            virtual_size = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            # If the difference is greater than 1024 bytes, flag it as a mismatch
            if abs(virtual_size - raw_size) > 1024:
                mismatch_count += 1
            # Check for strange section names (packers like UPX rename these)
            if not is_section_name_standard(section.Name):
                weird_name_count += 1
                
        features['Size_Mismatch_Count'] = mismatch_count
        features['Weird_Section_Names'] = weird_name_count
        
        # 3. Payload Entropy (Reading the raw file bytes for overall entropy)
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
            payload_entropy = calculate_entropy(file_bytes)
            features['Payload_Entropy'] = round(payload_entropy, 4)
            
        # 4. Packer Detection
        features['Is_Packed'] = detect_packing(payload_entropy, weird_name_count)
        
        # 5. API & DLL Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                # Add the DLL itself
                dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                features[dll_name] = 1
                
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', 'ignore')
                        features[api_name] = 1
                        
        return features

    except pefile.PEFormatError:
        print(f"[!] PEFormatError: Skipping corrupted or invalid PE file: {file_path}")
        return None
    except Exception as e:
        print(f"[!] Error processing {file_path}: {e}")
        return None

def main():
    # Define paths relative to where the script is executed
    malware_dir = os.path.join("data", "malware")
    benign_dir = os.path.join("data", "benign")
    output_csv = os.path.join("output", "features.csv")
    hash_output_json = os.path.join("output", "malware_hashes.json") # NEW: Hash export path
    
    all_extracted_data = []
    exported_hashes = {} # NEW: Dictionary to store our hashes
    
    print("[*] Starting extraction on Malware dataset...")
    if os.path.exists(malware_dir):
        for root, dirs, files in os.walk(malware_dir):
            for file in files:
                file_path = os.path.join(root, file)
                class_label = os.path.basename(root) 
                
                # Hash calculation
                file_hash = get_sha256(file_path)
                exported_hashes[file] = file_hash # NEW: Save the hash to our dictionary
                
                print(f"  -> Querying API for {file}...")
                api_data = query_malwarebazaar(file_hash)
                
                fetched_family = api_data.get("Family")
                
                if fetched_family and fetched_family not in ["Unknown_Not_In_DB", "API_Error", "Connection_Error", "Unknown_Family", None]:
                    class_label = fetched_family
                elif class_label == 'malware': 
                    class_label = 'Malware_Generic'
                    
                print(f"  -> Processing: {file} ({class_label})")
                features = extract_features_from_pe(file_path, class_label)
                if features:
                    features['MB_File_Size'] = api_data.get("MB_File_Size", 0)
                    all_extracted_data.append(features)
                    
                time.sleep(1)
    else:
        print(f"[-] Directory not found: {malware_dir}. Please create it and add samples.")

    print("\n[*] Starting extraction on Benign dataset...")
    if os.path.exists(benign_dir):
        for file in os.listdir(benign_dir):
            file_path = os.path.join(benign_dir, file)
            if os.path.isfile(file_path):
                print(f"  -> Processing: {file} (Benign)")
                features = extract_features_from_pe(file_path, "Benign")
                if features:
                    all_extracted_data.append(features)
    else:
         print(f"[-] Directory not found: {benign_dir}. Please create it and add samples.")

    print("\n[*] Structuring Feature Matrix...")
    if not all_extracted_data:
        print("[-] No data extracted. Exiting.")
        return

    all_columns = set()
    for data_row in all_extracted_data:
        all_columns.update(data_row.keys())

    all_columns.discard('Malware Class Name')
    sorted_columns = sorted(list(all_columns))
    sorted_columns.append('Malware Class Name')

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    print(f"[*] Writing data to {output_csv}...")
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=sorted_columns)
        writer.writeheader()

        for data_row in all_extracted_data:
            # If a file didn't have a specific API/Feature, fill it with '0'
            row_to_write = {col: data_row.get(col, 0) for col in sorted_columns}
            # Fix class name overriding (we don't want 0 for class name)
            row_to_write['Malware Class Name'] = data_row['Malware Class Name']
            writer.writerow(row_to_write)
            
    # NEW: Export the hashes to JSON right at the end
    if exported_hashes:
        print(f"[*] Exporting malware hashes to {hash_output_json}...")
        with open(hash_output_json, mode='w', encoding='utf-8') as json_file:
            json.dump(exported_hashes, json_file, indent=4)

    print(f"[+] Extraction complete. Processed {len(all_extracted_data)} files.")
    print(f"[+] Feature matrix saved to '{output_csv}' with {len(sorted_columns)} columns.")
    if exported_hashes:
        print(f"[+] Malware hashes saved to '{hash_output_json}'.")

if __name__ == "__main__":
    main()