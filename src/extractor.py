import pefile
import os
import csv
import math

# ==========================================
# FILE: extractor.py
# PURPOSE: Static Feature Extraction Pipeline for Aegis-ML
# ==========================================

# Define standard section names to detect anomalies
STANDARD_NAMES = ['.text', '.data', '.rdata', '.idata', '.edata', '.pdata', '.rsrc', '.bss', '.reloc']

def calculate_entropy(data_bytes):
    """Calculates the Shannon entropy of a byte sequence."""
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

def is_section_name_standard(name):
    """Checks if a section name is standard, stripping null bytes."""
    clean_name = name.decode('utf-8', 'ignore').strip('\x00')
    return clean_name.lower() in STANDARD_NAMES

def detect_packing(entropy, weird_name_count):
    """Heuristic: High entropy or weird section names often mean packed/encrypted."""
    if entropy > 7.0 or weird_name_count > 0:
        return 1
    return 0

def extract_features_from_pe(file_path, class_label):
    """Extracts structural and import features from a single PE file."""
    features = {}
    
    try:
        pe = pefile.PE(file_path)
        
        # 1. Base Class Label
        # Note: We use 'Malware Class Name' to match the PDF brief exactly
        features['Malware Class Name'] = class_label
        
        # 2. Structural Features
        features['Number_of_Sections'] = len(pe.sections)
        
        mismatch_count = 0
        weird_name_count = 0
        
        for section in pe.sections:
            # Check for size mismatches (Virtual Size vs Raw Size)
            # A common heuristic is checking if Virtual Size is significantly larger
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
                
                # Add the specific API functions
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
    # Ensure you are running this from the root 'Aegis-ML' directory
    malware_dir = os.path.join("data", "malware")
    benign_dir = os.path.join("data", "benign")
    output_csv = os.path.join("output", "features.csv")
    
    all_extracted_data = []
    
    print("[*] Starting extraction on Malware dataset...")
    # Assume malware is grouped in folders by class: data/malware/trojan/file.exe
    if os.path.exists(malware_dir):
        for root, dirs, files in os.walk(malware_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # The folder name containing the file becomes the class label
                class_label = os.path.basename(root) 
                
                # If files are just loose in the malware directory, default to 'Malware'
                if class_label == 'malware': 
                    class_label = 'Malware_Generic'
                    
                print(f"  -> Processing: {file} ({class_label})")
                features = extract_features_from_pe(file_path, class_label)
                if features:
                    all_extracted_data.append(features)
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

    # ---------------------------------------------------------
    # CSV GENERATION: Dynamic Column Mapping
    # ---------------------------------------------------------
    print("\n[*] Structuring Feature Matrix...")
    if not all_extracted_data:
        print("[-] No data extracted. Exiting.")
        return

    # Collect EVERY unique feature key discovered across ALL files
    all_columns = set()
    for data_row in all_extracted_data:
        all_columns.update(data_row.keys())
        
    # Ensure 'Malware Class Name' is the last column to match assignment specifications
    all_columns.discard('Malware Class Name')
    sorted_columns = sorted(list(all_columns))
    sorted_columns.append('Malware Class Name')

    # Ensure output directory exists
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

    print(f"[+] Extraction complete. Processed {len(all_extracted_data)} files.")
    print(f"[+] Feature matrix saved to '{output_csv}' with {len(sorted_columns)} columns.")

if __name__ == "__main__":
    main()