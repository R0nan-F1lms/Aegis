# Aegis: Static Malware Detection Engine

**Course:** SIT324 - Malware Analysis (Task 7.3HD)  
**Author:** Ronan (Me)

## Overview
Aegis is a machine learning-based static malware detection pipeline. Traditional signature-based detection relies on known hashes and strings, which are easily bypassed by code obfuscation and encryption. This engine solves that limitation by utilising supervised machine learning to recognise the underlying mathematical and structural patterns of malicious executables. 

The pipeline extracts structural anomalies (e.g., Virtual/Raw size mismatches, high payload entropy, non-standard section names) and Windows API/DLL imports from PE headers, generating a binary feature matrix to train high-accuracy classification models.

## Repository Structure
```text
Aegis-ML/
├── data/                  # (Ignored in Git) Raw .exe files (not included on github because I choose it not to be)
│   ├── malware/           # Malware samples (e.g., Trojan, Ransomware)
│   └── benign/            # Clean Windows executables
├── src/
│   ├── extractor.py       # Parses PEs, calculates entropy, generates CSV
│   ├── classifier.py      # Trains ML models (Decision Tree, RF, SVM)
│   └── selector.py        # Dimensionality reduction (Model-based & SFS)
├── output/
│   ├── features.csv       # The extracted binary dataset
│   └── matrices/          # Generated ROC, PR, and Confusion Matrix graphs
└── README.md