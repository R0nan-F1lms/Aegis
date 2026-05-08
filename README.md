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

## Prerequisites & Installation
Ensure you are running Python 3.8+ and install the required data science and reverse engineering libraries:


```bash
pip install pefile pandas scikit-learn matplotlib```

*Note: For the execution of extractor.py, it is highly recommended to run the script within an isolated, air-gapped Virtual Machine (e.g., FLARE VM) to ensure host safety while parsing live malware samples.*

## Pipeline Execution Guide
**Feature Extraction**
The extraction script safely parses the PE headers of all files in the `/data/` directory, calculates Shannon Entropy, checks for packing indicators, and outputs a binary matrix.

```bash
python src/extractor.py```

**Output:** `output/features.csv` (Contains all samples with their extracted features and class labels).

**Classification Training**
Trains three separate supervised learning models (Decision Tree, Random Forest, Support Vector Machine) using an 80/20 train-test split.


```bash
python src/classifier.py```

**Output:** Console accuracy metrics and performance graphs (ROC Curves, Precision-Recall Curves, Confusion Matrices) saved to `output/matrices/`.

**Dimensionality Reduction & Feature Selection**
Optimises the engine by identifying the most critical malware indicators, proving high accuracy can be maintained while discarding over 99% of the dataset's features.


```bash
python src/selector.py```

**Output:** 1. Ranks the Top 10 most important features using a Model-based approach.
2. Evaluates the models against reduced datasets (Top 100, 50, 20).
3. Executes Sequential Feature Selection (SFS) to isolate the definitive Top 10 features for an ultra-lightweight detection baseline.