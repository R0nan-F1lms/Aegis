import pandas as pd
import numpy as np
import os
import time
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.feature_selection import SequentialFeatureSelector


def load_and_prepare_data(csv_path):
    print(f"[*] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    df['Is_Malware'] = df['Malware Class Name'].apply(lambda x: 0 if str(x).lower() == 'benign' else 1)
    X = df.drop(columns=['Malware Class Name', 'Is_Malware'])
    y = df['Is_Malware']
    return X, y

# Trains 3 models on a specific feature set and returns their accuracies.
def evaluate_models(X_train, X_test, y_train, y_test, feature_set_name):
    models = {
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "SVM (Linear)": SVC(kernel='linear', random_state=42)
    }
    
    results = {}
    print(f"\n--- Evaluating {feature_set_name} ({X_train.shape[1]} Features) ---")
    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        results[name] = acc
        print(f"    > {name} Accuracy: {acc * 100:.2f}%")
        
    return results

def main():
    csv_path = os.path.join("output", "features.csv")
    
    if not os.path.exists(csv_path):
        print(f"[-] Error: {csv_path} not found.")
        return

    X, y = load_and_prepare_data(csv_path)
    feature_names = np.array(X.columns)

    # Base Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("\n[*] Running Model-Based Selection (Random Forest) to calculate feature scores...")
    rf_selector = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_selector.fit(X_train, y_train)

    # Get importance scores and sort them in descending order
    importances = rf_selector.feature_importances_
    indices = np.argsort(importances)[::-1]

    # Display the top 10 most important features for your report
    print("\n[*] Top 10 Most Important Features Discovered:")
    for i in range(10):
        print(f"    {i+1}. {feature_names[indices[i]]} (Score: {importances[indices[i]]:.4f})")

    # Extract our 3 feature sets required by the assignment
    sets_to_test = {
        "Top 100 Features": indices[:100],
        "Top 50 Features": indices[:50],
        "Top 20 Features": indices[:20]
    }

    # Evaluate the 3 Model-Based Sets
    for set_name, selected_indices in sets_to_test.items():
        X_train_reduced = X_train.iloc[:, selected_indices]
        X_test_reduced = X_test.iloc[:, selected_indices]
        evaluate_models(X_train_reduced, X_test_reduced, y_train, y_test, set_name)

    print("\n[*] Starting Sequential Feature Selection (SFS)...")
    print("    (Running SFS on the Top 50 pool to find the absolute best 10)")
    
    top_50_indices = indices[:50]
    X_train_sfs_pool = X_train.iloc[:, top_50_indices]
    X_test_sfs_pool = X_test.iloc[:, top_50_indices]

    #  Decision Tree for SFS because it is fast enough to finish in a few minutes
    sfs_estimator = DecisionTreeClassifier(random_state=42)
    
    start_time = time.time()
    sfs = SequentialFeatureSelector(sfs_estimator, n_features_to_select=10, direction='forward', cv=3)
    sfs.fit(X_train_sfs_pool, y_train)
    end_time = time.time()

    print(f"[*] SFS Completed in {end_time - start_time:.2f} seconds.")
    
    # Extract the final SFS features
    sfs_support = sfs.get_support()
    sfs_feature_names = X_train_sfs_pool.columns[sfs_support]
    print("\n[*] Final 10 Features chosen by SFS:")
    for i, name in enumerate(sfs_feature_names):
        print(f"    {i+1}. {name}")

    # Transform the dataset to only include the SFS features
    X_train_sfs_final = sfs.transform(X_train_sfs_pool)
    X_test_sfs_final = sfs.transform(X_test_sfs_pool)
    
    # must cast it back to a DataFrame for our evaluation function
    X_train_sfs_final = pd.DataFrame(X_train_sfs_final, columns=sfs_feature_names)
    X_test_sfs_final = pd.DataFrame(X_test_sfs_final, columns=sfs_feature_names)

    # Evaluate the SFS Set
    evaluate_models(X_train_sfs_final, X_test_sfs_final, y_train, y_test, "SFS Top 10 Features")
    
    print("\n[+] Feature Selection Phase Complete.")

if __name__ == "__main__":
    main()