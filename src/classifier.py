import pandas as pd
import os
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, confusion_matrix, ConfusionMatrixDisplay, 
                             roc_curve, auc, precision_recall_curve, average_precision_score)

# ==========================================
# FILE: classifier.py
# PURPOSE: Machine Learning Classification Pipeline for Aegis-ML
# ==========================================

def prepare_data(csv_path):
    """Loads the CSV and prepares the feature matrix (X) and labels (y)."""
    print(f"[*] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)

    # The assignment asks for a 'detection engine'. To evaluate ROC and PR curves effectively,
    # we need binary classification (Malware = 1, Benign = 0).
    # We keep the original class names for the dataset, but map them for the models.
    df['Is_Malware'] = df['Malware Class Name'].apply(lambda x: 0 if str(x).lower() == 'benign' else 1)

    # X is our feature matrix (drop the label columns)
    X = df.drop(columns=['Malware Class Name', 'Is_Malware'])
    
    # y is our target variable
    y = df['Is_Malware']

    print(f"[+] Dataset loaded: {X.shape[0]} samples with {X.shape[1]} features.")
    return X, y

def plot_and_save_roc(y_test, y_probs, model_name, output_dir):
    """Generates and saves the Receiver Operating Characteristic (ROC) curve."""
    fpr, tpr, _ = roc_curve(y_test, y_probs)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(f'ROC Curve - {model_name}')
    plt.legend(loc="lower right")
    
    save_path = os.path.join(output_dir, f"{model_name.replace(' ', '_')}_ROC.png")
    plt.savefig(save_path)
    plt.close()

def plot_and_save_pr(y_test, y_probs, model_name, output_dir):
    """Generates and saves the Precision-Recall curve."""
    precision, recall, _ = precision_recall_curve(y_test, y_probs)
    avg_precision = average_precision_score(y_test, y_probs)

    plt.figure()
    plt.plot(recall, precision, color='blue', lw=2, label=f'PR curve (AP = {avg_precision:.2f})')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title(f'Precision-Recall Curve - {model_name}')
    plt.legend(loc="lower left")
    
    save_path = os.path.join(output_dir, f"{model_name.replace(' ', '_')}_PR.png")
    plt.savefig(save_path)
    plt.close()

def plot_and_save_confusion_matrix(model, X_test, y_test, model_name, output_dir):
    """Generates and saves the Confusion Matrix."""
    # We display 'Benign' and 'Malware' instead of 0 and 1 for readability in the report
    disp = ConfusionMatrixDisplay.from_estimator(
        model, X_test, y_test, 
        display_labels=['Benign', 'Malware'], 
        cmap=plt.cm.Blues
    )
    disp.ax_.set_title(f'Confusion Matrix - {model_name}')
    
    save_path = os.path.join(output_dir, f"{model_name.replace(' ', '_')}_CM.png")
    plt.savefig(save_path)
    plt.close()

def main():
    csv_path = os.path.join("output", "features.csv")
    graph_dir = os.path.join("output", "matrices")
    
    # Ensure graph output directory exists
    os.makedirs(graph_dir, exist_ok=True)

    if not os.path.exists(csv_path):
        print(f"[-] Error: {csv_path} not found. Did you run extractor.py and move the file?")
        return

    # 1. Load Data
    X, y = prepare_data(csv_path)

    # 2. Train/Test Split (80% Training, 20% Testing)
    print("\n[*] Splitting data (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Define our three Classifiers
    # set probability=True for SVM so we can calculate the ROC curve
    models = {
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "Support Vector Machine": SVC(kernel='linear', probability=True, random_state=42)
    }

    # 4. Train and Evaluate Each Model
    for name, model in models.items():
        print(f"\n[========== Evaluating {name} ==========]")
        
        # Train the model
        print(f"[*] Training {name}...")
        model.fit(X_train, y_train)

        # Make predictions
        y_pred = model.predict(X_test)
        
        # Get probability scores for the positive class (Malware) for ROC and PR curves
        y_probs = model.predict_proba(X_test)[:, 1]

        # Calculate basic Accuracy
        acc = accuracy_score(y_test, y_pred)
        print(f"[+] Accuracy: {acc * 100:.2f}%")

        # Generate and save Visualizations
        print(f"[*] Generating metric graphs...")
        plot_and_save_confusion_matrix(model, X_test, y_test, name, graph_dir)
        plot_and_save_roc(y_test, y_probs, name, graph_dir)
        plot_and_save_pr(y_test, y_probs, name, graph_dir)
        
        print(f"[+] Graphs saved to {graph_dir}")

    print("\n[+] Classification phase complete. Check the 'output/matrices' folder for your report graphs.")

if __name__ == "__main__":
    main()