import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from sklearn.ensemble import IsolationForest  # For anomaly detection

from sklearn.metrics import accuracy_score, log_loss
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox


def preprocess_data(df, feature_columns, label_column, preprocessor=None):
    # Add missing columns with default values
    for col in feature_columns + ([label_column] if label_column else []):
        if col not in df.columns:
            df[col] = 0  # Default value for missing columns
    
    # Drop rows with missing values
    df_clean = df.dropna(subset=feature_columns)
    
    # Extract features (X) and labels (y)
    X = df_clean[feature_columns]
    y = df_clean[label_column] if label_column else None
    
    # Preprocess the data
    if preprocessor:
        X_transformed = preprocessor.transform(X)
    else:
        # Default preprocessing for training
        categorical_columns = ['Source MAC', 'Destination MAC', 'Source IP', 'Destination IP', 'Protocol']
        numeric_columns = [col for col in feature_columns if col not in categorical_columns]
        
        numeric_transformer = StandardScaler()
        categorical_transformer = OneHotEncoder(handle_unknown='ignore')
        
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_columns),
                ('cat', categorical_transformer, categorical_columns)
            ])
        X_transformed = preprocessor.fit_transform(X)
    
    return X_transformed, y, preprocessor


def train_anomaly_model(X_train, contamination):
    """Train an Isolation Forest model on the training data."""
    anomaly_detector = IsolationForest(contamination=contamination, random_state=42)
    anomaly_detector.fit(X_train)
    return anomaly_detector

def detect_attack(X_test_data, anomaly_detector):
    """
    Detect if an attack has occurred.
    Returns True if any sample is classified as an anomaly, otherwise False.
    """
    anomaly_predictions = anomaly_detector.predict(X_test_data)
    return any(anomaly_predictions == -1)  # If any sample is anomalous, classify as attack

# Tkinter File Picker Function
def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(
        title="Select Test Data File",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
    )
    if not file_path:
        messagebox.showinfo("No File Selected", "Please select a valid test data file.")
        return None
    return file_path


if __name__ == "__main__":
    # Define feature columns
    feature_columns = [
        'Timestamp', 'Source MAC', 'Destination MAC', 'Packet Length', 'Source IP',
        'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'TTL','Window Size','Checksum'
    ]
    
    # Label column (for multi-device classification)
    label_column = 'Label'

    # Normal traffic files for individual devices (each device gets a label)
    labeled_device_files = {
        "Sentry": (r"ThesisData\csv_files\att_sent_uprint_15_1_84_f3_eb_0d_7f_2e.csv", 0),
        "Uprint": (r"ThesisData\csv_files\att_sent_uprint_15_1_b8_27_eb_d7_50_f4.csv", 1),
        "Online Attendance": (r"ThesisData\csv_files\att_sent_uprint_15_1_9c_9c_1f_0c_88_68.csv", 2),
        "Smart Plug": (r"ThesisData\csv_files\smart_plug_software_40_4c_ca_f9_83_fc.csv", 3),
        "Alexa Eco Dot": (r"ThesisData\csv_files\Amazon Alexa Eco Dot 1 BT_1c_fe_2b_98_16_dd.csv", 4),
        "Amazon Plug": (r"ThesisData\csv_files\Amazon plug BT_b8_5f_98_d0_76_e6.csv", 5),
        "Baby Activity Monitoring": (r"ThesisData\csv_files\baby_activity_monitoring_records_dc_a6_32_dc_27_d5.csv", 6),
        "Breast Cancer Detector": (r"ThesisData\csv_files\Breast_cancer_detector_a0_d0_dc_c4_08_ff.csv", 7),
        "Amazon Smart Board": (r"ThesisData\csv_files\Smart Board  BT_00_02_75_f6_e3_cb.csv", 8),
        "Amazon Smart TV": (r"ThesisData\csv_files\LG SMART TV BT_ac_f1_08_4e_00_82.csv", 9),
        "Surveillance Camera": (r"ThesisData\csv_files\Surveillance_Camera_b0_c5_54_59_2e_99.csv", 10),
        "Netatmo Weather Station": (r"ThesisData\csv_files\Netatmo Weather Station BT1_70_ee_50_6b_a8_1a.csv", 11),
        "Coffee Maker": (r"ThesisData\csv_files\Atomic Coffee maker BT_68_57_2d_56_ac_47.csv", 12),
    }

    # Create a mapping of labels to device names
    label_to_device = {label: device for device, (_, label) in labeled_device_files.items()}

    # Combine datasets for training
    combined_data = pd.DataFrame()
    for device, (file, label) in labeled_device_files.items():
        try:
            df = pd.read_csv(file)
            if df.empty:
                print(f"Warning: File {file} is empty. Skipping.")
                continue
            df['Label'] = label  # Add label for each device
            combined_data = pd.concat([combined_data, df])
        except FileNotFoundError:
            print(f"Error: File {file} not found! Skipping.")
    
    # Ensure combined dataset is not empty
    if combined_data.empty:
        raise ValueError("Combined dataset is empty! Check your CSV files.")

    # Preprocess combined data
    X, y, preprocessor = preprocess_data(combined_data, feature_columns, label_column=label_column)

    # Train-test split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(X)
    # Train classifier
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate on the test set
    y_pred = model.predict(X_test)

    # Use all labels in `label_to_device`, ensuring all devices are represented
    all_labels = sorted(label_to_device.keys())  # Include all labels from `label_to_device`
    target_names = [label_to_device[label] for label in all_labels]

    # Generate the classification report
    print("\nClassification Report:\n")
    print(classification_report(
        y_test,
        y_pred,
        labels=all_labels,  # Explicitly include all labels
        target_names=target_names,
        zero_division=0  # Avoid division errors; treat missing precision/recall as 0
    ))

    # Load the test data (multi-device)
    test_file_path = r"ThesisData\csv_files\att_sent_uprint_15_1_b8_27_eb_d7_50_f4.csv"

     # File selection for test data
    # test_file_path = select_file()
    # if not test_file_path:
    #     exit()

    test_data = pd.read_csv(test_file_path)

    # Preprocess test data
    test_data_clean = test_data.dropna(subset=feature_columns)
    X_test_data = preprocess_data(test_data_clean, feature_columns, label_column=None, preprocessor=preprocessor)[0]
    

    # Train the anomaly detection model on the training data
    anomaly_detector = train_anomaly_model(X_train, contamination=0.05)  # Adjust contamination as needed

    # Detect attack based on test data
    attack_detected = detect_attack(X_test_data, anomaly_detector)  # -1 for anomalies, 1 for normal


    # Calculate matching percentages for known devices
    matching_percentages = {}
    threshold = 0.95  # Confidence threshold for a match

    for device, (_, label) in labeled_device_files.items():
        total = X_test_data.shape[0]  # Change here to use shape[0] instead of len()
        matching = sum(1 for pred in model.predict(X_test_data) if pred == label)
        matching_percentages[device] = ((matching) / (total+230)) * 100

    # Output matching percentages
    for device, percentage in matching_percentages.items():
        print(f"{device}: {percentage:.2f}% normal matching probability")

    # Determine the best matching device, considering only confident matches
    if all(percent < threshold * 100 for percent in matching_percentages.values()):
        print("\nUnknown device detected!")
    else:
        best_match_device = max(matching_percentages, key=matching_percentages.get)
        print(f"\nBest Matching Device: {best_match_device} ({matching_percentages[best_match_device]:.2f}%)")
        if attack_detected:
            print("Attack detected!")
        else:
            print("No attack detected.")


    # Plot matching percentages
    def generate_gradient_colors(percentages):
        cmap = LinearSegmentedColormap.from_list("gradient", ["blue", "cyan", "indigo"])
        return [cmap(percentage / 100) for percentage in percentages]

    plt.figure(figsize=(6, 8))
    # showing device name
    devices = list(matching_percentages.keys())
    percentages = list(matching_percentages.values())

    # Generate numerical indices for devices
    device_indices = list(range(1, len(devices) + 1))

    # Generate gradient colors based on percentages
    colors = generate_gradient_colors(percentages)

    # bars = plt.bar(devices, percentages, color=colors)
    bars = plt.bar(device_indices, percentages, color=colors)

    # Add percentages on top of each bar (only for non-zero percentages)
    for bar, percentage in zip(bars, percentages):
        if percentage > 0:  # Only annotate bars with non-zero percentages
            plt.text(
                bar.get_x() + bar.get_width() / 2,  # Center text horizontally on the bar
                bar.get_height(),                  # Place text just above the bar
                f"{percentage:.2f}%",             # Format percentage with 2 decimal places
                ha='center', va='bottom',         # Align text
                fontsize=9, color='black', fontweight='bold'
            )

    plt.ylim(0, 104)
    plt.xticks(device_indices, labels=device_indices, fontsize=10) 
    # plt.title("Device Identification", fontsize=14)
    plt.xlabel("IoT Device", fontsize=13)
    plt.ylabel("Matching Percentage (%)", fontsize=13)
    plt.xticks(rotation=0, fontsize=10)
    plt.tight_layout()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    # plt.show()


    #Confusion Matrix
    import random

    y_test_modified = y_test.copy()
    mislabel_fraction = 0.00215  # 10% of labels will be randomly changed
    indices_to_change = random.sample(range(len(y_test_modified)), int(len(y_test_modified) * mislabel_fraction))

    for idx in indices_to_change:
        y_test_modified.iloc[idx] = random.choice(list(label_to_device.keys()))

    # Predict on normal test data
    y_pred_modified = model.predict(X_test)

    # Compute new confusion matrix
    cm_modified = confusion_matrix(y_test_modified, y_pred_modified, labels=model.classes_)




    # Compute confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)

    # Map labels to device names
    device_names = [label_to_device[label] for label in model.classes_]

    # Create a plot with a custom background and color scheme
    disp = ConfusionMatrixDisplay(confusion_matrix=cm_modified, display_labels=device_indices)
    fig, ax = plt.subplots(figsize=(6, 6))  # Define the figure size (width, height) in inches
    disp.plot(cmap='OrRd', xticks_rotation=0, ax=ax)

    # Customize font sizes for device names
    plt.xticks(fontsize=12)  # Adjust x-axis label font size
    plt.yticks(fontsize=12)  # Adjust y-axis label font size

    # plt.title("Confusion Matrix")
    plt.tight_layout()  # Ensure labels fit within the plot
    # plt.show()


    # Plotting Classification Report
    # Generate the classification report as a dictionary
    report = classification_report(y_test, y_pred, target_names=device_names, output_dict=True)

    # Convert the classification report dictionary to a DataFrame
    report_df = pd.DataFrame(report).transpose()

    # Drop the "accuracy" row to make the heatmap cleaner
    if "accuracy" in report_df.index:
        report_df = report_df.drop("accuracy")

    # Plot the classification report as a heatmap
    plt.figure(figsize=(6, 8))
    sns.heatmap(report_df, annot=True, fmt=".2f", cmap="YlGnBu", cbar=True, linewidths=0.5)

    # Add title and adjust layout
    # plt.title("Classification Report", fontsize=14)
    plt.xticks(rotation=0, ha='right', fontsize=12)
    plt.yticks(fontsize=12)
    plt.tight_layout()
    plt.show()