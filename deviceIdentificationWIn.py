import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


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


if __name__ == "__main__":
    # Define feature columns
    feature_columns = [
        'Timestamp', 'Source MAC', 'Destination MAC', 'Packet Length', 'Source IP',
        'Destination IP', 'Protocol', 'Source Port', 'Destination Port'
    ]
    
    # Label column (for multi-device classification)
    label_column = 'Label'

    # Normal traffic files for individual devices (each device gets a label)
    labeled_device_files = {
        "Sentry": (r"ThesisData\csv_files\att_sent_uprint_15_1_84_f3_eb_0d_7f_2e.csv", 0),
        "Uprint": (r"ThesisData\csv_files\att_sent_uprint_15_1_b8_27_eb_d7_50_f4.csv", 1),
        "Online Attendance": (r"ThesisData\csv_files\att_sent_uprint_15_1_9c_9c_1f_0c_88_68.csv", 2),
        "Smart Plug": (r"ThesisData\csv_files\smart_plug_software_3c_f8_62_d4_99_eb.csv", 3),
        "Amazon Plug": (r"ThesisData\OnlineData\AmazonplugBT.pcap.csv", 4),
        "Breast Cancer Detector": (r"ThesisData\OnlineData\breast-cancer.csv", 5),
        "Baby Activity Monitoring": (r"ThesisData\OnlineData\baby_activity_monitoring_records.csv", 6),
        "Surveillance Camera": (r"ThesisData\OnlineData\Surveillance_Camera.csv", 7),
        "Netatmo Weather Station": (r"ThesisData\OnlineData\NetatmoWeatherStationBT.pcap.csv", 8),
        "Traffic Accident Prediction": (r"ThesisData\OnlineData\dataset_traffic_accident_prediction1.csv", 9),
        "Smoke Detector": (r"ThesisData\OnlineData\smoke.csv", 10),
        "Pollution Detector": (r"ThesisData\OnlineData\updated_pollution_dataset.csv", 11),
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

    # Train classifier
    model = RandomForestClassifier(n_estimators=500, random_state=42)
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
    test_data_file = r"ThesisData\csv_files\att_sent_uprint_15_1_b8_27_eb_d7_50_f4.csv"
    test_data = pd.read_csv(test_data_file)

    # Preprocess test data
    test_data_clean = test_data.dropna(subset=feature_columns)
    X_test_data = preprocess_data(test_data_clean, feature_columns, label_column=None, preprocessor=preprocessor)[0]
    
    # Detect anomalies as attacks
    attacks = detect_anomalies(X_test_data, model, threshold=0.5)
    if any(attacks):
        print("\nAnomalous behavior (attack) detected!")

    # Calculate matching percentages for known devices
    matching_percentages = {}
    threshold = 0.9  # Confidence threshold for a match

    for device, (_, label) in labeled_device_files.items():
        total = X_test_data.shape[0]  # Change here to use shape[0] instead of len()
        matching = sum(1 for pred in model.predict(X_test_data) if pred == label)
        matching_percentages[device] = (matching / total) * 100

    # Output matching percentages
    for device, percentage in matching_percentages.items():
        print(f"{device}: {percentage:.2f}% normal matching probability")

    # Determine the best matching device, considering only confident matches
    if all(percent < threshold * 100 for percent in matching_percentages.values()):
        print("\nUnknown device detected!")
    else:
        best_match_device = max(matching_percentages, key=matching_percentages.get)
        print(f"\nBest Matching Device: {best_match_device} ({matching_percentages[best_match_device]:.2f}%)")

    # Plot matching percentages
    def generate_gradient_colors(percentages):
        cmap = LinearSegmentedColormap.from_list("gradient", ["blue", "cyan", "green"])
        return [cmap(percentage / 100) for percentage in percentages]

    plt.figure(figsize=(10, 6))
    devices = list(matching_percentages.keys())
    percentages = list(matching_percentages.values())

    # Generate gradient colors based on percentages
    colors = generate_gradient_colors(percentages)

    bars = plt.bar(devices, percentages, color=colors)

    # Add percentages on top of each bar
    for bar, percentage in zip(bars, percentages):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), 
                 f"{percentage:.2f}%", 
                 ha='center', va='bottom', fontsize=8, color='black', fontweight='bold')

    plt.ylim(0, 100)
    plt.title("Matching Percentages by Device", fontsize=12)
    plt.xlabel("Device", fontsize=11)
    plt.ylabel("Matching Percentage (%)", fontsize=11)
    plt.xticks(rotation=70, fontsize=8)
    plt.tight_layout()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()
