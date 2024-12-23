import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Preprocess the data: Normalize the features and extract labels
def preprocess_data(df, feature_columns, label_column):
    # Check for missing columns in the data
    missing_columns = [col for col in feature_columns + [label_column] if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing columns in the data: {missing_columns}")
    
    # Drop rows with missing values
    df_clean = df.dropna(subset=feature_columns + [label_column])

    # Extract features (X) and labels (y)
    X = df_clean[feature_columns]
    y = df_clean[label_column]
    
    # Normalize the features
    scaler = StandardScaler()
    X_normalized = scaler.fit_transform(X)
    
    return pd.DataFrame(X_normalized, columns=feature_columns), y, scaler

if __name__ == "__main__":
    # Define feature columns
    feature_columns = [
        'Header_Length', 'Protocol Type', 'Time_To_Live',
        'Rate', 'fin_flag_number', 'syn_flag_number',
        'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
        'ece_flag_number', 'cwr_flag_number', 'ack_count',
        'syn_count', 'fin_count', 'rst_count', 
        'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 
        'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP','IGMP', 'IPv', 'LLC', 
        'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 
        'IAT', 'Number', 'Variance',
    ]
    
    # Label column (for multi-device classification)
    label_column = 'Label'

    # Normal traffic files for individual devices (each device gets a label)
    labeled_device_files = {
        "Online Attendance": (r"ThesisData\OpenWRT\att_sent_2_15_1_hour.pcap.csv", 0),
        "Sentry": (r"ThesisData\OpenWRT\sent_2_15_1_hour.pcap.csv", 1),
        "Uprint": (r"ThesisData\OpenWRT\uprint_dec_15_1.pcap.csv", 2),
        "Smart Plug": (r"ThesisData\OpenWRT\smart_plug_software.pcap.csv", 3),
    }

    # Create a mapping of labels to device names
    label_to_device = {label: device for device, (_, label) in labeled_device_files.items()}

    # Combine datasets for training
    combined_data = pd.DataFrame()
    for device, (file, label) in labeled_device_files.items():
        df = pd.read_csv(file)
        if df.empty:
            raise ValueError(f"File {file} is empty!")
        df['Label'] = label  # Add label for each device
        combined_data = pd.concat([combined_data, df])

    # Ensure combined dataset is not empty
    if combined_data.empty:
        raise ValueError("Combined dataset is empty! Check your CSV files.")

    # Preprocess combined data
    X, y, scaler = preprocess_data(
        combined_data, feature_columns, label_column=label_column
    )

    # Train-test split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train classifier
    model = RandomForestClassifier(n_estimators=500, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate on test set
    y_pred = model.predict(X_test)
    y_test_device_names = [label_to_device[label] for label in y_test]
    y_pred_device_names = [label_to_device[label] for label in y_pred]

    print("\nClassification Report:\n")
    print(classification_report(y_test_device_names, y_pred_device_names, target_names=list(label_to_device.values())))

    # Load the test data (multi-device)
    test_data_file = r"ThesisData\OpenWRT\sent_2_15_1_hour.pcap.csv"
    test_data = pd.read_csv(test_data_file)

    # Preprocess test data
    test_data_clean = test_data.dropna(subset=feature_columns)
    X_test_data = scaler.transform(test_data_clean[feature_columns])
    
    # Predict labels for test data
    y_pred_test = model.predict(X_test_data)

    # Calculate matching percentages
    matching_percentages = {}
    for device, (_, label) in labeled_device_files.items():
        total = len(y_pred_test)
        matching = sum(1 for pred in y_pred_test if pred == label)
        matching_percentages[device] = (matching / total) * 100

    # Output matching percentages
    for device, percentage in matching_percentages.items():
        print(f"{device}: {percentage:.2f}% normal matching probability")

    # Determine the best matching device
    best_match_device = max(matching_percentages, key=matching_percentages.get)
    print(f"\nBest Matching Device: {best_match_device} ({matching_percentages[best_match_device]:.2f}%)")
