from flask import Flask, request, jsonify, render_template
from sklearn.ensemble import RandomForestClassifier
from joblib import load
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)

# Define event conditions
events = {
    'Online Course Registration': {
        'ignored_attack': 'DoS',
        'condition': lambda x: x == 'Online Course Registration'
    },
    'Networking Class Scanning': {
        'ignored_attack': 'Reconnaissance',
        'condition': lambda x: x == 'Networking Class Scanning'
    },
    'Laboratory Software Updates': {
        'ignored_attack': 'Exploits',
        'condition': lambda x: x == 'Laboratory Software Updates'
    },
    'Remote Collaboration Tools': {
        'ignored_attack': 'Backdoor',
        'condition': lambda x: x == 'Remote Collaboration Tools'
    },
    'Cybersecurity Penetration Testing': {
        'ignored_attack': 'Generic',
        'condition': lambda x: x == 'Cybersecurity Penetration Testing'
    },
    'Software Testing Projects': {
        'ignored_attack': 'Fuzzers',
        'condition': lambda x: x == 'Software Testing Projects'
    },
    'Data Mining Research': {
        'ignored_attack': 'Analysis',
        'condition': lambda x: x == 'Data Mining Research'
    },
    'Exploit Development Exercises': {
        'ignored_attack': 'Shellcode',
        'condition': lambda x: x == 'Exploit Development Exercises'
    },
    'Distributed Computing Projects': {
        'ignored_attack': 'Worms',
        'condition': lambda x: x == 'Distributed Computing Projects'
    },
    'High Bandwidth Usage During Events': {
        'ignored_attack': 'Normal Activities',
        'condition': lambda x: x == 'High Bandwidth Usage During Events'
    }
}

# Define function to adjust predictions based on events
def adjust_predictions(event, predicted_attack):
    if event in events.keys():
        if events[event]['condition'](event):
            if predicted_attack == events[event]['ignored_attack']:
                return 'Normal'  # Ignore the attack
    return predicted_attack  # Keep the original prediction
# Function to convert Series to dictionary
def series_to_dict(series):
    return series.to_dict()

label_map = {
    'Analysis': 'Analysis',
    'Backdoor': 'Backdoor',
    'DoS': 'DoS',
    'Exploits': 'Exploits',
    'Fuzzers': 'Fuzzers',
    'Generic': 'Generic',
    'Normal': 'Normal',
    'Reconnaissance': 'Reconnaissance',
    'Shellcode': 'Shellcode',
    'Worms': 'Worms'
}

@app.route('/')
def index():
    return render_template('index.html', prediction_results=None, percentage_results=None)

# Function to calculate percentage of each attack type
def calculate_percentage(predictions):
    percentage_attack_types = (pd.Series(predictions).value_counts() / len(predictions)) * 100
    return percentage_attack_types

import io

@app.route('/predict', methods=['POST'])
def predict():
    # Get event and uploaded file from form data
    event = request.form['event']
    file = request.files['file']

    # Perform prediction
    # Load the trained model
    model = joblib.load("random_forest_classifier_model(13).pkl")

    scaler = joblib.load('scaler5.pkl')
    
    # Read the text file into a DataFrame
    df = pd.read_csv(io.StringIO(file.stream.read().decode("UTF8")), delimiter="\t")
    
    # Drop the specified columns if they exist in the DataFrame
    columns_to_drop = ['id', 'label', 'attack_cat', 'sloss', 'dloss', 'dwin', 'ct_ftp_cmd']
    df = df.drop(columns=[col for col in columns_to_drop if col in df.columns], axis=1)
    
    # Initialize LabelEncoder for categorical columns
    label_encoder = LabelEncoder()
    categorical_columns = ['proto', 'service', 'state']  # Assuming these are the categorical columns
    
    # Apply label encoding to categorical columns
    for column in categorical_columns:
        if column in df.columns:
            try:
                df[column] = label_encoder.fit_transform(df[column])
            except KeyError as e:
                print(f"Error encoding column '{column}': {e}")
    
    # Scale the values using the loaded scaler
    scaled_values = scaler.transform(df)
    
    # Make predictions using the model
    predictions = model.predict(scaled_values)
    predicted_attacks = [label_map.get(prediction, 'Unknown') for prediction in predictions]
    
    # Adjust predictions based on the selected event
    adjusted_predictions = [adjust_predictions(event, predicted_attack) for predicted_attack in predicted_attacks]

    # Calculate the percentage of each attack type
    percentage_results = calculate_percentage(adjusted_predictions)

    # Convert percentage_results Series to dictionary
    percentage_results_dict = series_to_dict(percentage_results)

    # Return the prediction and percentage results
    return render_template('index.html', prediction_results=adjusted_predictions, percentage_results=percentage_results_dict)
if __name__ == '__main__':
    app.run(debug=True)
