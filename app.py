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
import pickle
@app.route('/')
def index():
    return render_template('index.html')
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
    df = pd.read_csv(file)
    
    # Specify columns to drop
    columns_to_drop = ['id', 'label', 'attack_cat', 'sloss', 'dloss', 'dwin', 'ct_ftp_cmd']
    
    # Drop the specified columns from the first row
    first_row = df.iloc[0].drop(columns_to_drop)
    
    # Initialize LabelEncoder for categorical columns
    label_encoder = LabelEncoder()
    categorical_columns = ['proto', 'service', 'state']  # Assuming these are the categorical columns
    
    # Apply label encoding to categorical columns
    for column in categorical_columns:
        if column in first_row.index:
            try:
                first_row[column] = label_encoder.fit_transform([first_row[column]])[0]
            except KeyError as e:
                print(f"Error encoding column '{column}': {e}")
    
    # Convert the first row to a DataFrame and transpose it
    first_row_df = pd.DataFrame(first_row).T
    
    # Scale the values using the loaded scaler
    scaled_values = scaler.transform(first_row_df)
    # Make predictions using the model
    features_array = np.array(scaled_values).reshape(1, -1)
    predicted_label_int = model.predict(features_array)[0]
    predicted_attack = label_map.get(predicted_label_int, 'Unknown')
    
    # Adjust predictions based on the selected event
    adjusted_prediction = adjust_predictions(event, predicted_attack)

    # Return the prediction result
    return jsonify({'predicted_attack': adjusted_prediction})


if __name__ == '__main__':
    app.run(debug=True)
