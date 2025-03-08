from flask import Flask, render_template, request
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.naive_bayes import GaussianNB
import pickle
import warnings
import os

warnings.filterwarnings("ignore")

app = Flask(__name__, static_folder="static")

# Define model and dataset files
MODEL_FILE = "ddos_model.pkl"
DATA_FILE = "test3.csv"

def train_model():
    """Train the Naïve Bayes model if not already trained."""
    if not os.path.exists(DATA_FILE):
        print(f"Error: Dataset '{DATA_FILE}' not found.")
        return

    print("Training the model...")
    data = pd.read_csv(DATA_FILE)
    
    # Check required columns
    required_columns = ['frame.time', 'ip.dst', 'ip.src', 'Label']
    if not all(col in data.columns for col in required_columns):
        print("Error: Missing required columns in dataset.")
        return

    le = LabelEncoder()
    for col in ['frame.time', 'ip.dst', 'ip.src', 'Label']:
        data[col] = le.fit_transform(data[col])

    X = data.drop(['Label', 'frame.time'], axis=1)
    Y = data['Label']

    x_train, x_test, y_train, y_test = train_test_split(X, Y, test_size=0.25, random_state=0)

    model = GaussianNB()
    model.fit(x_train, y_train)
    

    pickle.dump(model, open(MODEL_FILE, "wb"))
    print("Model trained and saved successfully.")

# Train the model only if it doesn't exist
if not os.path.exists(MODEL_FILE):
    train_model()

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if request.method == 'GET':
        return "Error: This page only accepts POST requests. Please upload a file via the form."
    
    file = request.files.get('file')
    if not file:
        return "Error: No file uploaded. Please upload a CSV file."

    # Your file processing and prediction logic...


    try:
        df = pd.read_csv(file)
        df.fillna(0, inplace=True)  # Handle missing values

        model = pickle.load(open(MODEL_FILE, "rb"))

        # Validate if required columns exist
        required_columns = ['ip.dst', 'ip.src']
        if not all(col in df.columns for col in required_columns):
            return "Error: Uploaded file is missing required columns."

        le = LabelEncoder()
        df['ip.dst'] = le.fit_transform(df['ip.dst'])
        df['ip.src'] = le.fit_transform(df['ip.src'])

        X_test = df.select_dtypes(include=[np.number])  # Select numeric features only
        y_pred = model.predict(X_test)

        # Map predictions to labels
        prediction = "DDoS-ACK" if y_pred[0] == 0 else "DDoS-PSH-ACK" if y_pred[0] == 1 else "BENIGN"

        return render_template("result.html", prediction=prediction)

    except Exception as e:
        return f"Error processing file: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)
