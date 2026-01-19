from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import load_model
import traceback
import warnings

# =========================
# Suppress unnecessary warnings
# =========================
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# =========================
# Load Model & Scaler
# =========================
try:
    scaler = joblib.load("scaler.pkl")
    print("[INFO] Scaler loaded successfully")
except Exception as e:
    print("[ERROR] Failed to load scaler:", str(e))
    traceback.print_exc()
    raise e

try:
    model = load_model("autoencoder_model.h5", compile=False)
    print("[INFO] Autoencoder model loaded successfully")
except Exception as e:
    print("[ERROR] Failed to load model:", str(e))
    traceback.print_exc()
    raise e

# ⚠️ ضع هنا القيمة الحقيقية من التدريب
THRESHOLD = 0.123

# =========================
# Flask App
# =========================
app = Flask(__name__)

# =========================
# Health Check
# =========================
@app.route("/", methods=["GET"])
def health():
    return "IDS AI Engine is running"

# =========================
# Prediction Endpoint
# =========================
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        if not data:
            raise ValueError("No JSON data provided")

        print("[INFO] Received data:", data)

        # Feature order MUST match training
        feature_names = ["dstPort", "protocol", "packetSize", "packetCount",
                         "payloadSize", "flowDirection", "tcpFlags"]

        # Use DataFrame to avoid sklearn feature name warnings
        df = pd.DataFrame([{name: data.get(name) or data.get(name.capitalize()) for name in feature_names}])

        # Check for missing values
        if df.isnull().values.any():
            raise ValueError(f"Missing feature values: {df[df.isnull().any(axis=1)]}")

        print("[INFO] Feature types:", df.dtypes.tolist())

        sample_scaled = scaler.transform(df)
        print("[INFO] Sample scaled successfully:", sample_scaled)

        reconstructed = model.predict(sample_scaled, verbose=0)
        mse = np.mean(np.square(sample_scaled - reconstructed))
        print(f"[INFO] MSE computed: {mse}")

        prediction = 1 if mse > THRESHOLD else 0

        return jsonify({
            "prediction": prediction,
            "mse": float(mse),
            "threshold": THRESHOLD
        })

    except Exception as e:
        error_msg = str(e)
        stack_trace = traceback.format_exc()
        print("[ERROR] Exception during prediction:", error_msg)
        print(stack_trace)
        return jsonify({
            "error": error_msg,
            "stack_trace": stack_trace
        }), 500

# =========================
# Run Server
# =========================
if __name__ == "__main__":
    # threaded=True لتجنب مشاكل shutdown على Windows
    print("[INFO] Starting IDS AI Engine server on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, threaded=True)
