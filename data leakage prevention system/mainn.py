import os
import re
import pandas as pd
import joblib
import gradio as gr

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# =========================================================
# 1. LOAD DATASET
# =========================================================

DATASET_PATH = "dataset/dataset.csv"
MODEL_PATH = "dlp_model.pkl"

print("Loading dataset...")

data = pd.read_csv(DATASET_PATH)

# Text used for training
X = data["Test data"].fillna("").astype(str)

# Target labels
y = (
    data["Ground Truth (sensitive/non sensitive)"]
    .fillna("")
    .astype(str)
    .str.lower()
    .str.strip()
)

# Convert labels into numbers
y = y.map({
    "sensitive": 1,
    "non sensitive": 0,
    "non-sensitive": 0
})

# Remove rows with unknown labels
valid_rows = y.notna()

X = X[valid_rows]
y = y[valid_rows]


# =========================================================
# 2. TRAIN MACHINE LEARNING MODEL
# =========================================================

print("Training machine learning model...")

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            max_features=5000
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )
])

model.fit(X, y)

# Save trained model
joblib.dump(model, MODEL_PATH)

print("Model trained successfully!")
print("Total training records:", len(X))


# =========================================================
# 3. RULE-BASED SENSITIVE INFORMATION DETECTION
# =========================================================

def detect_sensitive_information(text):

    detections = []

    # Email
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    if re.search(email_pattern, text):
        detections.append("Email Address")

    # Indian phone number
    phone_pattern = r'(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)'

    if re.search(phone_pattern, text):
        detections.append("Phone Number")

    # Aadhaar number
    aadhaar_pattern = r'(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)'

    if re.search(aadhaar_pattern, text):
        detections.append("Aadhaar Number")

    # Credit / Debit card number
    card_pattern = r'(?<!\d)(?:\d{4}[\s-]?){3}\d{4}(?!\d)'

    if re.search(card_pattern, text):
        detections.append("Card Number")

    # Password-related words
    password_pattern = r'\b(password|passwd|passcode|secret|login password)\b'

    if re.search(password_pattern, text, re.IGNORECASE):
        detections.append("Password / Credential")

    return list(set(detections))


# =========================================================
# 4. MASK SENSITIVE INFORMATION
# =========================================================

def mask_sensitive_information(text):

    # Mask email
    text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        '[EMAIL MASKED]',
        text
    )

    # Mask phone number
    text = re.sub(
        r'(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)',
        '[PHONE MASKED]',
        text
    )

    # Mask Aadhaar
    text = re.sub(
        r'(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)',
        '[AADHAAR MASKED]',
        text
    )

    # Mask card number
    text = re.sub(
        r'(?<!\d)(?:\d{4}[\s-]?){3}\d{4}(?!\d)',
        '[CARD NUMBER MASKED]',
        text
    )

    return text


# =========================================================
# 5. ANALYZE USER TEXT
# =========================================================

def analyze_text(text):

    if not text or not text.strip():
        return (
            "⚠️ No text entered",
            "Please enter some text.",
            "None",
            "None",
            ""
        )

    text = text.strip()

    # -----------------------------
    # Machine Learning prediction
    # -----------------------------

    prediction = model.predict([text])[0]

    # Probability / confidence
    probabilities = model.predict_proba([text])[0]

    confidence = max(probabilities) * 100

    if prediction == 1:
        ml_result = "🔴 SENSITIVE"
    else:
        ml_result = "🟢 NON-SENSITIVE"


    # -----------------------------
    # Rule-based detection
    # -----------------------------

    detections = detect_sensitive_information(text)


    # =====================================================
    # RISK CALCULATION
    # =====================================================

    # High-risk sensitive information
    high_risk_types = {
        "Aadhaar Number",
        "Card Number",
        "Password / Credential"
    }

    # Medium-risk information
    medium_risk_types = {
        "Email Address",
        "Phone Number"
    }

    if any(item in high_risk_types for item in detections):
        risk = "🔴 HIGH"

    elif detections or prediction == 1:
        risk = "🟠 MEDIUM"

    else:
        risk = "🟢 LOW"


    # =====================================================
    # ACTION
    # =====================================================

    if risk == "🔴 HIGH":
        action = "🚫 BLOCK / MASK"

    elif risk == "🟠 MEDIUM":
        action = "⚠️ WARN / MASK"

    else:
        action = "✅ ALLOW"


    # =====================================================
    # DETECTION RESULT
    # =====================================================

    if detections:
        detected_text = "\n".join(
            ["✓ " + item for item in detections]
        )
    else:
        detected_text = "No specific sensitive information detected."


    # =====================================================
    # PROTECTED TEXT
    # =====================================================

    if detections:
        protected_text = mask_sensitive_information(text)
    else:
        protected_text = text


    # =====================================================
    # LOG EVENT
    # =====================================================

    log_data = {
        "Text": text,
        "ML Prediction": ml_result,
        "Confidence": round(confidence, 2),
        "Risk Level": risk,
        "Detected Information": ", ".join(detections),
        "Action": action
    }

    log_file = "dlp_security_log.csv"

    if os.path.exists(log_file):

        old_logs = pd.read_csv(log_file)

        new_log = pd.DataFrame([log_data])

        updated_logs = pd.concat(
            [old_logs, new_log],
            ignore_index=True
        )

        updated_logs.to_csv(
            log_file,
            index=False
        )

    else:

        pd.DataFrame([log_data]).to_csv(
            log_file,
            index=False
        )


    # =====================================================
    # RETURN RESULTS TO UI
    # =====================================================

    prediction_output = (
        f"{ml_result}\n\n"
        f"Confidence: {confidence:.2f}%"
    )

    return (
        prediction_output,
        detected_text,
        risk,
        action,
        protected_text
    )


# =========================================================
# 6. CREATE GRADIO USER INTERFACE
# =========================================================

with gr.Blocks(title="Data Leakage Prevention System") as app:

    gr.Markdown(
        """
        # 🔐 Data Leakage Prevention System

        ### AI/ML Based Sensitive Data Detection and Prevention

        Enter text below to check whether it contains
        sensitive information.
        """
    )

    with gr.Row():

        with gr.Column():

            input_text = gr.Textbox(
                label="Enter Text",
                placeholder=(
                    "Example: My email is abc@gmail.com "
                    "and my phone number is 9876543210"
                ),
                lines=8
            )

            check_button = gr.Button(
                "🔍 Check for Data Leakage"
            )

        with gr.Column():

            prediction_output = gr.Textbox(
                label="ML Prediction",
                lines=3
            )

            detection_output = gr.Textbox(
                label="Detected Information",
                lines=5
            )

            risk_output = gr.Textbox(
                label="Risk Level",
                lines=2
            )

            action_output = gr.Textbox(
                label="Recommended Action",
                lines=2
            )

            protected_output = gr.Textbox(
                label="Protected Text",
                lines=5
            )


    # Button action
    check_button.click(
        fn=analyze_text,
        inputs=input_text,
        outputs=[
            prediction_output,
            detection_output,
            risk_output,
            action_output,
            protected_output
        ]
    )


    # Example inputs
    gr.Markdown(
        """
        ### 🧪 Try these examples

        **Example 1 – Sensitive:**

        `My email is abc@gmail.com and my phone number is 9876543210`

        **Example 2 – High Risk:**

        `My Aadhaar number is 1234 5678 9012`

        **Example 3 – Non-Sensitive:**

        `I enjoy reading books and watching movies.`
        """
    )


# =========================================================
# 7. START APPLICATION
# =========================================================

if __name__ == "__main__":

    print("\n====================================")
    print("DATA LEAKAGE PREVENTION SYSTEM")
    print("====================================")

    print("Starting web interface...")

    app.launch()