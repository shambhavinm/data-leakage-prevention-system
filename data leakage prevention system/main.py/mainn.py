import re
import gradio as gr


def detect_sensitive_data(text):

    detected = []

    # Email
    emails = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text
    )

    # Phone
    phones = re.findall(
        r"\b[6-9]\d{9}\b",
        text
    )

    # Aadhaar
    aadhaar = re.findall(
        r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        text
    )

    # Card
    cards = re.findall(
        r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        text
    )

    # Password keywords
    passwords = re.findall(
        r"\b(password|passwd|secret|token|api_key)\b",
        text,
        re.IGNORECASE
    )

    if emails:
        detected.append("Email Address")

    if phones:
        detected.append("Phone Number")

    if aadhaar:
        detected.append("Aadhaar Number")

    if cards:
        detected.append("Card Number")

    if passwords:
        detected.append("Password / Credential")

    return detected


def mask_data(text):

    text = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[EMAIL MASKED]",
        text
    )

    text = re.sub(
        r"\b[6-9]\d{9}\b",
        "[PHONE MASKED]",
        text
    )

    text = re.sub(
        r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "[AADHAAR MASKED]",
        text
    )

    text = re.sub(
        r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "[CARD MASKED]",
        text
    )

    return text


def check_data(text):

    if not text.strip():
        return (
            "No Input",
            "Enter some text",
            "NONE",
            "NONE",
            ""
        )

    detected = detect_sensitive_data(text)

    if "Aadhaar Number" in detected or \
       "Card Number" in detected or \
       "Password / Credential" in detected:

        risk = "HIGH"
        action = "BLOCK / MASK"

    elif len(detected) > 0:

        risk = "MEDIUM"
        action = "WARN / MASK"

    else:

        risk = "LOW"
        action = "ALLOW"

    protected = mask_data(text)

    prediction = (
        "SENSITIVE"
        if len(detected) > 0
        else "NON-SENSITIVE"
    )

    detected_text = (
        ", ".join(detected)
        if detected
        else "No Sensitive Data Found"
    )

    return (
        prediction,
        detected_text,
        risk,
        action,
        protected
    )


with gr.Blocks(title="Data Leakage Prevention System") as app:

    gr.Markdown(
        "# 🔐 Data Leakage Prevention System"
    )

    input_text = gr.Textbox(
        label="Enter Text",
        lines=8
    )

    btn = gr.Button(
        "Check Data Leakage"
    )

    prediction = gr.Textbox(
        label="Prediction"
    )

    detection = gr.Textbox(
        label="Detected Information"
    )

    risk = gr.Textbox(
        label="Risk Level"
    )

    action = gr.Textbox(
        label="Recommended Action"
    )

    protected = gr.Textbox(
        label="Protected Text"
    )

    btn.click(
        fn=check_data,
        inputs=input_text,
        outputs=[
            prediction,
            detection,
            risk,
            action,
            protected
        ]
    )

if __name__ == "__main__":
    print("\nStarting Data Leakage Prevention System...")
    print("Open the link shown below in your browser.")

    app.launch(
        inbrowser=True,
        share=True,
        debug=True
    )