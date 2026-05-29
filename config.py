"""Configuration for IR AI Agent - OpenAI Version"""

# OpenAI API
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY"
OPENAI_MODEL = "gpt-4o-mini"

# EMAIL
EMAIL_CONFIG = {
    "sender": "vycliper@gmail.com",
    "password": "vyclipeR987@",  # Ganti dengan password app
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "recipient": "envyyyjoy@gmail.com"
}

# TELEGRAM (skip dulu)
TELEGRAM_CONFIG = {
    "bot_token": "skip",
    "chat_id": "skip"
}

print("✅ Configuration loaded!")