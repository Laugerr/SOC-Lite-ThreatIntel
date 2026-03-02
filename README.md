# 🛡 SOC Lite — Threat Intel & Risk Scoring Dashboard (Simulated)

A Streamlit web app that simulates threat intelligence enrichment for IPs/domains/URLs and generates a SOC-style risk score + alert output.

✅ No external APIs • No keys • Always works in demo

---

## 🚀 Live Demo [Threat Intel & Risk Scoring Dashboard](https://soc-lite-threatintel-ucwfqkcasvhtnqq6oskscg.streamlit.app/)

---

## ✨ Features
- 🔎 Analyze IP / Domain / URL
- 🧠 Simulated threat intel enrichment (local datasets)
- 📈 Risk scoring engine (0–100) + severity levels
- 🧾 SIEM-style JSON alert output + download
- 📊 Dashboard: history, metrics, risk distribution

---

## 🧱 Tech Stack
- Python
- Streamlit
- Pandas

---

## ▶️ Run Locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## 📁 Project Structure

```
soc-lite-threatintel/
├─ app.py
├─ core/
├─ data/
├─ requirements.txt
└─ .streamlit/
```

## ⚠️ Disclaimer
This project is **fully simulated** and intended for learning / portfolio demonstration only.
