# AegisQ Run Commands

## Backend — Terminal 1
```bash
cd ~/Desktop/aegisq-project/backend
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m uvicorn main:app
```

For future starts after the first install:
```bash
cd ~/Desktop/aegisq-project/backend
source venv/bin/activate
python3 -m uvicorn main:app
```

## Frontend — Terminal 2
```bash
cd ~/Desktop/aegisq-project/frontend
npm install
npm run dev
```

## Risk Forecast ML — Terminal 3 (only when retraining)
```bash
cd ~/Desktop/aegisq-project/backend
source venv/bin/activate
python3 ml/train.py
```

## Attack-Loss ML — only when retraining after updating incidents
```bash
cd ~/Desktop/aegisq-project/backend
source venv/bin/activate
python3 ml/train_attack_loss.py
```

Do not run reset_db.py during normal startup; the packaged database already contains the real dataset.
