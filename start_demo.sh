#!/bin/bash

echo "🚀 Starting NEXUS SOC Defense System..."

# 1. Activate the virtual environment
if [ -d ".venv" ]; then
    source .venv/bin/activate
    echo "✅ Virtual environment activated."
fi

# 2. Set the secure environment variable (Using single quotes for Mac!)
export SOC_MASTER_SECRET='super_secret_evaluator_key_2024!'
echo "✅ Secure master key loaded."

# 3. Start the Frontend in the background
echo "🖥️  Starting Frontend on http://localhost:3000..."
cd frontend_engineer || exit
python3 -m http.server 3000 &
FRONTEND_PID=$!
cd ..

# 4. Start the Backend
echo "⚙️  Starting FastAPI Backend..."
cd backend_engineer || exit

# Initialize database if it doesn't exist yet
if [ ! -f "nexus_soc.db" ]; then
    echo "🗄️  Creating new SQLite database..."
    python3 init_db.py
fi

# Run the backend server (This takes over the terminal window)
python3 main_sqlite.py

# 5. Clean up when the user hits Ctrl+C
kill $FRONTEND_PID
echo "🛑 NEXUS SOC shut down safely."