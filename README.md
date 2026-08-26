# Email Threat Intel Platform

AI-Powered Email Threat Detection Platform backend.

## Setup Instructions

1. Install dependencies:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```
2. Set up environment:
   ```bash
   cp .env.example .env
   ```
3. Start services:
   ```bash
   docker-compose up -d
   ```
4. Run server:
   ```bash
   cd backend
   uvicorn app.main:app --reload
   ```
