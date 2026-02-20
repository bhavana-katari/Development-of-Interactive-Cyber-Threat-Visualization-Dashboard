# cyber-threat-dashboard/config.py
import os

# Simple config - we'll add dotenv later
RAPIDAPI_KEY = os.getenv('RAPIDAPI_KEY', '2df125379fmshead16450789752ap17eabcjsn102865eda963')
RAPIDAPI_HOST = 'global-cyberattacks-database.p.rapidapi.com'

# If no API key, use sample data
USE_SAMPLE_DATA = RAPIDAPI_KEY == ''