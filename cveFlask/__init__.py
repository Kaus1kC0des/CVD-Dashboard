from dotenv import load_dotenv

load_dotenv()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

# Initialize Flask application
app = Flask(__name__, template_folder='templates', static_folder='static')

# Load secret key from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Load SQLAlchemy database URI from environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)

# Import routes to register them with the Flask app
from cveFlask import routes
