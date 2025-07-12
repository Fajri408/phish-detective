import logging
from flask import Flask
from app.api.v1.routes import api_v1_blueprint
from dotenv import load_dotenv

load_dotenv()


def create_app():
    app = Flask(__name__)

    logging.basicConfig()
    # Register blueprint
    app.register_blueprint(api_v1_blueprint, url_prefix="/api/v1")

    return app
