import os
from flask import Flask
from flask_cors import CORS
from routes.analyse import analyse_bp

def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})
    app.register_blueprint(analyse_bp)

    @app.route("/")
    def index():
        return {"status": "Jester API is running", "version": "1.1"}

    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
