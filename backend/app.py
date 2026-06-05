from flask import Flask
from flask_cors import CORS
from routes.analyse import analyse_bp

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.register_blueprint(analyse_bp)

    @app.route("/")
    def index():
        return {"status": "PhishGuard API is running"}

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
