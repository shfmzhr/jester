import os

from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from routes.analyse import analyse_bp, MAX_EMAIL_CHARS


def create_app():
    app = Flask(__name__)

    # Reject oversized request bodies at the WSGI layer (cost / DoS guard).
    app.config["MAX_CONTENT_LENGTH"] = MAX_EMAIL_CHARS + 5_000

    # Trust one proxy hop (Railway) so X-Forwarded-For is read correctly.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    # Restrict CORS. Chrome extensions call with a chrome-extension:// origin;
    # the default keeps any origin working for local dev, but you can lock it
    # down by setting ALLOWED_ORIGINS to a comma-separated list.
    origins_env = os.environ.get("ALLOWED_ORIGINS", "").strip()
    origins = [o.strip() for o in origins_env.split(",") if o.strip()] or "*"
    CORS(app, resources={r"/analyse": {"origins": origins},
                         r"/status": {"origins": origins}})

    app.register_blueprint(analyse_bp)

    @app.route("/")
    def index():
        return {"status": "Jester API is running"}

    return app


if __name__ == "__main__":
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("phsihshsishs")):
        print("WARNING: ANTHROPIC_API_KEY is not set. /analyse will return an error.")
    app = create_app()
    app.run(debug=False)
