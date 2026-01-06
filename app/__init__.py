from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY="dev-change-me",
    )

    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app
