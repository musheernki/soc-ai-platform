from app import app, socketio

# Azure App Service / gunicorn entry.
# Socket.IO: gunicorn --worker-class eventlet -w 1 wsgi:app

application = app

__all__ = ["app", "application", "socketio"]
