<<<<<<< HEAD
from app import app, socketio

# Azure App Service / gunicorn entry.
# Socket.IO: gunicorn --worker-class eventlet -w 1 wsgi:app

application = app

__all__ = ["app", "application", "socketio"]
=======
from app import app, socketio

# Azure App Service / gunicorn entry.
# Socket.IO: gunicorn --worker-class eventlet -w 1 wsgi:app

application = app

__all__ = ["app", "application", "socketio"]
>>>>>>> 5aeceaef23432e326a4511ac1320d8e8a6060045
