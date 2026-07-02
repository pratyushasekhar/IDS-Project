"""from server import create_app
from flask import redirect, render_template, url_for

app = create_app()

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
"""

from server import create_app
from server.ids_engine import start_ids_engine

app = create_app()
start_ids_engine()

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=False, use_reloader=False)
