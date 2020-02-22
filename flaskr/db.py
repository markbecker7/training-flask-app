import sqlite3

import click
from flask import current_app, g
from flask.cli import with_appcontext

# Returns the database object
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


# Closes the database object
def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()


# Executes the Schema.sql script to initialize database
def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))


# How init_db is called from command line
@click.command('init-db')
@with_appcontext
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')


#Do not know what this does actually
def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)



