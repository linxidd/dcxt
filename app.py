# -*- coding:utf-8 -*-
from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'hard to guess'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def __repr__(self):
        return '<User %r>' % self.username

    @property
    def password(self):
        raise AttributeError('Not readable!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class LoginForm(FlaskForm):
    username = StringField(u'用户名',validators=[Required()])
    password = PasswordField(u'密码',validators=[Required()])
    submit = SubmitField(u'登录')

@app.route('/', methods=['GET','POST'])
def hello():
    form = LoginForm()
    return render_template('login.html', form=form)

if __name__ == '__main__':
  app.run(debug=True)