# -*- coding:utf-8 -*-
import os
from flask import Flask, render_template, redirect, request, url_for, g, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, UserMixin, login_user

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'database.db')
app.config['SECRET_KEY'] = 'hard to guess'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    xm = db.Column(db.String,unique=True)
    password_hash = db.Column(db.String(128))
    orders = db.relationship('Order', backref='user')


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


class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_date = db.Column(db.Date)
    orered = db.Column(db.Integer)
    order_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class LoginForm(FlaskForm):
    username = StringField(u'用户名', validators=[Required()],
                           render_kw={'placeholder': u'用户名'})
    password = PasswordField(u'密码', validators=[Required()],
                             render_kw={'placeholder': u'密码'})
    submit = SubmitField(u'登录')


class RegistrationForm(FlaskForm):
    username = StringField(u'用户名',validators=[Required()])
    xm = StringField(u'姓名',validators=[Required()])
    password = PasswordField(u'密码',validators=[Required(),EqualTo(u'password1',message='密码不一致')])
    password1 = PasswordField(u'确认密码',validators=[Required()])
    submit = SubmitField(u'注册')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            return redirect(url_for('order',username=user.username))
    return render_template('login.html', form=form)


@app.route('/order/<username>')
@login_required
def order(username):
    user = User.query.filter_by(username=username).first()
    return render_template('order.html',xm=user.xm)


@app.route('/add_order', methods=['GET','POST'])
@login_required
def add_order():
    pass

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,
                    xm=form.xm.data,
                    password=form.password.data)
        db.session.add(user)
        flash('注册成功')
        return redirect(url_for('register'))
    return render_template('register.html',form=form)

if __name__ == '__main__':
    app.run(debug=True)
