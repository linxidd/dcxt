# -*- coding:utf-8 -*-
import os
import datetime
import json
from flask import Flask, render_template, redirect, request, url_for, g, flash, jsonify, Markup
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user

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
    ordered = db.Column(db.String)
    order_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Article(db.Model):
    __tablename__ = 'article'
    id = db.Column(db.Integer, primary_key=True)
    recipe_date = db.Column(db.Date)
    recipe_content = db.Column(db.String)


class LoginForm(FlaskForm):
    username = StringField(u'用户名', validators=[Required()],
                           render_kw={'placeholder': u'用户名'})
    password = PasswordField(u'密码', validators=[Required()],
                             render_kw={'placeholder': u'密码'})
    submit = SubmitField(u'登录')


class RegistrationForm(FlaskForm):
    username = StringField(u'用户名',validators=[Required()],render_kw={'placeholder': u'用户名'})
    xm = StringField(u'姓名',validators=[Required()],render_kw={'placeholder': u'姓名'})
    password = PasswordField(u'密码',validators=[Required(),EqualTo(u'password1',message='密码不一致')],render_kw={'placeholder': u'密码'})
    password1 = PasswordField(u'确认密码',validators=[Required()],render_kw={'placeholder': u'重复密码'})
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
    order_exist_br = Order.query.filter(Order.user==user,Order.ordered==u'早餐',Order.order_date==datetime.date.today()+datetime.timedelta(days=1)).first()
    order_exist_lc = Order.query.filter(Order.user==user,Order.ordered==u'午餐',Order.order_date==datetime.date.today()).first()
    order_exist_dn = Order.query.filter(Order.user==user,Order.ordered==u'晚餐',Order.order_date==datetime.date.today()).first()
    if order_exist_br:
        breakfirst = order_exist_br.ordered
    else:
        breakfirst = ''
    if order_exist_lc:
        lunch = order_exist_lc.ordered
    else:
        lunch = ''
    if order_exist_dn:
        dinner = order_exist_dn.ordered
    else:
        dinner = ''
    return render_template('order.html',xm=user.xm,breakfirst=breakfirst,lunch=lunch,dinner=dinner)

@app.route('/add_order', methods=['GET','POST'])
@login_required
def add_order():
    ordered = request.form.get('ordered','')
    date = datetime.date.today()
    time = datetime.datetime.now()
    username = request.form.get('username','')
    user = User.query.filter_by(username=username).first()
    if ordered == u'早餐':
        date = date + datetime.timedelta(days=1)
    order_exist = Order.query.filter(Order.order_date==date,Order.ordered==ordered,Order.user==user).first()
    if order_exist:
        return jsonify(ok=False)
    else:
        if ordered == u'早餐':
            if time.hour<17:
                order = Order(order_date=date,
                      ordered = ordered,
                      user = user
                      )
                db.session.add(order)
            else:
                return jsonify(ok=False)
        elif ordered == u'午餐':
            if time.hour<9:
                order = Order(order_date=date,
                      ordered = ordered,
                      user = user
                      )
                db.session.add(order)
            else:
                return jsonify(ok=False)
        else:
            if time.hour<15:
                order = Order(order_date=date,
                      ordered = ordered,
                      user = user
                      )
                db.session.add(order)
            else:
                return jsonify(ok=False)
    try:
        db.session.commit()
        return jsonify(ok=True)
    except:
        return jsonify(ok=False)


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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return  redirect(url_for('login'))


@app.route('/nimencaibudao')
def jiuburangnicai():
    date = datetime.date.today()
    time = datetime.datetime.now()
    order_exist_lc = Order.query.filter(Order.ordered==u'午餐',Order.order_date==date).all()
    order_exist_dn = Order.query.filter(Order.ordered==u'晚餐',Order.order_date==date).all()
    if time.hour<8:
        order_exist_br = Order.query.filter(Order.ordered==u'早餐',Order.order_date==date).all()
        return render_template('admin.html',ordered_br=len(order_exist_br),ordered_lc=len(order_exist_lc),ordered_dn=len(order_exist_dn),riqi=date.strftime('%Y-%m-%d'),riqi1=date.strftime('%Y-%m-%d'),br_username=order_exist_br,ln_username=order_exist_lc,dn_username=order_exist_dn)
    else:
        order_exist_br = Order.query.filter(Order.ordered==u'早餐',Order.order_date==date+datetime.timedelta(days=1)).all()
        return render_template('admin.html',ordered_br=len(order_exist_br),ordered_lc=len(order_exist_lc),ordered_dn=len(order_exist_dn),riqi=(date+datetime.timedelta(days=1)).strftime('%Y-%m-%d'),riqi1=date.strftime('%Y-%m-%d'),br_username=order_exist_br,ln_username=order_exist_lc,dn_username=order_exist_dn)


@app.route('/editor')
def editor():
    return render_template('ueditor.html')


@app.route('/upload/', methods=['GET', 'POST'])
def upload():
    result = {}
    action = request.args.get('action')
    with open(os.path.join(os.getcwd(), 'static', 'ueditor', 'php',
                           'config.json')) as fp:
        try:
            CONFIG = json.loads(re.sub(r'\/\*.*\*\/', '', fp.read()))
        except:
            CONFIG = {}
    if action == 'config':
        result = json.dumps(CONFIG)
        return result
    else:
        date = datetime.date.today()
        article = Article(recipe_date=date,recipe_content=request.form['editorValue'])
        db.session.add(article)
        db.session.commit()
        return render_template('article.html',
                               article_content=Markup(
                                   request.form['editorValue']))


@app.route('/recipe/')
def recipe():
    article_content = Article.query.order_by(Article.recipe_date.desc()).first()
    return render_template('article.html',
                               article_content=Markup(
                                   article_content.recipe_content))

if __name__ == '__main__':
    app.run(debug=True)
