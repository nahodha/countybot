from datetime import datetime
from flask import Flask, make_response, redirect, render_template, request, url_for, flash
from flask_bootstrap import Bootstrap
from flask_login import current_user, login_required, login_user, logout_user, LoginManager, UserMixin, AnonymousUserMixin
from flask_migrate import Migrate, MigrateCommand
from flask_moment import Moment
from flask_script import Manager, Shell
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import Form
# from sqlalchemy.orm.exc import DetachedInstanceError, MultipleResultsFound
from wtforms import (BooleanField, PasswordField, StringField, SubmitField)
from wtforms.validators import EqualTo, Length, Regexp, Required
from wtforms import ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from keys import *
import hashlib
import os


base_dir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DEV_DATABASE_URL') or\
        'postgresql://' + DB_USER + ':' + DB_PASS + '@' + DB_HOST + \
        ':' + str(DB_PORT) + '/' + DB_NAME
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'hard to guess string'

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
manager = Manager(app)
migrate = Migrate(app, db)
moment = Moment(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

class Permission:
    '''Specify permissions in hex which allow or deny users certain actions.
    Each bit represents a certain permission.'''
    FOLLOW = 0x01
    COMMENT = 0X02
    WRITE_ARTICLES = 0X04
    MODERATE_COMMENTS = 0X08
    ADMINISTER = 0x80


class Role(db.Model):
    '''Store user roles in db with availability of extensions for other types
    roles in future. Each role allows a user to perform certain activities.'''
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES |
                     Permission.MODERATE_COMMENTS, True),
            'Administrator': (0xff, False) # Admin gets all permissions default
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))


    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role_id is None:
            if self.role_id is None:
                self.role_id = Role.query.filter_by(default=True).first().id

    @property
    def password(self):
        '''Raise an attribute error when someone tries to read the password.'''
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        '''Generate a password hash that will be stored instead of the original
        password.'''
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        '''Verify the user password using the check_password hash method.'''
        return check_password_hash(self.password_hash, password)

    def can(self, permissions):
        '''Utility method to check whether a user has certain Permissions.'''
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        '''Utility method to check whether a user is an administrator.'''
        return self.can(Permission.ADMINISTER)

    def ping(self):
        '''Check whether user is online for use in views.'''
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def __repr__(self):
        return '<User %r>' % self.username



class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


# Flask_login requires a callback to load a user using the given identifier
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Transaction(db.Model):
    __tablename__ = 'transactions'
    transaction_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey('users.id'))
    block = db.Column(db.String(256), unique=True)
    timestamp = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)
    amount = db.Column(db.Integer, default=50)
    location = db.Column(db.String(128))

    def __init__(self, user, location):
        self.user = user
        self.location = location
        self.block = generate_password_hash(str(self.amount) + str(self.transaction_id) + \
            str(self.location))
        print self.block

    def __repr__(self):
        return '<Transaction %r>' % self.block


class LoginForm(Form):
    username = StringField('Username', validators=[
            Required(), Length(1, 64), Regexp(
                '^[A-Za-z][A-Za-z0-9_.]*$', 0,
                'Usernames must have only letters, numbers, dots, or underscores'
                )])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(Form):
    username = StringField('Username', validators=[
            Required(), Length(1, 64), Regexp(
                '^[A-Za-z][A-Za-z0-9_.]*$', 0,
                'Usernames must have only letters, numbers, dots, or underscores'
                )])
    password = PasswordField('Password', validators=[Required(),
                EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm Password',validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already registered!')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use!')


class PaymentForm(Form):
    location = StringField('Location', validators=[Required(), Length(1, 64)])
    submit = SubmitField('Buy Token')


def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)


manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('payment'))
        flash('Invalid username or Password!')
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out!')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(username=form.username.data,
                    password=form.password.data)
        try:
            db.session.add(user)
            db.session.commit()
            flash('You can now login.')

        # except (AttributeError, DetachedInstanceError, IntegrityError, MultipleResultsFound, Exception) as e:
        except Exception as e:
            db.session.rollback()
            flash('Something happened try again.')
            return redirect(url_for('register'))


        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@login_required
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    form = PaymentForm()

    if form.validate_on_submit():
        transaction = Transaction(user=current_user.id, location=form.location.data)
        try:
            db.session.add(transaction)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash('Something happened try again.')
            print 'Failed'
            return redirect(url_for('payment'))

        return redirect(url_for('dashboard'))

    return render_template('payment.html', form=form)

@login_required
@app.route('/dashboard', methods=['GET'])
def dashboard():
    transactions = Transaction.query.filter_by(user=current_user.id)
    return render_template('dashboard.html', transactions=transactions)


@app.route('/ussd-pay/', methods=['GET', 'POST'])
def ussd_pay():
    if request.method == 'POST':
        text = request.values.get('text', None)
        phonenumber = request.values.get('phonenumber')

        if text == '':
            response = 'CON Welcome to CountyBot how may we help you\n'
            response += '1. Register'
            response += '2. Make Payment'
            response += '3. Change Location'

        elif text == '1':
            response = 'CON Enter your name'

        elif text == '2':
            response = 'CON Enter amount payment'

        elif text == '3':
            response = 'CON Enter your new locaion.\n Additional charges will be incurred.'
        else:
            response = 'END goodbye'

        final_response = make_response(response, 200)
        final_response.headers['Content-Type'] = 'text/plain'
        return final_response



    else:
        return 'Hello There, you\'re not supposed to be here'



@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    manager.run()
