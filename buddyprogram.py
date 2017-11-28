#all that imports
from flask import Flask, request, session, g, redirect, url_for, abort, render_template,flash
from contextlib import closing
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateField, DateTimeField, SelectField
from wtforms.validators import InputRequired, Email, EqualTo, Length
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

import os
import sqlite3

#create application
app = Flask(__name__)
app.config['SECRET_KEY']= 'GRADSCHOOLNOLIFE'
app.config.from_object(__name__)
# app.config['SQLALCHEMY_DATABASE_URI']='sqlite:////Users/zengyh/myproject/buddyprogram.db'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:////Users/Yu/Desktop/buddy/buddyprogram.db'

db = SQLAlchemy(app)
login_manager = LoginManager() #handle user session
login_manager.init_app(app)
login_manager.login_view = 'login'





# @login_manager.user_loader
# def load_user(session_token):
#     return User.query.filter_by(session_token = session_token).first
#
# def get_id(self):
#     return unicode(self.session_token)
#
# login_manager.session_protection = "strong"

#Database

participate = db.Table('participate',
    db.Column('uid',db.Integer, db.ForeignKey('user.id')),
    db.Column('pid',db.Integer, db.ForeignKey('program.id'))
)


# config for updating intermediate table participate
###########################
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'buddyprogram.db'),
    # SECRET_KEY='development key'
    # USERNAME='liuyuci',
    # PASSWORD='default'
))
app.config.from_envvar('BUDDY_SETTINGS', silent=True)
# connect database
def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv
def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db
############################


# friend = db.Table('friend',
#     db.Column('u1id',db.Integer,db.ForeignKey('user.id')),
#     db.Column('u2id',db.Integer,db.ForeignKey('user.id'))
# )

class User(UserMixin,db.Model):
    id = db.Column (db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80),nullable=False)
    username = db.Column(db.String(15),nullable=False)
    program = db.relationship('Program',secondary=participate,backref=db.backref('participants',lazy='dynamic')) #many to many
    # buddy = db.relationship('User',secondary=friend,backref=db.backref('friends',lazy='dynamic',cascade='all, delete-orphan')) #many to many
    log = db.relationship('Dailylog',backref='user',lazy='dynamic')#one to many

    # def __init__(self,id,email,password,username):
    #     self.id=id
    #     self.email=email
    #     self.username=username
    #     self.password=password

@login_manager.user_loader #get the user object to manage
def load_user(user_id):
     return User.query.get(int(user_id))

class Program(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(80))
    activity = db.Column(db.String(80),nullable=False)
    start_date = db.Column(db.DateTime,nullable=False)
    activity_time = db.Column(db.DateTime,nullable=False)
    log = db.relationship('Dailylog',backref='programs',lazy='dynamic')#one to many
    #
    # def __init__(self,id,name,activity,start_date,activity_time):
    #     self.id=id
    #     self.name=name
    #     self.activity=activity
    #     self.start_date=start_date
    #     self.activity_time=activity_time

class Dailylog(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    date = db.Column(db.DateTime)
    checkin = db.Column(db.Boolean)
    reason = db.Column(db.Text)
    note = db.Column(db.Text)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'))
    program_id=db.Column(db.Integer, db.ForeignKey('program.id'))

    # def __init__(self, id, date, checkin, reason, note, user_id, program_id):
    #     self.id=id
    #     self.date=date
    #     self.checkin=checkin
    #     self.reason=reason
    #     self.note=note
    #     self.user_id=user_id
    #     self.program_id=program_id

#Forms
class LoginForm(FlaskForm):
    email = StringField('email', validators=[Email()])
    password = PasswordField('password', validators=[InputRequired(),Length(min=8,max=80)])
    remember = BooleanField('Keep me logged in')

@app.route('/login',methods=['GET','POST']) #form needs to write and inqury so get and post are needed
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user,remember=form.remember.data)
                return redirect(url_for('create_buddy'))
        return 'Invalid email or password'
    return render_template('login.html', form=form)

class ResigeationForm(FlaskForm):
    email = StringField('email',validators=[Email()])
    password = PasswordField('Input Password',validators=[InputRequired(),Length(min=8,max=80)])
    confirm = PasswordField('Confirm password', validators=[EqualTo('password',message='Password does not match')])
    username = StringField('username',validators=[InputRequired(),Length(min=4,max=15)])
    accept_tos = BooleanField('I accept the Term of Service',validators=[InputRequired()])

@app.route('/register',methods=['GET','POST'])
def register():
    form = ResigeationForm(request.form)
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')#for security, encode plain text password
        new_user = User(email=form.email.data, password=hashed_password,username=form.username.data)
        db.session.add(new_user)
        db.session.commit()
        # close the db.session
        db.session.close()
        #flash('Great job'+form.username.data+', you are one step closer to healthier life style!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

# @app.route('/checkin')
# def checkin():


# create buddy
class CreateForm(FlaskForm):
    name = StringField('Program Name', validators=[InputRequired(),Length(min=1,max=80)])
    activity = StringField('What you wanna do', validators=[InputRequired(),Length(min=1,max=80)])
    start_date = DateField('Start Date', format='%Y-%m-%d', default=datetime.today)
    activity_time = DateTimeField('Activity Time', format='%H:%M:%S', default=datetime.today)
    buddy = SelectField('Buddy', choices=[('Yu Liu', 'Yu Liu'), ('Bicheng Xu', 'Bicheng Xu'), ('Yihui Zeng', 'Yihui Zeng'), ('Hillary Clinton', 'Hillary Clinton')])

@app.route('/create', methods=['GET','POST'])
def create_buddy():
    form = CreateForm(request.form)
    if request.method == 'POST' and form.validate():
        # insert to program
        new_program = Program(name=form.name.data, activity=form.activity.data, start_date=form.start_date.data, activity_time=form.activity_time.data)
        db.session.add(new_program)
        db.session.commit()
        # close db.session
        db.session.close()

        # insert to intermediate table participate
        db1 = get_db()
        program_current = Program.query.order_by(Program.id.desc()).first()
        db1.execute('insert into participate (uid, pid) values (?, ?)',
                 [current_user.id, program_current.id])
        db1.commit()
        
        flash('New buddy program created!')
        # add session['created']
        session['created'] = True

        return redirect(url_for('home'))
    return render_template('create.html',form=form)



@app.route('/home')
@login_required
def home():
    program_current = Program.query.filter(Program.participants.any(id=current_user.id)).order_by(Program.id.desc()).first() #select the most current program
    logs = Dailylog.query.filter_by(user_id = current_user.id, program_id = program_current.id )
    return render_template('home.html',name=current_user.username,time=datetime.now(),logs=logs)

@app.route('/logout')
@login_required
def logout():
    # pop session['created']
    session.pop('created', None)
    logout_user()
    return redirect(url_for('login'))





if __name__ == '__main__':
    app.run(debug=True)
