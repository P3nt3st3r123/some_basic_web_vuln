from flask import Flask, request, render_template, redirect, url_for, flash, session, abort, safe_join, send_file
from flask_sqlalchemy import SQLAlchemy
# https://stackoverflow.com/questions/15871391/implementing-flask-login-with-multiple-user-classes
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from Crypto import Random
from Crypto.Hash import HMAC,SHA256
import base64
import random,time,smtplib,ssl,os
# https://wtforms.readthedocs.io/en/2.3.x/forms/
# https://stackoverflow.com/questions/22084886/add-a-css-class-to-a-field-in-wtform
# https://stackoverflow.com/questions/22024661/jinja2-template-not-rendering-if-elif-else-statement-properly
from flask_wtf import FlaskForm
## https://github.com/mbr/flask-bootstrap
# from flask_bootstrap import Bootstrap
from colorama import init


# IP_SERVER,PORT = '127.0.0.1',9000
IP_SERVER,PORT = 'localhost',9000
smtp_host,smtp_port,smtp_username,smtp_pass = 'smtp.gmail.com',587,'[DETACH]',"[DETACH]"

app = Flask(__name__)
app.config.from_object('config')
key = Random.new().read(32)# 32 bytes
data_base = SQLAlchemy(app)
login_manager = LoginManager(app)
DIR = os.path.dirname(os.path.realpath(__file__))

def side_channel_compare(data1,data2):
	if len(data1)!=len(data2):return False
	for a,b in zip(data1,data2):
		if a!=b:return False
	return True

def send_mail(to_email,header,body):
	try:
		ssl._create_default_https_context = ssl._create_unverified_context
		context = ssl.create_default_context()
		server = smtplib.SMTP(smtp_host,smtp_port)
		server.starttls(context=context)
		server.ehlo()
		server.login(smtp_username,smtp_pass)
		
		orginal_from = 'vulnerable web app'
		subject = f"Subject: {header}"
		the_message=f'''From: {orginal_from}\nTo: {to_email}\n{subject}\n\n{body}'''
		server.sendmail(orginal_from, to_email, the_message)
		server.quit()
	except Exception as E:
		print("[-]Error mail: ",E)
		return False
	return True
# https://stackoverflow.com/questions/10059345/sqlalchemy-unique-across-multiple-columns
# https://stackoverflow.com/questions/9667138/how-to-update-sqlalchemy-row-entry
class User(UserMixin, data_base.Model):
	id = data_base.Column(data_base.Integer, primary_key=True)
	username = data_base.Column(data_base.String(64), index=True)
	email = data_base.Column(data_base.String(64),unique=True)
	password_hash = data_base.Column(data_base.String(128))
	
	@property
	def password(self):
		# raise AttributeError('password is not a readable attribute')
		return self.password_hash
	
	@password.setter
	def password(self, password):
		self.password_hash = HMAC.new(password.encode(),key).hexdigest()
	
	def verify_password(self, password):
		password = HMAC.new(password.encode(),key).hexdigest()
		return side_channel_compare(self.password_hash,password)

class PwdReset(UserMixin, data_base.Model):
	id = data_base.Column(data_base.Integer, primary_key=True)
	email = data_base.Column(data_base.String(64),unique=True)
	# selector = data_base.Column(data_base.String(16))
	token = data_base.Column(data_base.String(64),unique=True)
	expire = data_base.Column(data_base.Integer)
	

# https://stackoverflow.com/questions/10695093/how-to-implement-user-loader-callback-in-flask-login
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
	"""Registration form."""
	email = EmailField('Email', validators=[DataRequired(), Email()])
	username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
	password = PasswordField('Password', validators=[DataRequired()])
	password_again = PasswordField('Password again', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Register')

class LoginForm(FlaskForm):
	"""Login form."""
	username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Login')

class ForgetPassword(FlaskForm):
	email = EmailField('Email', validators=[DataRequired(), Email()])
	submit = SubmitField('Get Token Link')
	
class ResetPassword(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Reset')

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
	"""User registration route."""
	if current_user.is_authenticated:
		# if user is logged in we get out of here
		return redirect(url_for('index'))
	form = RegisterForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is not None:
			flash('Username already exists.')
			return redirect(url_for('register'))
		user_ = User.query.filter_by(email=form.email.data).first()
		if user_ is not None:
			flash('Email already exists.')
			return redirect(url_for('register'))
		print(form.username.data,form.email.data,form.password.data.encode("raw_unicode_escape"))
		user = User(username=form.username.data, email=form.email.data, password=form.password.data)
		data_base.session.add(user)
		data_base.session.commit()
		
		## setup cookie name
		# session['username'] = user.username
		return redirect(url_for('login'))
	return render_template('register.html',form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
	"""User login route."""
	if current_user.is_authenticated:
		# if user is logged in we get out of here
		return redirect(url_for('index'))
	form = LoginForm();
	'''
	print(dir(form))
	print(form.csrf_token().type)
	# print(form.populate_obj())
	print(form.process())
	print(form.username())
	print(form.submit())
	print(form.validate())
	print([(a,b) for a,b in form._fields.items()])
	print(form._fields['username'])
	print(form._fields['username'].type)
	'''
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is None or not user.verify_password(form.password.data):
			flash('Invalid username, password.')
			return redirect(url_for('login'))
		# log user in
		login_user(user) ## => current_user have all attribute of user
		# flash('You are now logged in!') ## may be don't get this signal
		return redirect(url_for('index'))
	return render_template('login.html', form=form)

@app.route('/profile')
@login_required
def profile():
	## https://blog.nvisium.com/injecting-flask
	## render_template is safe but render_template_string not safe
	return render_template('profile.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))

# https://datatracker.ietf.org/doc/html/rfc2617
# https://www.reddit.com/r/flask/comments/g0e0ap/flask_wtf_vs_wtforms/
# https://stackoverflow.com/questions/23039734/flask-login-password-reset#:~:text=Flask%2DSecurity%20sends%20an%20email,a%20specified%20amount%20of%20time.
# https://uniwebsidad.com/libros/explore-flask/chapter-12/forgot-your-password
# https://dev.to/paurakhsharma/flask-rest-api-part-5-password-reset-2f2e
# https://gist.github.com/gitrajit/a8b631eab1data_base8f280e149a0bcaa14d3e
@app.route('/forget', methods=['GET', 'POST'])
def forget_password():
	if current_user.is_authenticated:
		# if user is logged in we get out of here
		return redirect(url_for('index'))
	form = ForgetPassword()
	# print(form.email)
	# print(form.validate_on_submit())
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()	
		if user is None:
			flash('Email not found')
			return redirect(url_for('forget_password'))
		## send link reset password
		# selector = random.getrandbits(64).to_bytes(8,'big').hex()
		token = random.getrandbits(512).to_bytes(64,'big').hex()
		expire = int(time.time()) + 3600 
		
		# http://flask.pocoo.org/docs/quickstart/#redirects-and-errors
		# https://stackoverflow.com/questions/14343812/redirecting-to-url-in-flask
		# url = f'http://localhost/forget/{selector}/{token}/'
		url = f'http://localhost:{PORT}/reset/{token}/'
		# url = f"{url_for('index')}{token}/"
		# https://stackoverflow.com/questions/27158573/how-to-delete-a-record-by-id-in-flask-sqlalchemy
		tmp = PwdReset.query.filter_by(email=user.email)
		if tmp: tmp.delete()
		# pwd_reset = PwdReset(email=user.email,selector=selector,token=token,expire=expire)
		pwd_reset = PwdReset(email=user.email,token=token,expire=expire)
		data_base.session.add(pwd_reset)
		data_base.session.commit()
		
		header = 'Password reset'
		message = f'We receive your reset password request. You can ignore this message if you don\'t want to reset password\n'
		message += f'This is your reset password link:\n{url}'
		
		flash("Check your email account") if send_mail(user.email,header,message) else flash("Something go wrong")
		# return redirect(url_for('login'))
	return render_template('forget.html', form=form)

# https://stackoverflow.com/questions/41492721/in-python-flask-how-do-you-get-the-path-parameters-outside-of-the-route-functio/41493168
# http://flask.pocoo.org/docs/api/#flask.Request.view_args
@app.route("/reset/<token>/",methods=['GET', 'POST'])
def reset_password(token):
	if current_user.is_authenticated:
		# if user is logged in we get out of here
		return redirect(url_for('index'))
	# selector = request.view_args.get('selector')
	token = request.view_args.get('token')
	if not token:
		flash('Could not validate your request')
		return redirect(url_for('forget_password'))
	
	# pwdreset = PwdReset.query.filter_by(selector=selector,token=token).first()
	pwdreset = PwdReset.query.filter_by(token=token).first()
	if pwdreset is None:
		flash('Token not validate')
		return redirect(url_for('forget_password'))
		
	if pwdreset.expire - int(time.time())<0:
		flash('Token expire')
		data_base.session.delete(pwdreset)
		data_base.session.commit()
		return redirect(url_for('forget_password'))
	
	form = ResetPassword()
	if form.validate_on_submit():
		user = User.query.filter_by(email=pwdreset.email).first()
		# user.password(form.password.data)
		# https://stackoverflow.com/questions/27158573/how-to-delete-a-record-by-id-in-flask-sqlalchemy
		user.password = form.password.data
		# pwdreset.delete()
		data_base.session.delete(pwdreset)
		data_base.session.commit()
		flash('Password change successful')
		return redirect(url_for('login'))
		
	return render_template('reset.html',form=form,token=token)

## download file feature
## methods=['GET']
@app.route('/download')
@login_required
def download():
	file_get,hash_auth = request.args.get('file'),request.args.get('hash')
	list_file_pub = ['report.txt','another_file.txt']
	only_admin_file = ['report.txt']
	# print(file_get,hash_auth)
	# print(request.__dict__)
	# print(request.get_data())
	# print(request.view_args)
	# print(request.query_string)
	# print(request.full_path)
	# print(request.pragma)
	# print(dir(request))
	file_url_set = {file:f'{url_for("index")}download?file={base64.b64encode(file.encode("Latin1")).decode("Latin1")}&hash={("NOPE" if file in only_admin_file and current_user.username!="Admin" else SHA256.new(key+file.encode()).hexdigest())}' for file in list_file_pub}
	if file_get and hash_auth:
		message = b''
		file_get = base64.b64decode(file_get)
		print(file_get)
		## damnit decode/encode mechanism corrupt filename 
		## encode wrong data because of unquote utf-8 => error; repalce char
		# print(file_get.encode('raw_unicode_escape'))
		try:
			# if side_channel_compare(hash_auth,SHA256.new(key+file_get.encode()).hexdigest()):
			if side_channel_compare(hash_auth,SHA256.new(key+file_get).hexdigest()):
				# https://flask.palletsprojects.com/en/2.0.x/api/
				return send_file(os.path.normpath(f"{DIR}/download_file/{file_get.decode('Latin1')}"),mimetype="text/plain")
			else: 
				flash("Hash not valid")
				return render_template('download.html',files=file_url_set)
		except Exception as E: 
			flash(f"{E}")	
			return render_template('download.html',files=file_url_set)
		return (message, 200)
	return render_template('download.html',files=file_url_set)

@login_required
@app.route('/admin')
def db_log():
	if current_user.username!="Admin":
		return redirect(url_for('index'))
	# https://stackoverflow.com/questions/2633218/how-can-i-select-all-rows-with-sqlalchemy/26217436
	# https://stackoverflow.com/questions/11530196/flask-sqlalchemy-query-specify-column-names
	info_users = User.query.with_entities(User.email, User.username, User.password_hash)
	return render_template('db_user.html',info_users=info_users)
		
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html')

if __name__=='__main__':
	# worave8164@beydent.com
	# admin@admin.com	
	init(autoreset=True)
	
	# create database tables if they don't exist yet
	data_base.create_all()
	password = Random.new().read(16).hex();print(password)
	user = User(username="Admin", email="Admin@Admin.Admin", password=password)
	data_base.session.add(user)
	data_base.session.commit()
	app.run(host = IP_SERVER, port = PORT, debug = True)
