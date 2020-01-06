import os
from flask import render_template, url_for, flash, redirect, request, session
from flaskProject import app, db, bcrypt, mail
from flaskProject.forms import (RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm)
from flaskProject.models import User
from flask_login import login_user, current_user, logout_user, login_required, login_manager
from flask_mail import Message
from werkzeug.utils import secure_filename
import pandas as pd

ALLOWED_EXTENSIONS = {'csv'}

db.create_all()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegistrationForm(request.form)
    if request.method == 'POST':
        if register_form.validate():
            email = request.form.get('email')
            password = request.form.get('password')
            username = request.form.get('username')
            existing_user = User.query.filter_by(email=email).first()
            if existing_user is None:
                user = User(username=username, email=email,
                            password=bcrypt.generate_password_hash(password))
                db.session.add(user)
                db.session.commit()
                login_user(user)
                return redirect(url_for('home'))
            flash('A user already exists with that email address.')
            return redirect(url_for('register'))
    return render_template('/register.html',
                           title='Create an Account',
                           form=RegistrationForm())


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if request.method == 'POST':
        if login_form.validate():
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user:
                if user.check_password(password=password):
                    login_user(user)
                    next = request.args.get('next')
                    return redirect(next or url_for('home'))
        flash('Invalid username/password combination')
        return redirect(url_for('login'))
    return render_template('login.html',
                           form=LoginForm())


@app.route('/logout')
def logout():
    logout_user()
    return redirect((url_for('home')))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='alertsmogowyvba@gmail.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_token', token=token, _external=True)}
     If you did not make this request then simply ignore this email and no changes will be made.
     '''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been send with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Your password has been updated  ! You are now able to log in!', 'success')
        return redirect((url_for('login')))
    return render_template('reset_token.html', title='Reset Password', form=form)


@app.route("/upload", methods=['GET', 'POST'])
def upload():
    if 'file' in session:
        return redirect(url_for('table'))
    else:
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            sep = request.form.get('Sep')
            enc = request.form.get('Enc')
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                session['file'] = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                session['sep'] = sep
                session['enc'] = enc
                session['filename'] = session['file'][session['file'].rfind('/') + 1:]
                return redirect(url_for('table'))
            elif file and not allowed_file(file.filename):
                flash('Not supported format')
                return redirect(request.url)
        return render_template("upload.html")


@app.route("/upload_back", methods=['GET', 'POST'])
def upload_back():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        sep = request.form.get('Sep')
        enc = request.form.get('Enc')
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            session['file'] = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            session['sep'] = sep
            session['enc'] = enc
            session['filename'] = session['file'][session['file'].rfind('/') + 1:]
            return redirect(url_for('table'))
        elif file and not allowed_file(file.filename):
            flash('Not supported format')
            return redirect(request.url)
    return render_template("upload.html")


@app.route('/table')
def table():
    if 'file' in session:
        df = pd.read_csv(session['file'], sep=session['sep'], encoding=session['enc'])
        return render_template('table.html', data=df.to_html(table_id="table"))
    else:
        flash('No selected file')
        return redirect(url_for('upload'))


@app.route("/viz")
def create_viz():
    if 'file' in session:
        df = pd.read_csv(session['file'], sep=session['sep'], encoding=session['enc'])
        return render_template('create_viz.html', data=df.to_html(table_id="data"))
    else:
        flash('No selected file')
        return redirect(url_for('upload'))


