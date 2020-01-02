from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail

UPLOAD_FOLDER = '/Users/Szymon/Desktop/UNI/Mag/1 semestr/PythonSQL/project/flaskProject_291219_1853_sw'
ALLOWED_EXTENSIONS = {'csv'}

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = '58hqfiqlfb1476478hijgdbkygik67899'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'alertsmogowyvba@gmail.com'
app.config['MAIL_PASSWORD'] = 'applePie3'
mail = Mail(app)

from flaskProject import routes