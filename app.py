import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
# Security: Use environment variable or a default for dev
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '7a9d1b2c3e4f5g6h8i9j0k1l2m3n4o5p') 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB max limit

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False) # Original filename
    filepath = db.Column(db.String(200), nullable=False) # System filename (UUID)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = FileField('Select File', validators=[DataRequired()])
    submit = SubmitField('Upload')

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='scrypt')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file:
            original_filename = secure_filename(file.filename)
            # Use UUID for storage to prevent collisions
            file_ext = os.path.splitext(original_filename)[1]
            storage_filename = f"{uuid.uuid4()}{file_ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_filename)
            
            file.save(filepath)
            
            new_file = File(filename=original_filename, filepath=storage_filename, owner=current_user)
            db.session.add(new_file)
            db.session.commit()
            
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))

    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=files, user=current_user, form=form)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_data = File.query.get_or_404(file_id)
    if file_data.owner != current_user:
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filepath, as_attachment=True, download_name=file_data.filename)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file_data = File.query.get_or_404(file_id)
    if file_data.owner != current_user:
        abort(403)
        
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_data.filepath))
    except OSError:
        pass # File might not exist on disk
        
    db.session.delete(file_data)
    db.session.commit()
    flash('File deleted!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
