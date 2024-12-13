from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projects.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# إعداد OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='YOUR_GOOGLE_CLIENT_ID',
    client_secret='YOUR_GOOGLE_CLIENT_SECRET',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(150), nullable=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    requirements = db.Column(db.String(500), nullable=False)
    leader = db.Column(db.String(150), nullable=False)
    team_members = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tasks = db.relationship('Task', backref='project', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    assignee = db.Column(db.String(150), nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)
    deadline = db.Column(db.String(50), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('dashboard_page.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('create_project'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/login/google')
def login_with_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/callback')
def authorize_google():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    email = user_info['email']
    username = user_info['name']

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash('Login with Google successful!', 'success')
    return redirect(url_for('create_project'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        try:
            title = request.form['title']
            description = request.form['description']
            requirements = request.form['requirements']
            leader = request.form['leader']
            team_members = request.form['team_members']

            new_project = Project(
                title=title,
                description=description,
                requirements=requirements,
                leader=leader,
                team_members=team_members,
                user_id=current_user.id
            )
            db.session.add(new_project)

            # Adding tasks
            task_names = request.form.getlist('task_name')
            assignees = request.form.getlist('assignee')
            difficulties = request.form.getlist('difficulty')
            deadlines = request.form.getlist('deadline')

            for i in range(len(task_names)):
                new_task = Task(
                    name=task_names[i],
                    assignee=assignees[i],
                    difficulty=difficulties[i],
                    deadline=deadlines[i],
                    project_id=new_project.id
                )
                db.session.add(new_task)

            db.session.commit()
            flash('Project and tasks created successfully!', 'success')
            return redirect(url_for('view_projects'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", 'danger')

    return render_template('create_project.html')

@app.route('/view_projects')
@login_required
def view_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('view_projects.html', projects=projects)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# Main
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
