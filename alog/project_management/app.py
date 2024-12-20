from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projects.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# إعداد نظام تسجيل الأخطاء
logging.basicConfig(level=logging.DEBUG)

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

# نماذج قاعدة البيانات
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(150), nullable=False)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    requirements = db.Column(db.String(500), nullable=False)
    leader = db.Column(db.String(150), nullable=False)
    team_members = db.Column(db.String(500), nullable=True)  # مرونة أعلى
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tasks = db.relationship('Task', backref='project', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    assignee = db.Column(db.String(150), nullable=True)
    difficulty = db.Column(db.String(50), nullable=True)
    deadline = db.Column(db.String(50), nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# المسارات
@app.route('/')
def index():
    return render_template('dashboard_page.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during registration: {e}")
            flash('An error occurred. Please try again.', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        try:
            # الحصول على بيانات المشروع
            title = request.form.get('title')
            description = request.form.get('description')
            requirements = request.form.get('requirements')
            leader = request.form.get('leader')

            # الحصول على أعضاء الفريق كقائمة
            team_members = request.form.getlist('team_members[]')

            # الحصول على المهام
            task_names = request.form.getlist('task_name[]')
            assignees = request.form.getlist('assignee[]')
            difficulties = request.form.getlist('difficulty[]')
            deadlines = request.form.getlist('deadline[]')

            # التحقق من صحة البيانات
            if not title or not description or not leader:
                flash('Please fill out all required fields.', 'danger')
                return redirect(url_for('create_project'))

            if len(team_members) == 0:
                flash('You must add at least one team member.', 'error')
                return redirect(url_for('create_project'))

            if len(task_names) == 0:
                flash('You must add at least one task.', 'error')
                return redirect(url_for('create_project'))

            # إنشاء مشروع جديد
            new_project = Project(
                title=title,
                description=description,
                requirements=requirements,
                leader=leader,
                team_members=','.join(team_members),
                user_id=current_user.id
            )
            db.session.add(new_project)

            # Commit to generate the project ID
            db.session.commit()

            # إضافة المهام للمشروع
            for i in range(len(task_names)):
                if not task_names[i].strip():
                    continue
                new_task = Task(
                    name=task_names[i],
                    assignee=assignees[i] if i < len(assignees) else None,
                    difficulty=difficulties[i] if i < len(difficulties) else None,
                    deadline=deadlines[i] if i < len(deadlines) else None,
                    project_id=new_project.id  # Ensure the project_id is set here
                )
                db.session.add(new_task)

            db.session.commit()

            # إعطاء رد إيجابي
            flash('Project and tasks created successfully!', 'success')
            return redirect(url_for('view_projects'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating project: {e}")
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('create_project'))

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
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
