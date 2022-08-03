import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView



# set up flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['WTF_CSRF_ENABLED'] = False
Bootstrap(app)


# set up database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('TODOAPP_DATABASE_URI', "sqlite:///TodoApp.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# set up flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'Login'


# PARENT
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    # EACH USER CAN HAVE HIS OR HER OWN TODOS
    todos = db.relationship('TodoApp', back_populates='todo_user')


# CHILD
class TodoApp(db.Model):
    __tablename__ = 'todo_app'
    id = db.Column(db.Integer, primary_key=True)
    # FOREIGN KEY ASSIGNMENT
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # CREATE REFERNCE TO PARENT OBJECT, THROUGH THE todos property
    todo_user = db.relationship("User", back_populates="todos")
    task = db.Column(db.String(250), nullable=False)
    day_created = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(250), nullable=False)


admin = Admin(app)
admin.add_view(ModelView(User, db.session))


@app.route('/')
def home():
    all_tasks = TodoApp.query.all()
    return render_template('home.html', total=all_tasks, logged_in=current_user.is_authenticated)


# set up the user loader.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # check the database to be sure that the email isn't already at the database. if yes, proceed to login.
        if User.query.filter_by(email=email).first():
            flash('Email already exists.proceed to login')
            return redirect(url_for('login'))
        elif password != confirm_password:
            flash('please confirm password')
        # if email does not exist already, go ahead and process it.
        else:
            insecure_password = password
            secure_password = generate_password_hash(insecure_password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                name=name,
                email=email,
                password=secure_password
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('register.html', logged_in=current_user.is_authenticated)


@app.route('/login', methods=['Get', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        # if the user does not exist.
        if not user:
            flash('Your email does not exist. Try again.')
            return redirect(url_for('login'))
        # if password is incorrect
        elif not check_password_hash(user.password, password):
            flash('Password is incorrect. Try again.')
            return redirect(url_for('login'))
        # if it finally works
        else:
            login_user(user)
            flash('Login Successful')
            return redirect(url_for('home',  logged_in=True))

    return render_template('login.html', logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/index')
@login_required
def todo_list():
    user_tasks = TodoApp.query.filter_by(user_id=current_user.id).all()
    print(user_tasks)
    return render_template('index.html', tasks=user_tasks, current_user=current_user)


@app.route('/add', methods=["GET", "POST"])
def add_task():
    if request.method == 'POST':
        status = 'In progress'
        new_task = TodoApp(
            task=request.form['details'].title(),
            status=status.title(),
            user_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('todo_list'))
    return render_template('index.html', logged_in=current_user.is_authenticated, current_user=current_user)


@app.route('/delete/<task_id>')
def delete(task_id):
    task_to_delete = TodoApp.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()

    return redirect(url_for('todo_list'))


@app.route('/finished/<task_id>')
def finished(task_id):
    finish = TodoApp.query.get(task_id)
    status_finished = 'finished'
    finish.status = status_finished
    db.session.commit()

    return redirect(url_for('todo_list', task_done=True))


if __name__ == "__main__":
    app.run(debug=True)

