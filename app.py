from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskproject.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Article %r>' % self.id


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
@app.route('/home')
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page)
        else:
            flash('Логин или пароль неверны')
    else:
        flash('Заполните поля логина и пароля')
    return render_template("login.html")


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect('/home')


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    if request.method == 'POST':
        if not (login or password or password2):
            flash('Пожалуйста, заполните все поля')
        elif password != password2:
            flash('Введённые пароли не совпадают')
        else:
            hash_psw = generate_password_hash(password)
            new_user = User(login=login, password=hash_psw)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))

    return render_template('/register.html')


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/contacts')
def contacts():
    return render_template("contacts.html")


@app.route('/create-article', methods=['POST', 'GET'])
def create_article():
    if request.method == "POST":
        title = request.form['title']
        intro = request.form['intro']
        text = request.form['text']

        article = Article(title=title, intro=intro, text=text)

        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/posts')
        except:
            return "Возникла ошибка при добавлении"
    else:
        return render_template("create-article.html")


@app.route('/posts/<int:id>/update', methods=['POST', 'GET'])
def post_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.title = request.form['title']
        article.intro = request.form['intro']
        article.text = request.form['text']
        try:
            db.session.commit()
            return redirect('/posts')
        except:
            return "Возникла ошибка при редактировании"
    else:
        return render_template("post_update.html", article=article)


@app.route('/posts')
def posts():
    articles = Article.query.order_by(Article.date.desc()).all()
    return render_template("posts.html", articles=articles)


@app.route('/posts/<int:id>/delete')
def post_delete(id):
    article = Article.query.get_or_404(id)

    try:
        db.session.delete(article)
        db.session.commit()
        return redirect('/posts')
    except:
        return "Возникла ошибка при удалении"


@app.route('/posts/<int:id>')
def post_detail(id):
    article = Article.query.get(id)
    return render_template("post_detail.html", article=article)


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)
    return response


if __name__ == "__main__":
    app.run(debug=True)
