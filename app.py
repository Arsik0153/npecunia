from flask import Flask, request, jsonify, make_response, render_template, redirect
from flask.helpers import url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
from werkzeug.utils import redirect
from werkzeug.wrappers import response
from utils.scraper import Scraper
import asyncio
import os
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DB_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    email = db.Column(db.String(50))
    password = db.Column(db.String(50))


class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    Author = db.Column(db.String(50), unique=True, nullable=False)
    Publisher = db.Column(db.String(50), nullable=False)
    book_prize = db.Column(db.Integer)


async def scrap(query):
    scraper = Scraper()
    results = await scraper.scrap(query, 3)

    return results


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None
        token = request.cookies.get('token')

        if not token:
            return redirect(url_for('login_user'))

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/', methods=['GET'])
def index():
    new_user = Users(public_id="12345132412",
                     email="John", password="asdfaksdfsdf")
    db.session.add(new_user)
    db.session.commit()
    return render_template('index.html', name="Mike")


@app.route('/register', methods=['POST'])
def signup_user():
    data = {
        'email': request.form['email'],
        'password': request.form['password'],
        'confpassword': request.form['confpassword']
    }

    if data['password'] != data['confpassword']:
        return jsonify({'message': 'passwords are not same'})

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()),
                     email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('signin_page'))


@app.route('/register', methods=['GET'])
def signup_page():
    return render_template('signup.html')


@app.route('/login', methods=['POST'])
def login_user():
    data = {
        'email': request.form['email'],
        'password': request.form['password']
    }
    print(data)

    if not data or not data['email'] or not data['password']:
        return make_response('could not verify', 401, {'Authentication': 'login required"'})

    user = Users.query.filter_by(email=data['email']).first()
    if not user:
        return make_response('no such user',  401, {'Authentication': '"login required"'})

    if check_password_hash(user.password, data['password']):

        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        response = make_response(redirect(url_for('search_page')))
        response.set_cookie('token', token)
        return response

    return make_response('could not verify',  401, {'Authentication': '"login required"'})


@app.route('/login', methods=['GET'])
def signin_page():
    return render_template('signin.html')


@app.route('/logout', methods=['GET'])
def logout():
    response = redirect(url_for('signin_page'))
    response.delete_cookie('token')
    return response


@app.route('/search', methods=['GET'])
@token_required
def search_page(current_user):
    query = request.args.get('q')

    if not query:
        return render_template('search.html')

    return render_template('search.html', payload=asyncio.run(scrap(query)))


@app.route('/users', methods=['GET'])
def get_all_users():

    users = Users.query.all()
    result = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['password'] = user.password

        result.append(user_data)

    return jsonify({'users': result})


@app.route('/book', methods=['POST'])
@token_required
def create_book(current_user):

    data = request.get_json()

    new_books = Books(name=data['name'], Author=data['Author'], Publisher=data['Publisher'],
                      book_prize=data['book_prize'], user_id=current_user.id)
    db.session.add(new_books)
    db.session.commit()

    return jsonify({'message': 'new books created'})


@app.route('/books', methods=['GET'])
@token_required
def get_books(current_user):

    books = Books.query.filter_by(user_id=current_user.id).all()

    output = []
    for book in books:
        book_data = {}
        book_data['id'] = book.id
        book_data['name'] = book.name
        book_data['Author'] = book.Author
        book_data['Publisher'] = book.Publisher
        book_data['book_prize'] = book.book_prize
        output.append(book_data)

    return jsonify({'list_of_books': output})


@app.route('/books/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id):
    book = Books.query.filter_by(id=book_id, user_id=current_user.id).first()
    if not book:
        return jsonify({'message': 'book does not exist'})

    db.session.delete(book)
    db.session.commit()

    return jsonify({'message': 'Book deleted'})


@app.before_first_request
def create_tables():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
