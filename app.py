from flask import Flask, request, render_template,redirect,flash
from pymongo import MongoClient
import qrcode
import uuid
import io
import base64
from pysafebrowsing import SafeBrowsing
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user
from werkzeug.security import generate_password_hash, check_password_hash

app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
API_KEY="<Your API_KEY>"


s = SafeBrowsing(API_KEY)


db_sql = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(db_sql.Model, UserMixin):
    id=db_sql.Column(db_sql.Integer, primary_key=True)
    name=db_sql.Column(db_sql.String(80), nullable=False)
    email=db_sql.Column(db_sql.String(40), unique=True, nullable=False)
    passh=db_sql.Column(db_sql.String(256), nullable=False)

    def set_password(self, password):
        self.passh = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.passh, password)
    
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

uri = "<Your URI>"
# Create a new client and connect to the server
client = MongoClient(uri)
# Send a ping to confirm a successful connection
# try:
#     client.admin.command('ping')
#     print("Pinged your deployment. You successfully connected to MongoDB!")
# except Exception as e:
#     print(" Error")

db=client['Shortify']
coll=db['urls']


@app.route('/')
def home():
    # print(current_user.name)
    if current_user.is_authenticated:
        return render_template('index_log.html', user=current_user.name)
    else:
        return render_template('index.html')

@app.route('/short', methods=['POST'])
def short():
    lurl=""
    flag=False
    lurl=request.form.get('urlbx')
    if lurl != "":
        result = s.lookup_urls([lurl])
        for data in result.values():
            if data.get("malicious") is True:
                flag=True
        if flag:
            flash('Warning! This maybe a deceptive site. Cannot Shorten.<br><a href="https://developers.google.com/safe-browsing/v4/advisory" target="_blank">Advisory</a> provided by Google <br><br><p>Powered by Google SafeBrowsing','warning')
            return redirect('/')
        else:
            random_uuid = uuid.uuid4().int
            base62_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            short_id = ""
            while random_uuid > 0 and len(short_id) < 6:  
                short_id = base62_chars[random_uuid % 62] + short_id
                random_uuid //= 62
            surl=f'http://127.0.0.1:5000/{short_id}'
            img = qrcode.make(surl)
            img_io = io.BytesIO()
            img.save(img_io, "PNG")
            img_io.seek(0)

            
            base64_str = base64.b64encode(img_io.getvalue()).decode("utf-8")
            # result=coll.insert_one({'longurl':lurl, 'shorturl':surl})
            if current_user.is_authenticated:
                lbl=request.form.get('lbl')
                print(lbl)
                result=coll.insert_one({'longurl':lurl, 'shorturl':surl, 'user':current_user.email, 'qr':base64_str, 'label':lbl})
                return render_template('index_log.html', surl=surl,imgurl=base64_str, user=current_user.name)
            else:
                result=coll.insert_one({'longurl':lurl, 'shorturl':surl})
                return render_template('index.html', surl=surl,imgurl=base64_str)
    else:
        return redirect('/')
    
@app.route('/<shorturl>')
def redirect_url(shorturl):
    if shorturl !=" ":
        query=f'http://127.0.0.1:5000/{shorturl}'
        result=coll.find_one({'shorturl':query})
        lurl=result['longurl'] # type: ignore
        return redirect(lurl)
    else:
        return "Error"
    
@app.route('/auth', methods=['GET','POST'])
def auth():
    return render_template('auth.html')

@app.route('/login', methods=['POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()

        if user and user.check_password(password=password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect('/')
        else:
            flash('Incorrect Credentials', 'danger')
    return render_template('auth.html')

@app.route('/reg', methods=['POST'])
def reg():
    if request.method=='POST':
        name=request.form.get('name')
        email=request.form.get('email')
        password=request.form.get('password')
        print(name,email,password)

        if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect('/auth')
        
        new_user=User(name=name, email=email)
        new_user.set_password(password)
        db_sql.session.add(new_user)
        db_sql.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect('/auth')
    return render_template('auth.html')

@app.route('/dash')
def dash():
    result=coll.find({'user':current_user.email})
    print(result)
    return render_template('dashboard.html', user=current_user.name, result=result)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db_sql.create_all()

    app.run(debug=True)
