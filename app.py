#FLASK import
from flask import Flask, url_for, session, jsonify, request
from flask import render_template, redirect
from werkzeug.security import generate_password_hash, check_password_hash
 
#third party library
from authlib.integrations.flask_client import OAuth
from flask_mysqldb import MySQL

#generating instances
app = Flask(__name__)
google_oauth = OAuth(app)
fb_oauth = OAuth(app)
mysql = MySQL(app)


#flask configuration
app.secret_key = '!developer'
app.config.from_object('config')

#mysql configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'alohmora'
app.config['MYSQL_DB'] = 'login_func'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'


#Google login configuration
CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
google_oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

#facebook login configuration
fb_oauth.register(
    name='facebook',
    client_id='965059147271347',
    client_secret='4861d1d74aaf0fe33eb6c38bfdeaa3b6',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email,public_profile'},
)






### pasara
#trial--- get_all_users
@app.route('/get_all_users', methods=['GET'])
def get_all_users():
    cur = mysql.connection.cursor()
    cur.execute(''' select * from user ''')
    results = cur.fetchall()
    return jsonify({'users':results})

##mock hompage
@app.route('/')
def homepage():
    user = session.get('user')
    print(user)
    return render_template('home.html', user=user)




##supporting functions
def does_user_exist(email_id):
    cur = mysql.connection.cursor()
    query = ''' select * from user where user.email = '%s' '''%email_id
    print(query)
    cur.execute(query)
    cur.fetchall()
    print(cur.rowcount)

    if cur.rowcount == 0:
        return False
    else:
        return True






## end points
## /registration
## 
@app.route('/user', methods=['POST'])
def registration():
    data = request.get_json()
    print(data)

    if does_user_exist(data['email_id']):
        return jsonify({'Logical status code':'403','message': 'Email ID already registerd!', 'email_id':str(data['email_id'])})

    ##hashing of password with SHA128
    hashed_password = generate_password_hash(data['password'],method='sha1')
    
#DEBUG purpose print
    print("DEBUG @registration-->  hashed password SHA1:" + hashed_password)

    #creating cursor for inserting data
    cur = mysql.connection.cursor()
    query = ''' insert into user (uuid, fname, lname, email, password, user_type,auth_source,is_verified) values (uuid(), %s,%s,%s,%s,%s,%s,0);'''
    val = [data['fname'],data['lname'],data['email_id'],hashed_password,data['user_type'], 'volunteer']

    cur.execute(query,val)
#DEBUG purpose print
    print(cur.rowcount, " affected rows")


    ##do we have to add user_history timestamp and activity??
    mysql.connection.commit()

    ##verification()
    return jsonify({'Logical status code':'200', 'message':'User registered successfully'})




##google login 
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('auth', _external=True)
    return google_oauth.google.authorize_redirect(redirect_uri)

##fb login
@app.route('/login/fb')
def fb_login():
    facebook = fb_oauth.create_client('facebook')
    redirect_uri = url_for('authorize', _external=True)
    print("fb_login: " + str(redirect_uri))
    return facebook.authorize_redirect(redirect_uri)



#Google callback 
@app.route('/auth')
def auth():
    token = google_oauth.google.authorize_access_token()
    user = google_oauth.google.parse_id_token(token)
    session['user'] = user
    print(user)
    
    ## remaining : add exception cases!!!

    if does_user_exist(user['email']):
        return jsonify({'Logical status code':'200', 'message':'Username already registered!', 'data':{'email':user['email']}})

    #if flow reaches here, it means user is NEW!
    #registration of the user begin

    #creating cursor for inserting data
    cur = mysql.connection.cursor()
    query = ''' insert into user (uuid, fname, lname, email, auth_source, is_verified) values (uuid(), %s,%s,%s,%s, 0);'''
    val = [user['given_name'],user['family_name'],user['email'],'google']
    cur.execute(query,val)
    #creating cursor for in

#DEBUG purpose print
    print(cur.rowcount, " affected rows")
    ##do we have to add user_history timestamp and activity??
    mysql.connection.commit()


    return jsonify({'logical status code':'200','message':'User added into db successfully through GOOGLE login'})

#fb callback 
@app.route('/authorize')
def authorize():
    facebook = fb_oauth.create_client('facebook') #to create facebook oauth client
    token = facebook.authorize_access_token()  
    resp = fb_oauth.facebook.get('me',token=token)  
    user_info = resp.json()
    session['profile'] = user_info
    print("authorze: " + str(user_info))
    return redirect('/')






#common logout
@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/')






    