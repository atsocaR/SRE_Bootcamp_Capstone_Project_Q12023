from dotenv import load_dotenv
from flask import *
from methods import *
from convert import *
import mysql.connector
import configparser


app = Flask(__name__)
load_dotenv()
config = configparser.ConfigParser()
config.read('config.ini')

login = Token()
protected = Restricted()
convert = CidrMaskConvert()
validate = IpValidate()


# Just a health check
@app.route("/")
def urlRoot():
    return "OK"


# Just a health check
@app.route("/_health")
def urlHealth():
    return "OK"


# e.g. http://127.0.0.1:8000/login
@app.route("/login", methods=['POST'])
def urlLogin():
    username = request.form('username')
    password = request.form('password')
    # This database data is here just for you to test, please, remember to define your own DB
    # You can test with username = admin, password = secret  
    # This DB has already a best practice: a salt value to store the passwords

    db_config = config['database']
    con = mysql.connector.connect(**db_config)
    cursor = con.cursor()
    cursor.execute("SELECT salt, password, role from users where username = %s;")
    Query = cursor.fetchall()
    token = login.generateToken(username, password, Query)

    if token is not False:
        payload = {"data": token}
        return jsonify(payload)
    abort(401)


# e.g. http://127.0.0.1:8000/cidr-to-mask?value=8
@app.route("/cidr-to-mask")
def url_cidr_to_mask():
    auth_header = request.headers.get('Authorization')
    if not protected.access_Data(auth_header):
        abort(401)
    cidr_value = request.args.get('value')
    response = {"function": "cidr_to_mask", "input": cidr_value, "output": convert.cidr_to_mask(cidr_value), }
    return jsonify(response)


# # e.g. http://127.0.0.1:8000/mask-to-cidr?value=255.0.0.0
@app.route("/mask-to-cidr")
def urlMaskToCidr():
    auth_header = request.headers.get('Authorization')
    if not protected.access_Data(auth_header):
        abort(401)
    cidr_value = request.args.get('value')
    response = {"function": "maskToCidr", "input": cidr_value, "output": convert.mask_to_cidr(cidr_value), }
    return jsonify(response)


if __name__ == '__main__':
    app_config = config['app']
    app.run(debug=app_config.getboolean('debug'),
            host=app_config['host'],
            port=app_config.getint('port'))
