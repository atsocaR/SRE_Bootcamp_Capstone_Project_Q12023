from dotenv import load_dotenv
from flask import *
from methods import *
from convert import *
from Database import *

app = Flask(__name__)
load_dotenv()
config = configparser.ConfigParser()
config.read('config.ini')

login = Token()
protected = Restricted()
convert = CidrMaskConvert()
validate = IpValidate()
database = Database()


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
    username = request.form['username']
    password = request.form['password']

    user_data = database.get_user_data(username)
    token = login.generate_token(username, password, user_data)

    if token is not False:
        payload = {"data": token}
        return jsonify(payload)
    abort(401)


# e.g. http://127.0.0.1:8000/cidr-to-mask?value=8
@app.route("/cidr-to-mask", methods=['POST'])
def url_cidr_to_mask():

    auth_header = os.getenv('TOKEN')
    if not protected.access_data(auth_header):
        abort(401)
    cidr_value = int(request.form['cidr'])
    response = {
        "function": "cidr_to_mask",
        "input": cidr_value,
        "output": convert.cidr_to_mask(cidr_value)
    }
    return jsonify(response)


# # e.g. http://127.0.0.1:8000/mask-to-cidr?value=255.0.0.0
@app.route("/mask-to-cidr", methods=['POST'])
def urlMaskToCidr():

    auth_header = os.getenv('TOKEN')

    if not protected.access_data(auth_header):
        abort(401)
    mask_value = request.form['value']

    if not validate.ipv4_validation(mask_value):
        abort(400)
    response = {"function": "maskToCidr", "input": mask_value, "output": convert.mask_to_cidr(mask_value), }
    return jsonify(response)


if __name__ == '__main__':
    app_config = config['app']
    app.run(debug=app_config.getboolean('debug'),
            host=app_config['host'],
            port=app_config.getint('port'))
