import hashlib
import os
import jwt


class Token:

    def generate_token(self, username, input_password, query):
        useful_key = 'my2w7wjd7yXF64FIADfJxNs1oupTGAuW'

        if query:
            salt, password, role = query
            hashPass = hashlib.sha512((input_password + salt).encode()).hexdigest()
            if hashPass == password:
                token = jwt.encode({"role": role}, useful_key, algorithm='HS256')
                os.environ['TOKEN'] = 'Bearer ' + token
                return token
        return False


class Restricted:

    def access_data(self, authorization):
        try:
            token = jwt.decode(authorization.replace('Bearer', '')[1:],
                               'my2w7wjd7yXF64FIADfJxNs1oupTGAuW',
                               algorithms='HS256')
            if 'role' in token:
                return True
        except jwt.InvalidTokenError:
            pass
        return False
