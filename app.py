from flask import Flask, request
from flask_sqlalchemy  import SQLAlchemy
from flask_restful import Resource, Api
# Resource: Each resource class defines the behavior for handling different HTTP methods 
# Api: Adding resources to a Flask application, managing routes, and handling HTTP requests
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
# flask_jwt_extended: generate a new JWT access token
# jwt_required: It's a decorator if token is not valid it's denied error message
# get_jwt_identity: retrieve the identity (e.g., user ID) from a JWT token. It is commonly used within protected routes to access the user's identity.
# JWTManager: It provides a centralized way to handle JWT-related functionalities.
# JWT (JSON Web Token) authentication

app = Flask(__name__)

# The SECRET_KEY used for cryptographic operations in Flask applications.
# It's secure session data, generate tokens, and other security-related tasks.
app.config['SECRET_KEY'] = 'SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
api = Api(app) # Flask-RESTful API instance.
jwt = JWTManager(app) # Initializes the Flask-JWT-Extended extension for handling JWT authentication

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class UserResources(Resource):
    # Resource class is used to define the behavior of a resource for example "GET", "POST", "PUT", "DELETE" etc.
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Checks if the username or password is missing in the request data and returns an error message if true.
        if not username or not password:
            return {"Message": "Missing Username or Password "}
        
        # Checks if the provided username already exists in the database and returns an error message if true.
        if User.query.filter_by(username=username).first():
            return {"Message": "Username already exist"}
        
        # If both upper condition is false then add the new user in database
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return {"Message": "User has been created successfully"}
    
class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Retrieves the user from the database based on the provided username.
        user = User.query.filter_by(username=username).first()

        # If user enter same password as register password then give him JWT access token
        if user and user.password==password:
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
            print(access_token)
        
        return {"Message": "Invalid credentials"}
    
class Protected(Resource):
    @jwt_required() # This decorator ensures that the request has a valid JWT token.
    def get(self):
        current_user_id = get_jwt_identity() 
        # get_jwt_identity() is a function provided by Flask-JWT-Extended that extracts the identity information from the JWT token.
        return {"Message": f"Hello user {current_user_id} you access the protected resources"}

# The resource classes with the Flask-RESTful API and specifies the corresponding endpoints.    
api.add_resource(UserResources, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(Protected, '/secure')

if __name__ == "__main__":
    app.run(debug=True)