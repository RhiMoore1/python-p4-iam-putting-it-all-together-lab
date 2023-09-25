#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

# from flask.ext.bcrypt import Bcrypt
# # instantiate Bcrypt with app instance
# bcrypt = Bcrypt(app)



# /Signup resource in app.py creates user records with usernames and passwords at /signup. 
# Signup resource in app.py 422s invalid usernames at /signup.
# Handle sign up by implementing a POST /signup route
class Signup(Resource):
    def post(self):
        request_json = request.get_json()


        user = User()
        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        user = User(
            username = username,
            image_url = image_url, 
            bio = bio
        )

        user.password_hash = password

        try: 
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            return user.to_dict(), 201
        except:
            return {'error': '422 invalid username'}, 422 


    

# /CheckSession resource in app.py returns JSON for the user's data if there is an active session.
# /CheckSession resource in app.py returns a 401 Unauthorized status code if there is no active session.

class CheckSession(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return user.to_dict(), 200
        return {'error': '401: Not Authorized'}, 401

# api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(CheckSession, '/check_session')    

# /Login resource in app.py logs users in with a username and password at /login.
# /Login resource in app.py returns 401 for an invalid username and password at /login.

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')

        
        user = User.query.filter(
            User.username == username
        ).first()

        if user:
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        else:
            return {'error': '401 invalid username and password'}, 401



# /Logout resource in app.py logs users out at /logout.
# /Logout resource in app.py returns 401 if a user attempts to logout without a session at /logout.
class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {'logged out': '204'},204
        else: 
            return {'error': '401 not logged in'}, 401
    
# /RecipeIndex resource in app.py returns a list of recipes associated with the logged in user and a 200 status code.
# /RecipeIndex resource in app.py test_get_route_returns_401_when_not_logged_in
class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return [recipe.to_dict() for recipe in user.recipes], 200
        else:
            return {'error': '401 not logged in'}, 401

# /RecipeIndex resource in app.py returns a list of recipes associated with the logged in user and a 200 status code.
# /RecipeIndex resource in app.py test_returns_422_for_invalid_recipes
    def post(self):
        if session.get('user_id'):
            request_json = request.get_json()
            title = request_json['title']
            instructions = request_json['instructions']
            minutes_to_complete = request_json['minutes_to_complete']

            try: 
                recipe = Recipe(
                    title = title,
                    instructions = instructions, 
                    minutes_to_complete  = minutes_to_complete,
                    user_id = session['user_id']
                )
                db.session.add(recipe)
                db.session.commit()

                return recipe.to_dict(), 201
            except:
                return {'error': '422 not logged in'}, 422 
       



api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
