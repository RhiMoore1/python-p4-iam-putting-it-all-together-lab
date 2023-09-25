from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from sqlalchemy import CheckConstraint

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    serialize_rules = ('-recipes.user', '-_password_hash',)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # have many recipes
    recipes = db.relationship('Recipe', backref='user')

    # incorporate bcrypt to create a secure password. 
    # Attempts to access the password_hash should be met with an AttributeError
    @hybrid_property
    def password_hash(self):
        raise AttributeError('cannot access password')
    

    @password_hash.setter
    def password_hash(self, password):
        # utf-8 encoding and decoding is required in python 3
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))




class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String,
                             CheckConstraint('(LENGTH(instructions) >= 50)'),
                             nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    # a recipe belongs to a user.
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    
    __table_args__ = (
        db.CheckConstraint('(LENGTH(instructions) >= 50)'),
    )


    
    # @validates('title', 'instructions')
    # def validate(self, key, value):
    #     if key == 'title':
    #         if value == '':
    #             raise ValueError('')
    #         return value
    #     elif key == 'instructions':
    #         if len(value) < 50:
    #             raise ValueError('')
    #         return value