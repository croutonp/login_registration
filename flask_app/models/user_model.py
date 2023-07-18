from flask_app.config.mysqlconnection import connectToMySQL
from flask_app.controllers import users_controller 
from flask import flash
from flask_app import DATABASE
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+-]+@[a-zA-Z0-9._-]+.[a-zA-Z]+$')
ALPHA = re.compile(r"^[a-zA-Z]+$")


class User:
    def __init__(self,data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    # @classmethod
    # def create(cls,data):
    #     query= """
    #         INSERT INTO users (first_name, last_name, email, password)
    #         VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);
    #     """
    #     return connectToMySQL(DATABASE).query_db(query, data)

    # @classmethod
    # def get_by_id(cls,data):
    #     query = """
    #         SELECT * FROM users WHERE id = %(id)s;
    #     """
    #     results = connectToMySQL(DATABASE).query_db(query, data)
    #     if results:
    #         return cls(results[0])
    #     return False
    
    # @classmethod
    # def get_by_email(cls,data):
    #     query = """
    #         SELECT * FROM users WHERE id = %(email)s;
    #     """
    #     results =  connectToMySQL(DATABASE).query_db(query, data)
    #     if results:
    #         return cls(results[0])
    #     return False

    # @staticmethod
    # def is_valid(data):
    #     is_valid = True #First name validation
    #     if len(data['first_name']) < 1:
    #         flash('First name required', 'reg')
    #         is_valid = False
    #     elif len(data['first_name']) < 2:
    #         flash("Name must be at least two characters long", "reg")
    #         is_valid = False
    #     elif not ALPHA.match(data['first_name']):
    #     # elif not data['first_name'].isalpha():
    #         flash('First name may only contain letters', 'reg')
    #         is_valid = False
        
    
    #     if len(data['last_name']) < 1: #Last name validation
    #         flash('Last name required', 'reg')
    #         is_valid = False
    #     elif len(data['last_name']) <2:
    #         flash("Name must be at least two characters long", "reg")
    #         is_valid = False
    #     elif not ALPHA.match(data['last_name']):
    #         # elif not data['last_name'].isalpha():
    #         flash('Last name may only contain letters', 'reg')
    #         is_valid = False
        
    #     if len(data['email']) < 1: #Email validation
    #         flash('Email required!', 'reg')
    #     elif not EMAIL_REGEX.match(data['email']):
    #         flash('Email must be in proper format', 'reg')
    #         is_valid = False
    #     else: 
    #         potential_user = User.get_by_email({'email':data['email']})
    #         if potential_user:
    #             flash('This Email address has already been registered.',  'reg')
    #             is_valid=False
        
    #     if len(data['password']) < 1: #Password Validation
    #         is_valid = False
    #         flash('Password Required','reg')
    #     elif len(data['password']) < 8:
    #         is_valid = False
    #         flash('Password must be eight or more characters long', 'reg')
    #     elif data['password'] != data['cpass']:
    #         is_valid = False
    #         flash('Passwords must match')
    #     return is_valid

    @classmethod
    def create(cls, data):
        query="""
            INSERT INTO users (first_name, last_name, email, password)
            VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s)
        """
        return connectToMySQL(DATABASE).query_db(query, data)

    @classmethod
    def get_by_id(cls, data):
        query = """
            SELECT * FROM users WHERE id = %(id)s;
        """

        results = connectToMySQL(DATABASE).query_db(query,data)
        if results:
            return cls(results[0])#if returns return as an object
        return False

    @classmethod
    def get_by_email(cls, data):
        query = """
            SELECT * FROM users WHERE email = %(email)s;
        """

        results = connectToMySQL(DATABASE).query_db(query,data)
        if results:
            return cls(results[0])
        return False

    # @classmethod
    # def get_by_email(cls,data):
    #     query = """
    #         SELECT * FROM users WHERE email = %(email)s;
    #     """
    #     results =  connectToMySQL(DATABASE).query_db(query, data)
    #     if results:
    #         return cls(results[0])
    #     return False

    @staticmethod
    def is_valid (data):
            is_valid = True #FIRST NAME VALIDATION
            if len(data['first_name']) < 1:
                flash('First name is required', 'reg')
                is_valid = False
            elif len(data['first_name']) < 2:
                flash('First name must be 2 characters at least', 'reg')
                is_valid = False
            elif not data ['first_name'].isalpha():
                flash('First name can only contain letters', 'reg')
                is_valid = False
            if len(data['last_name']) < 1: #LAST NAME VALIDATION
                flash('Last name required', 'reg')
                is_valid = False
            elif len(data['last_name']) < 2:
                flash('Last name must be 2 characters at least', 'reg')
                is_valid = False
            elif not data ['last_name'].isalpha():
                flash('Last name can only contain letters', 'reg')
                is_valid = False
            if len(data['email']) < 1: #EMAIL VALIDATION
                flash('Email required', 'reg')
                is_valid = False
            elif not EMAIL_REGEX.match(data['email']):
                flash('Email must be in proper format','reg')
                is_valid = False
            else: 
                potential_user = User.get_by_email({'email':data['email']})
                if potential_user:
                    flash('Email already exists in Database', 'reg')
                    is_valid=False
            if len(data['password']) < 1:
                is_valid=False
                flash('Password Required','reg')
            elif len(data['password']) < 8:
                is_valid=False
                flash('Password must be 8 or more characters','reg')
            elif data ['password'] != data['cpass']:
                is_valid=False
                flash('Password must match','reg')
            return is_valid