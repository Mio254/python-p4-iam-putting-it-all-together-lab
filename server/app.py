from flask import Flask, request, session
from flask_restful import Api, Resource
from sqlalchemy.exc import IntegrityError

from config import db, bcrypt, migrate
from models import User, Recipe

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "super-secret-key"

db.init_app(app)
bcrypt.init_app(app)
migrate.init_app(app, db)

api = Api(app)


def user_dict(user: User):
    return {
        "id": user.id,
        "username": user.username,
        "image_url": user.image_url,
        "bio": user.bio,
    }


# -------------------- SIGNUP --------------------
class Signup(Resource):
    def post(self):
        data = request.get_json() or {}

        try:
            user = User(
                username=data.get("username"),
                image_url=data.get("image_url"),
                bio=data.get("bio"),
            )
            user.password_hash = data.get("password")

            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id
            return user_dict(user), 201

        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Username must be unique"]}, 422

        except ValueError as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422


# -------------------- CHECK SESSION --------------------
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = db.session.get(User, user_id)
        if not user:
            session.pop("user_id", None)
            return {"error": "Unauthorized"}, 401

        return user_dict(user), 200


# -------------------- LOGIN --------------------
class Login(Resource):
    def post(self):
        data = request.get_json() or {}

        user = User.query.filter_by(username=data.get("username")).first()
        if user and user.authenticate(data.get("password")):
            session["user_id"] = user.id
            return user_dict(user), 200

        return {"error": "Invalid username or password"}, 401


# -------------------- LOGOUT --------------------
class Logout(Resource):
    def delete(self):
        if not session.get("user_id"):
            return {"error": "Unauthorized"}, 401

        session.pop("user_id", None)
        return "", 204


# -------------------- RECIPES --------------------
class RecipeIndex(Resource):
    def get(self):
        if not session.get("user_id"):
            return {"error": "Unauthorized"}, 401

        recipes = Recipe.query.all()
        return [
            {
                "id": r.id,
                "title": r.title,
                "instructions": r.instructions,
                "minutes_to_complete": r.minutes_to_complete,
                "user": user_dict(r.user),
            }
            for r in recipes
        ], 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json() or {}

        try:
            recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()

            return {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": user_dict(recipe.user),
            }, 201

        except ValueError as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422


api.add_resource(Signup, "/signup")
api.add_resource(CheckSession, "/check_session")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")
api.add_resource(RecipeIndex, "/recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
