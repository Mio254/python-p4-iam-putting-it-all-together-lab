from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property

from config import db, bcrypt


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)  # must be nullable for tests

    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship(
        "Recipe",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        if password is None:
            password = ""
        self._password_hash = bcrypt.generate_password_hash(
            password.encode("utf-8")
        ).decode("utf-8")

    def authenticate(self, password):
        if not self._password_hash or password is None:
            return False
        return bcrypt.check_password_hash(
            self._password_hash,
            password.encode("utf-8")
        )

    @validates("username")
    def validate_username(self, key, value):
        if not value or not value.strip():
            raise ValueError("Username must be present")
        return value.strip()


class Recipe(db.Model):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))  # nullable for tests
    user = db.relationship("User", back_populates="recipes")

    @validates("title")
    def validate_title(self, key, value):
        if not value or not value.strip():
            raise ValueError("Title must be present")
        return value.strip()

    @validates("instructions")
    def validate_instructions(self, key, value):
        if not value or not value.strip():
            raise ValueError("Instructions must be present")
        if len(value) < 50:
            raise ValueError("Instructions must be at least 50 characters long")
        return value
