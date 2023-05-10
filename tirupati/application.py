import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///tirupati.db")


@app.route("/")
def index():

    return render_template("index.html")



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy products"""
    if request.method == "POST":
        product = request.form.get("product")
        if not product:
            return apology("Please select a product")

        pricee = db.execute("SELECT price FROM portfolio where product = ?", product)[0]["price"]
        print(pricee)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        print(cash)

        qty = request.form.get("qty")
        total = pricee * int(qty)

        if int(total) > int(cash):
            return apology("Not enough shares available for this symbol")

        else:
            db.execute("INSERT into transactions (userid, product, qty, price) VALUES (?, ?, ?, ?)",
                       session["user_id"], product, qty, pricee)

            newcash = cash - total

            db.execute("UPDATE users SET cash = ? where id = ?", newcash, session["user_id"])
            flash("Items bought.")

        return redirect("/")

    else:
        products = db.execute("SELECT product, price FROM portfolio where availability = 'Yes'")
        return render_template("buy.html", products=products)

@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    if request.method == "POST":
        amount = request.form.get("amount")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        newcash = cash + int(amount)
        db.execute("UPDATE users SET cash = ? where id = ?", newcash, session["user_id"])

        return redirect("/")

    else:
        return render_template("wallet.html", cash=cash)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    rows = db.execute("SELECT * FROM transactions")
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) == 1:
            return apology("username already taken", 400)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))

        # Redirect user to login page
        return render_template("login.html")

    else:
        return render_template("register.html")



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
