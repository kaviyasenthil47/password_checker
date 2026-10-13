
import math
import secrets
import string
import mysql.connector


def password_check(user, password):
    score = 0

    if len(password) >= 8:
        score += 1

    if any(c.isdigit() for c in password):
        score += 1

    if any(c.isupper() for c in password):
        score += 1

    if any(c.islower() for c in password):
        score += 1

    if any(not c.isalnum() and not c.isspace()
           for c in password):
        score += 1

    if user and user.lower() not in password.lower():
        score += 1

    return score


def get_entropy(password):
    pool = 0

    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() and not c.isspace()
           for c in password):
        pool += 32

    if not password or pool == 0:
        return 0

    return len(password) * math.log2(pool)


def generate_password(length=12):
    special = "!@#$%^&*()-_=+"

    chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(special)
    ]

    pool = string.ascii_letters + string.digits + special

    for _ in range(length - 4):
        chars.append(secrets.choice(pool))

    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


common_passwords = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "iloveyou",
    "welcome123"
}


db = None
cursor = None

try:
    user = input("Enter username: ").strip()
    password = input("Enter password: ")

    if not user or not password:
        raise ValueError("Username and password cannot be empty")

    score = password_check(user, password)
    entropy = get_entropy(password)
    total = score + entropy

    print("\n--- Password Analysis ---")
    print("Rule-based score:", score, "/ 6")
    print("Estimated entropy:", round(entropy, 2), "bits")
    print("Combined total:", round(total, 2))

    if password.lower() in common_passwords:
        strength = "Weak"
        print("Rating: Weak - Common password detected")

    elif user.lower() in password.lower():
        strength = "Weak"
        print("Rating: Weak - Username found in password")

    elif total >= 60 and score >= 4:
        strength = "Strong"
        print("Rating: Strong")

    elif total >= 35 and score >= 2:
        strength = "Medium"
        print("Rating: Medium")

    else:
        strength = "Weak"
        print("Rating: Weak")

    # Connect to MySQL
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="black",
        database="intern"
    )

    cursor = db.cursor()

    # Save username, password and strength
    sql = """
    INSERT INTO password_check (user_id, passwords, strength)
    VALUES (%s, %s, %s)
    """

    values = (user, password, strength)

    cursor.execute(sql, values)
    db.commit()

    print("Record saved to MySQL successfully!")

    if strength == "Weak":
        choice = input(
            "Generate a stronger password? (yes/no): "
        ).strip().lower()

        if choice == "yes":
            print("Generated password:", generate_password())

finally:
    if cursor is not None:
        cursor.close()

    if db is not None and db.is_connected():
        db.close()
