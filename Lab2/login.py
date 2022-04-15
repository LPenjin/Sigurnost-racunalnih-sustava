from base64 import b64encode
from Crypto.Hash import SHA256
from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt
import pickle
import getpass
import sys

from Crypto.Protocol.KDF import bcrypt, bcrypt_check

PSWD = 'pswd'
FORCE_CHANGE_FLAG = "force_change_flag"


def change_password(user):
    try:
        pickle_off = open("userpass", "rb")
        user_dict = pickle.load(pickle_off)
    except:
        print(f"Userpass does not exist")
        exit(1)
    if user in user_dict:
        password = getpass.getpass('New password: ')
        if password:
            repeat_password = getpass.getpass('Repeat password: ')
        else:
            print(f"No password given")
        if repeat_password == password:
            derived_password = b64encode(SHA256.new(bytes(password, 'utf-8')).digest())
            value = {PSWD: derived_password, FORCE_CHANGE_FLAG: False}
            user_dict[user] = value
            print(f"User password successfuly changed.")
            with open('userpass', 'wb') as up:
                pickle.dump(user_dict, up)
            return True
        else:
            print(f"User password change failed. Password mismatch.")
            return False
    else:
        print(f"User does not exist in userpass")
        return False


def get_password(guessed_password):
    password = getpass.getpass('Password: ')
    return password, guessed_password + 1


def login(user):
    try:
        pickle_off = open("userpass", "rb")
        user_dict = pickle.load(pickle_off)
    except:
        print(f"Userpass does not exist")
        exit(1)
    guessed_password = 0
    while guessed_password < 3:
        password, guessed_password = get_password(guessed_password)
        if user in user_dict:
            password_derived = b64encode(SHA256.new(bytes(password, 'utf-8')).digest())
            password_hash = bcrypt(user_dict[user][PSWD], 12)
            try:
                bcrypt_check(password_derived, password_hash)
            except:
                print(f"Username or password incorrect.")
                continue
            if user_dict[user][FORCE_CHANGE_FLAG]:
                result = change_password(user)
                if result:
                    print("Login succesful!")
                    user_dict[user][FORCE_CHANGE_FLAG] = False
                    return
                else:
                    print("Login unsuccesful!")
            else:
                print("Login succesful!")
                return
        else:
            password_derived = b64encode(SHA256.new(bytes(password, 'utf-8')).digest())
            password_hash = bcrypt(b64encode(SHA256.new(bytes(password + '..', 'utf-8')).digest()), 12)
            try:
                bcrypt_check(password_derived, password_hash)
            except:
                print(f"Username or password incorrect.")
                continue
    print("Login unsuccesful!")


def main(argv):
    login(argv[0])


if __name__ == "__main__":
    main(sys.argv[1:])
