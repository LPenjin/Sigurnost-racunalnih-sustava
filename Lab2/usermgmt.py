import argparse
import pickle
import getpass
from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt

PSWD = 'pswd'
FORCE_CHANGE_FLAG = "force_change_flag"


def set_force_change_flag(user):
    try:
        pickle_off = open("userpass", "rb")
        user_dict = pickle.load(pickle_off)
    except:
        print(f"Userpass does not exist")
        exit(1)
    if user in user_dict:
        if user_dict[user][FORCE_CHANGE_FLAG]:
            user_dict[user][FORCE_CHANGE_FLAG] = False
            print(f"Force_change_flag has been set to False")
        else:
            user_dict[user][FORCE_CHANGE_FLAG] = True
            print(f"Force_change_flag has been set to True")
        with open('userpass', 'wb') as up:
            pickle.dump(user_dict, up)
    else:
        print(f"User does not exist in userpass")


def del_user(user):
    try:
        pickle_off = open("userpass", "rb")
        user_dict = pickle.load(pickle_off)
    except:
        print(f"Userpass does not exist")
        exit(1)
    if user in user_dict:
        del user_dict[user]
        print(f"User succesfuly deleted")
        with open('userpass', 'wb') as up:
            pickle.dump(user_dict, up)
    else:
        print(f"User does not exist in userpass")


def change_password(user):
    try:
        pickle_off = open("userpass", "rb")
        user_dict = pickle.load(pickle_off)
    except:
        print(f"Userpass does not exist")
        exit(1)
    if user in user_dict:
        password = getpass.getpass('Password: ')
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
        else:
            print(f"User password change failed. Password mismatch.")
    else:
        print(f"User does not exist in userpass")


def add_user(user):
    try:
        pickle_off = open("userpass", "rb")
        user_dict = pickle.load(pickle_off)
    except:
        user_dict = {}
    if user not in user_dict:
        password = getpass.getpass('Password: ')
        if password:
            repeat_password = getpass.getpass('Repeat password: ')
        else:
            print(f"No password given")
        if repeat_password == password:
            derived_password = b64encode(SHA256.new(bytes(password, 'utf-8')).digest())
            value = {PSWD: derived_password, FORCE_CHANGE_FLAG: False}
            user_dict[user] = value
            print(f"User add successfuly added.")
        else:
            print(f"User add failed. Password mismatch.")
        with open('userpass', 'wb') as up:
            pickle.dump(user_dict, up)
    else:
        print(f"User add failed. User already exists.")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='SRS labos',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--add', type=str, default=None)
    parser.add_argument('--passwd', type=str, default=None)
    parser.add_argument('--delete', type=str, default=None)
    parser.add_argument('--forcepass', type=str, default=None)
    return parser.parse_args()

def main():
    args = parse_arguments()
    if args.add:
        add_user(args.add)
    elif args.passwd:
        change_password(args.passwd)
    elif args.delete:
        del_user(args.delete)
    elif args.forcepass:
        set_force_change_flag(args.forcepass)


if __name__ == "__main__":
    main()
