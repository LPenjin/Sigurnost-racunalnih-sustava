import argparse
import pickle

from Crypto.Hash import HMAC
from Crypto.Cipher import Salsa20
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


def decrypt_encrypted(encrypted_dict, key):
    decrypted_dict = {}
    for pswd in encrypted_dict:
        if pswd == b'salt' or pswd == b'MAC':
            continue
        cipher = Salsa20.new(key=key, nonce=pswd[:8])
        decrypted_key = cipher.decrypt(pswd[8:])
        encrypted_value = encrypted_dict[pswd]
        cipher = Salsa20.new(key=key, nonce=encrypted_value[:8])
        decrypted_value = cipher.decrypt(encrypted_value[8:])
        decrypted_dict[decrypted_key] = decrypted_value
    return decrypted_dict


def get_HMAC(encrypted_dict, key):
    h = HMAC.new(key)
    for pswd in sorted(list(encrypted_dict.keys())):
        if pswd == b"MAC":
            continue
        h.update(pswd)
        h.update(encrypted_dict[pswd])
    return h


def get_passwd(get_list):
    password = get_list[0]
    wanted_value = bytes(get_list[1], 'utf-8')
    try:
        pickle_off = open("PasswordManager", "rb")
    except:
        print("PasswordManager file missing! Try initializing with tajnik.py --init <Your password here>")
        exit(1)
    encrypted_dict = pickle.load(pickle_off)
    try:
        if not b'salt' in encrypted_dict:
            raise ValueError
        if not b'MAC' in encrypted_dict:
            raise ValueError
    except ValueError:
        print('Salt or MAC missing from PasswordManager!')
        exit(1)
    key = scrypt(password, encrypted_dict[b'salt'], 32, N=2 ** 14, r=8, p=1)
    try:
        h = get_HMAC(encrypted_dict, key)
        h.hexverify(encrypted_dict[b'MAC'])
        decrypted_dict = decrypt_encrypted(encrypted_dict, key)

        if wanted_value in decrypted_dict:
            print(f"Password for {wanted_value.decode('utf-8')}: {decrypted_dict[wanted_value].decode('utf-8')}")
        else:
            print("Password does not exist")
    except:
        print("Wrong password or integrity compromised")


def put_passwd(put_list):
    password = put_list[0]
    dict_key = bytes(put_list[1], 'utf-8')
    dict_value = bytes(put_list[2], 'utf-8')
    try:
        pickle_off = open("PasswordManager", "rb")
    except:
        print("PasswordManager file missing! Try initializing with tajnik.py --init <Your password here>")
        exit(1)
    encrypted_dict = pickle.load(pickle_off)
    try:
        if not b'salt' in encrypted_dict:
            raise ValueError
        if not b'MAC' in encrypted_dict:
            raise ValueError
    except ValueError:
        print('Salt or MAC missing from PasswordManager!')
        exit(1)
    key = scrypt(password, encrypted_dict[b'salt'], 32, N=2 ** 14, r=8, p=1)
    salt = encrypted_dict[b'salt']
    try:
        h = get_HMAC(encrypted_dict, key)
        h.hexverify(encrypted_dict[b'MAC'])
        decrypted_dict = decrypt_encrypted(encrypted_dict, key)
        if dict_key in decrypted_dict:
            print(f"Password for {dict_key.decode('utf-8')} already exits and it will be replaced")
        decrypted_dict[dict_key] = dict_value
        if bytes('sifra', 'utf-8') in decrypted_dict:
            del encrypted_dict
            encrypted_dict = {}
            for pswd in decrypted_dict:
                cipher = Salsa20.new(key)
                new_encrypted_key = cipher.nonce + cipher.encrypt(pswd)
                cipher = Salsa20.new(key)
                new_encrypted_value = cipher.nonce + cipher.encrypt(decrypted_dict[pswd])
                encrypted_dict[new_encrypted_key] = new_encrypted_value
            encrypted_dict[b'salt'] = salt
            h = get_HMAC(encrypted_dict, key)
            encrypted_dict[b'MAC'] = h.hexdigest()
        with open('PasswordManager', 'wb') as pm:
            pickle.dump(encrypted_dict, pm)
        print(f"Stored password for {dict_key.decode('utf-8')}")
    except ValueError:
        print("Wrong password or integrity compromised")


def init_file(masterPassword):
    salt = get_random_bytes(16)
    key = scrypt(masterPassword, salt, 32, N=2 ** 14, r=8, p=1)
    cipher = Salsa20.new(key)
    key_key = cipher.nonce + cipher.encrypt(bytes('sifra', 'utf-8'))
    cipher = Salsa20.new(key)
    key_value = cipher.nonce + cipher.encrypt(key)
    starting_dict = {key_key: key_value}
    starting_dict[b'salt'] = salt
    h = get_HMAC(starting_dict, key)
    starting_dict[b'MAC'] = h.hexdigest()
    with open('PasswordManager', 'wb') as pm:
        pickle.dump(starting_dict, pm)
    print("Password manager initialized!")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='SRS labos',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--init', type=str, default=None)
    parser.add_argument('--put', type=str, default=None, nargs='+')
    parser.add_argument('--get', type=str, default=None, nargs='+')
    return parser.parse_args()


def main():
    args = parse_arguments()
    if args.init:
        init_file(args.init)
    elif args.put:
        if len(args.put) == 3:
            put_passwd(args.put)
        else:
            print(f"Incorrect number of arguments. Please enter masterpassword, password name and password "
                  f"that you want to add")
    elif args.get:
        if len(args.get) == 2:
            put_passwd(args.get)
        else:
            print(f"Incorrect number of arguments. Please enter masterpassword and password name "
                  f"that you want to get")


if __name__ == '__main__':
    main()
