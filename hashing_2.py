from multiprocessing import Pool
from itertools import repeat
from Crypto.Hash import SHA3_512
from multiprocessing import Manager

def string_to_binary(string):
    return ''.join(format(ord(i), '08b') for i in string)

def binary_to_string(binary):
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def hash_password(password_flag,rows,hashes_to_compare):
    password, flag = password_flag
    if flag.value == len(rows):
        return None
    for row in rows:
        salt = row['salt'].values[0]
        h = SHA3_512.new(bytes(password, 'utf-8'))
        h.update(salt)
        tmp = h.hexdigest()
        if tmp in hashes_to_compare:
            username = row['username'].values[0]
            hashes_to_compare.remove(tmp)
            flag.value += 1
            print('Password correct for username: ', username)
            print('Password: ', password)
            return password  # Return the password if it matches the hash
    return None  # Return None if password not found

def hash_passwords(passwords, rows):
    print('Hashing passwords')
    print('Number of passwords: ', len(passwords))
    manager = Manager()
    flag = manager.Value('i', 0)
    hashes_to_compare = [row['password'].values[0] for row in rows]
    print(hashes_to_compare)
    with Pool(processes=16) as p:
        results = p.starmap(hash_password, zip(((password, flag)for password in passwords),repeat(rows),repeat(hashes_to_compare)))
    # Filter out None values (passwords not found) from results
    found_passwords = [password for password in results if password is not None]
    
    return found_passwords