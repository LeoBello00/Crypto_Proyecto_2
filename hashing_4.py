from multiprocessing import Pool
from itertools import repeat
from Crypto.Hash import SHA3_512
from Crypto.Protocol.KDF import PBKDF2
from multiprocessing import Manager

def hash_password(password_flag,rows,hashes_to_compare):
    password, flag = password_flag
    #if flag.value == len(rows):
    if flag.value % 20 == 0:
        print(flag.value)
    for row in rows:
        salt = row['salt'].values[0]
        key = PBKDF2(bytes(password,'utf-8'), bytes.fromhex(salt), dkLen=64, count=2 ** 20)
        h = SHA3_512.new()
        h.update(key)
        tmp = h.hexdigest()
        flag.value += 1
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

    with Pool(processes=10) as p:
        results = p.starmap(hash_password, zip(((password, flag)for password in passwords),repeat(rows),repeat(hashes_to_compare)))
    # Filter out None values (passwords not found) from results
    found_passwords = [password for password in results if password is not None]
    
    return found_passwords