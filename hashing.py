from multiprocessing import Pool
from itertools import repeat
from Crypto.Hash import SHA3_512

def hash_password(password, rows, hashes_to_compare):
    h = SHA3_512.new()
    h.update(password.encode())
    tmp = h.hexdigest()
    if tmp in hashes_to_compare:
        print('Password correct for row: ', rows[hashes_to_compare.index(tmp)]['username'].values[0])
        print('Password: ', password)
        return password  # Return the password if it matches the hash
    return None  # Return None if password not found

def hash_passwords(passwords, rows, hashes_to_compare):
    print('Hashing passwords')
    print('Number of passwords: ', len(passwords))
    with Pool(processes=10) as pool:
        results = pool.starmap(hash_password, zip(passwords,repeat(rows), repeat(hashes_to_compare)))

    # Filter out None values (passwords not found) from results
    found_passwords = [password for password in results if password is not None]
    
    return found_passwords