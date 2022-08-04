import requests
import hashlib  #we can do SHA1 hashing with this lib
import sys

#below function will request our data and return a response
def request_api_data(query_char):
    # below we are sending the first 5 digits of the sha1 hash and the api will get back all the related passwords
    # starting with those 5 digits
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again.')
    return res

#check the response that comes back
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':')for line in hashes.text.splitlines())
    for h, count in hashes: #using this loop to check if any of the hashes match hash_to_check
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    #check if the password exists in response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:] #taking the first 5 char and the remainder
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)
    # print(sha1password)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... You need to change this password immediately')
        else:
            print(f'{password} was not found. Safe to use!')
    return 'Done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))