import requests
import hashlib
import re


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,}$"
    check_validity = re.match(pattern, password)
    if check_validity:
        count = pwned_api_check(password)
        if count:
            print(f'"{password}" was found {count} times. You should probably change your password')
        else:
            print(f'"{password}" was NOT found. It is a good password!')
        return True
    else:
        print('Your password must contain minimum eight characters, at least one uppercase letter, one lowercase '
              'letter, one number and one special character ')
        return False


if __name__ == '__main__':
    while True:
        password_to_check = input('Input your password: ')
        if main(password_to_check):
            break
