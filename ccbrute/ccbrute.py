#
# ccbrute.py
#
# By 5anti
#
# Coded on March 31, 2023
#


import sys, chardet


# Fancy banner :)
banner = '''
       ______ ______ ____                __                        
      / ____// ____// __ ) _____ __  __ / /_ ___      ____   __  __
     / /    / /    / __  |/ ___// / / // __// _ \    / __ \ / / / /
    / /___ / /___ / /_/ // /   / /_/ // /_ /  __/_  / /_/ // /_/ / 
    \____/ \____//_____//_/    \__,_/ \__/ \___/(_)/ .___/ \__, /  
                                                  /_/     /____/
    [ ---==>  By 5anti (https://github.com/5anti) <==--- ]
    [ ---==>        Coded on March 31, 2023       <==--- ]
     
'''

def decrypt(message, extra=''):
    """Use every key possible to decrypt
    the inputted string and store each
    shifted string in 'checklist'."""

    alphabet = 'abcdefghijklmnopqrstuvwxyz'

    global checklist
    checklist = []

    # Add extra characters to alphabet if provided by user.
    alphabet += extra

    # Attempt to decrypt inputted string with every possible key in alphabet.
    # Amount of keys may vary depending on size of alphabet.
    for key in range(1, len(alphabet)):
        shifted_string = []

        for letter in message:
            if letter in alphabet:
                shifted_index = alphabet.index(letter) - key
                shifted_letter = alphabet[shifted_index].upper()
                shifted_string.append(shifted_letter)

        # Append each shifted string to "checklist" for comparing phase.
        checklist.append([''.join(shifted_string), key])


def compare(file):
    """Loop through the inputted wordlist
    and check if any words match any of
    the strings in 'checklist'."""
    try:
        results = []
        
        # Encoding detection
        with open(file, 'rb') as wordlist:
            for line in wordlist.readlines():
                encoding = chardet.detect(line)

        # Access file. Remove any escape sequences.
        with open(file, 'r', encoding=encoding['encoding']) as wordlist:
            words = [word.replace('\n', '').upper() for word in wordlist.readlines()]

            # Compare each string in wordlist with each shifted string in "checklist". Append results to "results".
            for word in words:
                for pair in checklist:
                    if word == pair[0]:
                        result_msg = '[+] MATCH FOUND!\n\t=> Word: {}\n\t=> Key: {}\n'.format(pair[0], pair[1])
                        results.append(result_msg)

        # Convert "results" to set to remove any duplicate results. Print results.
        for result in set(results):
            print(result)

    except FileNotFoundError:
        print('[!] File "{}" does not exist.\n'.format(file))


# Run if user does not input a third argument.
if len(sys.argv) < 4:
    # This prevents the program from running into an IndexError.
    sys.argv.append('')

    try:
        print('{}\n[*] Cracking string...'.format(banner))
        decrypt(sys.argv[1], extra=sys.argv[3])
        compare(sys.argv[2])
    except IndexError:
        print('[!] You must provide the correct arguments.\n')
    except KeyboardInterrupt:
        print('[*] Process terminated.\n')
# Run if user does input a third argument.
else:
    try:
        print('{}\n[*] Cracking string...'.format(banner))
        decrypt(sys.argv[1], extra=sys.argv[3])
        compare(sys.argv[2])
    except IndexError:
        print('[!] You must provide the correct arguments.\n')
    except KeyboardInterrupt:
        print('[*] Process terminated.\n')
    