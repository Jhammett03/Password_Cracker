import hashlib
import string

import bcrypt
import random
import time
import nltk
import multiprocessing
import Crypto
from collections import defaultdict
import matplotlib.pyplot as plt


"""TASK 1"""
#takes string data input and returns its SHA256 hash in hexadecimal format
def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def trunc_hash(hash: str, numbits: int) -> str:
    trunc = hash[:int(numbits/4)]
    num = int(trunc, 16)
    bitmask = (1 << numbits) - 1
    return str(num & bitmask)

def hamming_distance(str1: str, str2: str)-> int:
    if len(str1) != len(str2):
        raise ValueError("String lengths must be the same")
    else:
        count = 0
        for i in range(len(str1)):
            if str1[i] != str2[i]:
                count += 1
    return count

def find_hamming_distance_1():
    characters = string.ascii_letters
    str = ''.join(random.choice(characters) for _ in range(10))
    for i in range(len(str)):
        char = str[i]
        ascii = ord(char)
        modifiedchar = chr(ascii ^ (1 << i))
        modified = str[:i] + modifiedchar + str[i+1:]
        if hamming_distance(str, modified) == 1:
            return str, modified
    return None, None

def find_collision(bits, max_attempts):
    seen = {}
    start_time = time.time()
    for attempt in range(1, max_attempts):
        str = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        h = trunc_hash(sha256_hash(str), bits)
        if h in seen.keys():
            end_time = time.time()

            return seen[h], str, attempt, end_time - start_time
        else:
            seen[h] = str
    return None, None, max_attempts, time.time() - start_time

def task1_a():
    print('Hashes of arbitrary inputs:\n')
    for item in ["Hello World", "Python", "Cryptography"]:
        print(f'Data: {item} -> {sha256_hash(item)}\n')

def task1_b():
    print('Strings with Hamming distance of 1:\n')
    for i in range(3):
        s1, s2 = find_hamming_distance_1()
        h1, h2 = sha256_hash(s1), sha256_hash(s2)
        print(f'Data: ({s1}, {s2}) -> ({h1}, {h2})\n')

def task1_c():
    ins = []
    times = []
    bits = []
    max_attempts = 10000000
    for bit_num in range(8, 52, 2):
        collision = find_collision(bit_num, max_attempts)
        if collision != (None, None):
            ins.append(collision[2])
            times.append(collision[3])
            bits.append(bit_num)
        else:
            raise TimeoutError(f'Could not find collision, bits: {bit_num}, attempts: {max_attempts}\n')
    print(ins, times, bits)
    return ins, times, bits

def make_plot(x, y, title):
    plt.plot(x,y)
    plt.title(title)
    plt.savefig(f'{title}.png')
    plt.show()


"""TASK 2"""
# Crack password in a given chunk, stopping if another process finds it
def crack_password_chunk(chunk, stored_hash, result_dict, progress_queue, user, stop_event):
    for idx, word in enumerate(chunk):
        if stop_event.is_set():  # Check if another process found the password
            return
        if bcrypt.checkpw(word.encode(), stored_hash.encode()):
            result_dict[user] = word
            print(f"[SUCCESS] User '{user}' cracked! Password: {word}")
            stop_event.set()  # Notify all other processes to stop
            return
        if idx % 1000 == 0: # helpful for showing progress of how many attempts
            progress_queue.put((user, idx))


def crack_bcrypt_passwords_parallel(shadow_file, wordlist, num_processes=4):
    """Crack bcrypt passwords using multiprocessing with an early stop mechanism."""
    cracked_passwords = {}
    with open(shadow_file, 'r') as file:
        for line in file:
            user, hash_str = line.strip().split(':', 1)
            _, algo, workfactor, salt_hash = hash_str.split('$')
            salt = salt_hash[:22]
            stored_hash = f"$2b${workfactor}${salt}{salt_hash[22:]}"

            chunk_size = len(wordlist) // num_processes
            chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]

            manager = multiprocessing.Manager()
            result_dict = manager.dict()
            progress_queue = multiprocessing.Queue()
            stop_event = multiprocessing.Event()  # New event for early stopping

            processes = []
            for chunk in chunks:
                p = multiprocessing.Process(target=crack_password_chunk,
                                            args=(chunk, stored_hash, result_dict, progress_queue, user, stop_event))
                processes.append(p)
                p.start()

            total_checked = 0
            while any(p.is_alive() for p in processes):
                while not progress_queue.empty():
                    user, checked = progress_queue.get()
                    total_checked += checked
                    print(f"[STATUS] Cracking '{user}': Checked {total_checked}/{len(wordlist)} passwords...")

            for p in processes:
                p.join()

            if user in result_dict:
                cracked_passwords[user] = result_dict[user]

    return cracked_passwords


if __name__ == "__main__":
    #Task 1: Part a
    print("-------------- Task 1: Part a --------------\n")
    task1_a()
    print("-------------- Task 1: Part b --------------\n")
    task1_b()
    print("-------------- Task 1: Part c --------------\n")
    result = task1_c()
    make_plot(result[2], result[1], "Digest Size vs Time")
    make_plot(result[2], result[0], "Digest Size vs Number of Inputs")
    print('\n-------------- Task 2 --------------\n')
    do = True
    while do:
        #userin = input("Do you want to run task 2? Y/N ")
        userin = 'N'
        if userin == 'Y':
            nltk.download('words') #note: if words is already downloaded it will show an error message, but will keep running
            wordlist = [w for w in nltk.corpus.words.words() if 6 <= len(w) <= 10]

            shadow_file = 'shadow.txt'  # Change to actual shadow file path
            # Safe number of processes; Note: I'm impatient and made this
            # number probably larger than it shouldve been, made using the computer nearly impossible, but it didnt crash
            num_processes = max(1, multiprocessing.cpu_count() - 1)
            print(f"Using {num_processes} processes for password cracking...")

            cracked_passwords = crack_bcrypt_passwords_parallel(shadow_file, wordlist, num_processes=num_processes)
            print(cracked_passwords)
        elif userin == 'N':
            do = False
