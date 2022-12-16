#!/usr/bin/python3

import os
import argparse
from math import log
from pathlib import Path

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def load_words_from_file_and_put_score(freq_words_path: Path):

    if not freq_words_path.exists():
        raise FileFileNotFoundError

    with freq_words_path.open('r') as words_file:
        words = words_file.read().split() # extract words from file path
        wordcost = dict((k, log((i+1)*log(len(words)))) for i,k in enumerate(words))
        maxword = max(len(x) for x in words)

    return wordcost, maxword

def load_cipher_text(cipher_text_path: Path):

    if not cipher_text_path.exists():
        raise FileFileNotFoundError

    with cipher_text_path.open('r') as cipher_file:
        cipher_text = cipher_file.read()
        return cipher_text

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

def break_affine(cipher_text: str, split_space_func):
    print(f"[*] Start breaking cipher text:\n{cipher_text}")
    plain_texts = []
    for z in range(26):
        if gcd(z, 26) != 1:
            continue 
        for x in range(26):
            prob_cipher = []
            word_dicts = {}
            prob_cipher = [alphabet[(i*z+x)%26] for i in range(26)]
            for cnt in range(26):
                word_dicts[prob_cipher[cnt]] = alphabet[cnt]
            plain_texts.append(split_space_func(cipher_text.translate(str.maketrans(word_dicts)).lower()))
    max_of_plain_text = len(cipher_text)*2
    main_plain_text_index = 0
    for cnt in range(len(plain_texts)):
        if max_of_plain_text > len(plain_texts[cnt]):
            max_of_plain_text = len(plain_texts[cnt])
            main_plain_text_index = cnt
    print(f"[*] Decrypted Plain text: \n{plain_texts[main_plain_text_index]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cipher-path', help="Path to cipher text file", type=str, required=True, dest="cipher_text_path")
    parser.add_argument('-f', '--freq-words-path', help="Path to frequency words", type=str, required=True, dest="freq_words_path")
    parser.add_argument('-s', '--speed', help="Speed up breaking process(only for brute force)", action='store_true', required=False, dest="speed_up")
    args = parser.parse_args()

    if args.speed_up:
        from proj_utils import utils
        wordcost, maxword = load_words_from_file_and_put_score(Path(args.freq_words_path))
        split_space_func = lambda string: utils.infer_spaces(string, wordcost, maxword)
    else:
        try:
            import wordninja
            split_space_func = lambda string: " ".join(wordninja.split(string))
        except ImportError:
            print("[*] Cannot import wordninja. install wordninja package or use speed up option")
            exit()
    
    cipher_text = load_cipher_text(Path(args.cipher_text_path))
    break_affine(cipher_text, split_space_func)
