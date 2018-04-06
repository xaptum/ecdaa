#!/usr/bin/env python3

import argparse
import os
import errno

big_pattern = 'XXX'
fp_pattern = 'YYY'
curve_pattern = 'ZZZ'

big_replacements = {
    '64': {
        'BN254': '256_56',
        'BN254CX': '256_56',
        'BLS383': '384_56',
        'FP256BN': '256_56'},
    '32': {
        'BN254': '256_28',
        'BN254CX': '256_28',
        'BLS383': '384_29',
        'FP256BN': '256_28'},
    '16': {
        'BN254': '256_13',
        'BN254CX': '256_13'}
}

fp_replacements = {
    '64': {
        'BN254': 'BN254',
        'BN254CX': 'BN254CX',
        'BLS383': 'BLS383',
        'FP256BN': 'FP256BN'},
    '32': {
        'BN254': 'BN254',
        'BN254CX': 'BN254CX',
        'BLS383': 'BLS383',
        'FP256BN': 'FP256BN'},
    '16': {
        'BN254': 'BN254',
        'BN254CX': 'BN254CX'}
}

def translate_file_name(original_file_name, wordsize, curve, output_directory):
    moved_path = original_file_name.replace(toplevel_dir, output_directory)

    big_replace = big_replacements[wordsize][curve]
    fp_replace = fp_replacements[wordsize][curve]
    return moved_path.replace(big_pattern, big_replace) \
                     .replace(fp_pattern, fp_replace) \
                     .replace(curve_pattern, curve)

def get_processed_file_names(template_file_name, wordsize, curve_list, output_directory, toplevel_dir):
    file_names = set()
    for curve in curve_list:
        new_file_name = translate_file_name(template_file_name, wordsize, curve, output_directory)
        file_names.add(new_file_name)

    return file_names

def expand_template(input_file, wordsize, curve_list, output_directory):
    for curve in curve_list:
        with open(input_file, 'r') as template_file:
            big_replace = big_replacements[wordsize][curve]
            fp_replace = fp_replacements[wordsize][curve]
            expanded_string = template_file.read() \
                                           .replace(big_pattern, big_replace) \
                                           .replace(fp_pattern, fp_replace) \
                                           .replace(curve_pattern, curve)

        output_file_name = translate_file_name(input_file, wordsize, curve, output_directory)
        os.makedirs(os.path.dirname(output_file_name), exist_ok=True)

        with open(output_file_name, 'w') as output_file:
            output_file.write(expanded_string)

def generate_top_level_header(input_file, wordsize, curve_list, output_directory, use_tpm):
    with open(input_file, 'r') as template_file:
        input_lines = template_file.readlines()

    output_file_name = input_file.replace(toplevel_dir, output_directory)
    os.makedirs(os.path.dirname(output_file_name), exist_ok=True)

    with open(output_file_name, 'w') as output_file:
        for line in input_lines:
            if '#include' in line and (big_pattern in line or fp_pattern in line or curve_pattern in line):
                for curve in curve_list:
                    big_replace = big_replacements[wordsize][curve]
                    fp_replace = fp_replacements[wordsize][curve]
                    output_file.write(line.replace(big_pattern, big_replace) \
                                          .replace(fp_pattern, fp_replace) \
                                          .replace(curve_pattern, curve))
            elif not use_tpm and ('tpm' in line or 'TPM' in line):
                pass
            else:
                output_file.write(line)

def print_file_names(file_name_list):
    for file_name in file_name_list:
        print(file_name, end=';')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Expand a given template source file')
    parser.add_argument('--template', help='template file to process')
    parser.add_argument('--word-size', type=str, help='word-size in bits (64, 32, 16)')
    parser.add_argument('--curves', type=str, help='comma-separated list of curves to use')
    parser.add_argument('--names-only', action='store_true', help="don't process the files, just output the new names")
    parser.add_argument('--out-dir', help='directory to move expanded files')
    parser.add_argument('--top-level-dir', help='top-level directory of project')
    parser.add_argument('--top-level-header', action='store_true', help='the given template is the top-level header file')
    parser.add_argument('--use-tpm', action='store_true', help='use tpm-enabled functions')
    args = parser.parse_args()

    input_file = args.template
    wordsize = args.word_size
    curve_list = args.curves.split(',')
    output_directory = args.out_dir
    toplevel_dir = args.top_level_dir

    if not args.names_only:
        if not args.top_level_header:
            expand_template(input_file, wordsize, curve_list, output_directory)
        else:
            generate_top_level_header(input_file, wordsize, curve_list, output_directory, args.use_tpm)

    file_name_list = get_processed_file_names(input_file, wordsize, curve_list, output_directory, toplevel_dir)
    print_file_names(file_name_list)
