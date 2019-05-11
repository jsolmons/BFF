#!/home/angr/.virtualenvs/angr/bin/python3

# Author: Jeremy Solmonson
# Date: 5/10/2019
# Class: University of Colorado at Colorado Springs (UCCS) CS371 - Software Testing 
# Purpose: To load a function within a larger program and fuzz the string parameter of that function
# Benefits: Finds where the program counter was modified. This indicates a potential exploitable vulnerability.
# Functions Tested in test_functions.c: vulnfunc, printf, puts, strlen, atoi, atof, atol
# Limitations: Only fuzzes single functions with the sole parameter as a string
# Future work: Modify the loadable function to accept additional parameters and various types (ints, structs, ptrs).

print("This takes about 20 second to load...")
print("Don't worry about the errors too much")

import angr
import monkeyhex
import argparse
import logging

def getFuncAddress(cfg, funcName, plt=None ):
    found = [
        addr for addr,func in cfg.kb.functions.items()
        if funcName == func.name and (plt is None or func.is_plt == plt)
        ]
    if len( found ) > 0:
        return found[0]
    else:
        raise Exception("No address found for function : "+funcName)


def binary_function_fuzzer(program, function, fuzzfile):

    # Load the program
    proj = angr.Project(program, load_options={'auto_load_libs':False})

    # Create the cfg to find the vulnerable function
    cfg = proj.analyses.CFG(fail_fast=True)

    # Get the function address
    funcAddr = getFuncAddress(cfg, function)

    # make the function stand alone - callable
    f = proj.factory.callable(funcAddr)

    # Open the fuzz file - the first item within the fuzz file is "known good" input
    with open(fuzzfile) as fuzz:
        known_good = fuzz.readline()
        f(known_good)
        correct_result = f.result_state.addr
        found_vuln = False
        # Use the remaining text within the fuzz file as input to the function
        for line in fuzz:
            f(line)
            test_result = f.result_state.addr
            # if the return addresses are different, then likey the program counter was modified
            if test_result != correct_result:
                print("Potential vulnerability with input: %s" %(line))
                found_vuln = True
    if not found_vuln:
        print("No vulnerability found")

    # Close the file
    fuzz.close()

def main():
    # Parse the arguments
    parser = argparse.ArgumentParser(description='Binary Function Fuzzer')
    parser.add_argument('-prog', dest='program', required=True, help='Program Name')
    parser.add_argument('-func',dest='function', required=True, help='Function Name')
    parser.add_argument('-file',dest='fuzzfile', required=True, help='Fuzzer Input Filename')
    args = parser.parse_args()

    # Set the verbosity
    # https://github.com/angr/angr-doc/blob/master/docs/faq.md
    logging.getLogger('angr').setLevel('ERROR')

    # Begin the BFF
    binary_function_fuzzer(args.program, args.function, args.fuzzfile)

if __name__ == "__main__":
    main()
