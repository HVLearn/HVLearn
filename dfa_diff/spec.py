"""
Copyright (c) 2017 Columbia University.
Network Security Lab, Columbia University, New York, NY, USA

This file is part of HVLearn Project, https://github.com/HVLearn/.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from pythondfa import PythonDFA as DFA

from sys import argv
from itertools import product


def parse_alphabet(filename):
    """
    Parse an alphabet file
    """
    with open(filename, 'r') as f:
        return [x.rstrip() for x in f.readlines()]

def save_learnlib_dfa(dfa, filename, alphabet):
    """
    """
    num_states = len(dfa.states)
    alphabet_size = len(alphabet)
    is_final_array = []
    for state in dfa:
        is_final_array.append(str(int(state.final)))

    with open(filename, 'w') as f:

        f.write('{} {}\n'.format(num_states, alphabet_size))
        f.write(' '.join(is_final_array) + "\n")
        for state in dfa:
            state_map = { dfa.isyms.find(arc.ilabel) : arc.nextstate for arc in state.arcs }
            target_state = []
            for symbol in alphabet:
                target_state.append(str(state_map[symbol]))
            f.write(' '.join(target_state) + "\n")



def load_learnlib_dfa(filename, alphabet):
    """
    Create a python DFA from a learnlib dfa file format. The format is as
    follows:
    [num of states] [alphabet size]
    [0/1 array denoting if each state is accepting/rejecting]
    [transitions for each state]
    """
    dfa = DFA(alphabet)
    with open(filename, 'r') as f:
        for counter, line in enumerate(f.readlines()):
            s = line.rstrip().split()
            # read file
            if counter == 0:
                num_states = int(s[0])
                alphabet_size = int(s[1])
            elif counter == 1:
                is_final_array = [bool(int(b)) for b in s]
            else:
                cur_state_id = counter - 2
                for i, dst in enumerate(s):
                    dfa.add_arc(cur_state_id, int(dst), alphabet[i])
                dfa[cur_state_id].final = is_final_array[cur_state_id]
    return dfa


def main(argc, argv):

    if argc < 4:
        print 'Usage: {} [alphabet file] [dfa_1] ... [dfa_n]'.format(argv[0])
        return


    dfa_list = []
    alphabet = parse_alphabet(argv[1])
    for filename in argv[2:]:
        dfa_list.append(load_learnlib_dfa(filename, alphabet))

    dfa_inter = dfa_list[0]
    for dfa in dfa_list[1:]:
        dfa_inter.intersect(dfa)

    dfa.minimize()
    save_learnlib_dfa(dfa, 'dfa_spec.txt', alphabet)






if __name__ == '__main__':
    main(len(argv), argv)

