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


def get_state_neighbors(dfa, sid):
    """
    return a tuple (state, symbol) for all states that can be accesed by one
    transition from the input state.
    """
    neighbors = []
    n_set = set([])
    for arc in dfa[sid].arcs:
        src_id = arc.srcstate
        dst_id = arc.nextstate
        symbol = dfa.isyms.find(arc.ilabel)
        if dst_id in n_set or dst_id == src_id:
            continue
        n_set.add(dst_id)
        neighbors.append((dst_id, symbol))
    return neighbors


def _get_path_dfs(dfa, src_id, dst_id, visited, differences, current_input):
    """
    Return an input for every simple path from src_id to dst_id in dfa given
    that we already have visited the "visited" states and have an input of
    current_input. The resulting differences found are stored in the respective
    argument variable.
    """

    if src_id == dst_id:
        differences.append(''.join(current_input))
        return

    neighbors = get_state_neighbors(dfa, src_id)
    for (sid, symbol) in neighbors:
        if sid in visited:
            continue
        visited.append(sid)
        current_input.append(symbol)
        _get_path_dfs(dfa, sid, dst_id, visited, differences, current_input)
        visited.pop()
        current_input.pop()



def get_simple_paths_input(dfa, target_state_id):
    """
    Return inputs exercising all paths from the initial state to the target
    state.
    """

    differences = []
    visited = [0]
    current_input = []

    # For each state get a set of pairs (state, symbol) where symbol is taking
    # us to the state "state".
    neighbors = get_state_neighbors(dfa, 0)

    for (sid, symbol) in neighbors:
        visited.append(sid)
        current_input.append(symbol)
        _get_path_dfs(dfa, sid, target_state_id, visited,
                      differences, current_input)
        visited.pop()
        current_input.pop()

    return differences


def RCADiff(dfa1, dfa2, alphabet):
    """
    Compute the set of root cause differences and return
    """
    prod_dfa = DFA(alphabet)

    # This will give us the id of the state in the product DFA.
    get_state = lambda sid1, sid2, len2: sid1 * len2 + sid2

    # Points of exposure is a subset of the non accepting states in the
    # product automaton
    poe = []

    for (s1, s2) in product(dfa1.states, dfa2.states):
        src_id = get_state(s1.stateid, s2.stateid, len(dfa2.states))
        t1 = { dfa1.isyms.find(arc.ilabel): arc.nextstate for arc in s1 }
        t2 = { dfa2.isyms.find(arc.ilabel): arc.nextstate for arc in s2 }
        for char in alphabet:
            dst_id = get_state(t1[char], t2[char],
                               len(dfa2.states))
            prod_dfa.add_arc(src_id, dst_id, char)

        prod_dfa[src_id].final = s1.final and s2.final
        if s1.final != s2.final:
            poe.append(src_id)

    # Minimize the product dfa to optimize subsequent computations
    #  prod_dfa.minimize()

    # Product DFA is ready. Iterate with a DFS to get all paths to the points
    # of exposure
    differences = []
    for sid in poe:
        differences += get_simple_paths_input(prod_dfa, sid)
    return differences


##################################


def parse_alphabet(filename):
    """
    Parse an alphabet file
    """
    with open(filename, 'r') as f:
        return [x.rstrip() for x in f.readlines()]


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



def get_single_dfa_strings(dfa_file, alphabet_file):
    """
    Get the simple paths that lead to accepting states for a single automaton.
    """
    alphabet = parse_alphabet(alphabet_file)
    dfa = load_learnlib_dfa(dfa_file, alphabet)

    targets = []
    for state in dfa:
        if state.final:
            targets.append(state.stateid)
    diffs = []
    for sid in targets:
        diffs += get_simple_paths_input(dfa, sid)
    return diffs


##################################

def main(argc, argv):

    if argc < 3:
        print 'Usage: {} [dfa1 filename] [dfa2 filename] '.format(argv[0]) + \
            '[alphabet filename]'
        exit()


    if argc == 3:
        for diff in get_single_dfa_strings(argv[1], argv[2]):
            print diff
        return


    alphabet_filename = argv[3]
    dfa2_filename = argv[2]
    dfa1_filename = argv[1]

    alphabet = parse_alphabet(alphabet_filename)
    dfa1 = load_learnlib_dfa(dfa1_filename, alphabet)
    dfa2 = load_learnlib_dfa(dfa2_filename, alphabet)

    for diff in RCADiff(dfa1, dfa2, alphabet):
        print diff

if __name__ == '__main__':
    main(len(argv), argv)
