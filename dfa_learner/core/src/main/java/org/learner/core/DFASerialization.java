/*
 * Copyright (c) 2017 Columbia University.
 * Network Security Lab, Columbia University, New York, NY, USA
 *
 * This file is part of HVLearn Project, https://github.com/HVLearn/.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.learner.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import net.automatalib.automata.concepts.StateIDs;
import net.automatalib.automata.fsa.DFA;
import net.automatalib.automata.fsa.NFA;
import net.automatalib.automata.fsa.impl.compact.CompactDFA;
import net.automatalib.automata.fsa.impl.compact.CompactNFA;
import net.automatalib.serialization.SerializationProvider;
import net.automatalib.util.automata.Automata;
import net.automatalib.words.Alphabet;
import net.automatalib.commons.util.IOUtil;
import net.automatalib.words.Alphabet;
import net.automatalib.words.impl.Alphabets;

public class DFASerialization implements SerializationProvider {

    public DFASerialization() {}

    @Override
    public CompactDFA<Integer> readGenericDFA(InputStream is) throws IOException {
        // we DO NOT want to close the input stream
        @SuppressWarnings("resource")
        Scanner sc = new Scanner(IOUtil.asUncompressedInputStream(is));

        int numStates = sc.nextInt();
        int numSymbols = sc.nextInt();

        Alphabet<Integer> alphabet = Alphabets.integers(0, numSymbols - 1);

        CompactDFA<Integer> result = new CompactDFA<>(alphabet, numStates);

        // This is redundant in practice, but it is in fact not specified by
        // CompactDFA
        // how state IDs are assigned
        int[] states = new int[numStates];

        // Parse states
        states[0] = result.addIntInitialState(sc.nextInt() != 0);

        for (int i = 1; i < numStates; i++) {
            states[i] = result.addIntState(sc.nextInt() != 0);
        }

        // Parse transitions
        for (int i = 0; i < numStates; i++) {
            int state = states[i];
            for (int j = 0; j < numSymbols; j++) {
                int succ = states[sc.nextInt()];
                result.setTransition(state, j, succ);
            }
        }

        return result;
    }

    @Override
    public CompactNFA<Integer> readGenericNFA(InputStream is) throws IOException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public <I> void writeNFA(NFA<?, I> nfa, Alphabet<I> alphabet, OutputStream os) throws IOException {
        // TODO Auto-generated method stub

    }

    @Override
    public <I> void writeDFA(DFA<?, I> dfa, Alphabet<I> alphabet, OutputStream os) throws IOException {
        doWriteDFA(dfa, alphabet, os);
    }


    private final <S, I> void doWriteDFA(DFA<S, I> dfa, Alphabet<I> alphabet, OutputStream os) throws IOException {
        boolean partial = Automata.hasUndefinedInput(dfa, alphabet);
        int numDfaStates = dfa.size();
        int numStates = numDfaStates;

        int numInputs = alphabet.size();
        PrintStream ps = new PrintStream(os);
        ps.printf("%d %d\n", numStates, numInputs);

        StateIDs<S> stateIds = dfa.stateIDs();

        S initState = dfa.getInitialState();
        int initId = stateIds.getStateId(initState);

        List<S> orderedStates = new ArrayList<>(numDfaStates);
        orderedStates.add(initState);

        ps.printf("%d ", dfa.isAccepting(initState) ? 1 : 0);

        for (int i = 1; i < numDfaStates; i++) {
            S state = stateIds.getState(i);
            if (i == initId) {
                state = stateIds.getState(0);
            }
            ps.printf("%d ", dfa.isAccepting(state) ? 1 : 0);
            orderedStates.add(state);
        }
        ps.println();
        for (S state : orderedStates) {
            for (I sym : alphabet) {
                S target = dfa.getSuccessor(state, sym);
                int targetId = numDfaStates;
                if (target != null) {
                    targetId = stateIds.getStateId(target);
                    if (targetId == initId) {
                        targetId = 0;
                    } else if (targetId == 0) {
                        targetId = initId;
                    }
                }
                ps.printf("%d ", targetId);
            }
            ps.println();
        }
    }

}
