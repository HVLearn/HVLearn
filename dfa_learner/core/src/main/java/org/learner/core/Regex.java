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

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.io.File;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.HashMap;

import net.automatalib.words.Alphabet;
import net.automatalib.automata.fsa.DFA;
import net.automatalib.brics.AbstractBricsAutomaton;
import net.automatalib.automata.fsa.impl.compact.CompactDFA;
import net.automatalib.brics.BricsNFA;
import net.automatalib.brics.BricsDFA;
import net.automatalib.commons.dotutil.DOT;
import net.automatalib.util.graphs.dot.GraphDOT;
import net.automatalib.words.Word;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.State;
import dk.brics.automaton.Transition;

import net.automatalib.words.Word;
import net.automatalib.words.impl.Alphabets;


public class Regex
{
    private BricsDFA bricsDfa;
    private CompactDFA<Character> compDfa;

    private HashMap<State, Integer> stateTable       = new HashMap<>();
    private HashMap<String, Integer> transitionTable = new HashMap<>();

    private Alphabet<Character> alphabets;

    private int sinkStateId;
    private List<State> visitedStates = new ArrayList<>();

    private RegExp regexRule    = null;
    private Automaton automaton = null;

    public Regex(String rule, Alphabet<Character> alphabets) {
        this.setRule(rule);
        this.setAlphabets(alphabets);

    }

    public Regex(RegExp regexRule, Alphabet<Character> alphabets) {
        this.regexRule = regexRule;
        this.alphabets = alphabets;

    }


    public void setAlphabets(Alphabet<Character> alphabets) {
        this.alphabets = alphabets;
    }

    public void setRule(String rule) {
        if (rule == null) {
            // accept nothing
            this.regexRule = null;

        } else {
            this.regexRule = new RegExp(rule);
        }
    }


    private String get_transitionKey(int srcStateId, int dstStateId, Character input) {
        return srcStateId + "|" + dstStateId + "|" + input;
    }

    private void do_copy(State bricsState, int compStateId) {

        Iterator<Character> iter = this.alphabets.iterator();

        while (iter.hasNext()) {
            Character c = iter.next();
            State tranState = this.bricsDfa.getTransition(bricsState, c);
            if (tranState == null) {
                // Go to sink state
                this.compDfa.setTransition(compStateId, c, this.sinkStateId);
            } else {
                int stateId;
                if (this.stateTable.containsKey(tranState)) {
                    // Existing state
                    stateId = (int)this.stateTable.get(tranState);

                } else {
                    // Non-existing state
                    stateId = this.compDfa.addState(tranState.isAccept());
                    this.stateTable.put(tranState, stateId);
                }

                String tranKey = this.get_transitionKey(compStateId, stateId, c);
                if (this.transitionTable.containsKey(tranKey)) {
                    // Skip
                    continue;
                }

                this.compDfa.setTransition(compStateId, c, stateId);
                this.transitionTable.put(tranKey, 1);

                if (compStateId != stateId) {
                    // Do not do self loop twice
                    this.do_copy(tranState, stateId);
                }

            }
        }

    }


    private void do_convert() {

        this.compDfa = new CompactDFA<>(this.alphabets);

        // Copy initial state
        State initState = this.bricsDfa.getInitialState();
        this.compDfa.addInitialState(initState.isAccept());


        // Create sink state (All reject)
        this.sinkStateId = this.compDfa.addState(false);

        Iterator<Character> iter = alphabets.iterator();
        while (iter.hasNext()) {
            Character c = iter.next();
            // Self transition for all alphabets
            //sinkState.addTransition(new Transition(c, this.sinkState));
            this.compDfa.setTransition(this.sinkStateId, c, this.sinkStateId);

        }

        State bricsState = initState;
        int compStateId = this.compDfa.getInitialState();

        this.stateTable.put(bricsState, compStateId);

        this.do_copy(bricsState, compStateId);

    }


    public DFA<?, Character> getDFA() {

        // Regex string to automaton
        // https://github.com/misberner/automatalib/blob/601e6fe105c3366b0706f8f2984873a67bf13e69/adapters/brics/src/main/java/net/automatalib/brics/BricsDFA.java
        if (this.regexRule == null) {
            // Empty regular expression, accept nothing
            this.automaton = Automaton.makeEmpty();
        } else {
            this.automaton  = this.regexRule.toAutomaton();
        }

        this.bricsDfa   = new BricsDFA(this.automaton, true);

        this.do_convert();

        return this.compDfa;
    }

}
