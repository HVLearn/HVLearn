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

package org.learner.tools;

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

import org.apache.commons.cli.*;

import org.learner.core.Regex;
import org.learner.core.Utils;


public class RegexToDFA
{

    public static void main(String[] args) throws IOException
    {

        // Parse argument
        Options options = new Options();

        Option ruleFileOpt = new Option("r", "rule-file", true, "Rule file path");
        ruleFileOpt.setRequired(true);

        Option alphabetFileOpt = new Option("a", "alphabet-file", true, "Alphabet file path");
        alphabetFileOpt.setRequired(true);

        Option outFileOpt = new Option("o", "output-file", true, "Output file path");

        options.addOption(ruleFileOpt);
        options.addOption(alphabetFileOpt);
        options.addOption(outFileOpt);

        CommandLineParser parser    = new DefaultParser();
        HelpFormatter formatter     = new HelpFormatter();

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            formatter.printHelp("RegexToDFA", options);
            System.exit(-1);
        }


        // Do it
        File ruleFile       = new File(cmd.getOptionValue("rule-file"));
        File alphabetFile   = new File(cmd.getOptionValue("alphabet-file"));

        String outFileName  = cmd.getOptionValue("output-file", ruleFile.getAbsolutePath());

        File dotFile = new File(outFileName + ".dot");
        File dfaFile = new File(outFileName + ".dfa");


        Alphabet<Character> alphabets = Utils.readAlphabets(alphabetFile);
        String ruleStr = Utils.readName(ruleFile);
        //String ruleStr = "[aA]{1}\\.[aA]{1}\\.[aA]{1}";
        //String ruleStr = "xn--[^\\*]+\\.[aA]{3}";

        Regex regex = new Regex(ruleStr, alphabets);
        DFA<?, Character> dfa = regex.getDFA();

        Utils.writeDOT(dfa, alphabets, dotFile);
        Utils.writeDFA(dfa, alphabets, dfaFile);

    }


}
