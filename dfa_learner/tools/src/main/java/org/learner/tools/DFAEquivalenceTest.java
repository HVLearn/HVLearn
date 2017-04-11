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

import java.io.File;
import java.io.IOException;

import net.automatalib.words.Word;
import net.automatalib.words.Alphabet;
import net.automatalib.automata.fsa.DFA;

import org.apache.commons.cli.*;

import org.learner.core.Utils;
import org.learner.core.Regex;

public class DFAEquivalenceTest
{
    public static void main(String[] args) throws IOException {

        // Parse argument
        Options options = new Options();

        /*
        Option dfaFileAOpt = new Option("A", "dfa-A", true, "DFA (A) file path");
        dfaFileAOpt.setRequired(true);

        Option dfaFileBOpt = new Option("B", "dfa-B", true, "DFA (B) file path");
        dfaFileBOpt.setRequired(true);
        */


        Option ruleFileOpt      = new Option("r", "rule-file", true, "Rule file path (Regular expression rule)");
        Option ruleDfaFileOpt   = new Option("d", "rule-dfa-file", true, "DFA file path with expected rule");
        Option alphabetFileOpt  = new Option("a", "alphabet-file", true, "Alphabet file path");

        alphabetFileOpt.setRequired(true);

        /*
        options.addOption(dfaFileAOpt);
        options.addOption(dfaFileBOpt);
        */

        options.addOption(alphabetFileOpt);
        options.addOption(ruleFileOpt);
        options.addOption(ruleDfaFileOpt);

        CommandLineParser parser    = new DefaultParser();
        HelpFormatter formatter     = new HelpFormatter();

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

            if (cmd.getOptionValue("rule-file") == null && cmd.getOptionValue("rule-dfa-file") == null) {
                throw new ParseException("[FAILED] rule-file/rule-dfa-file required");
            }

            if (cmd.getOptionValue("rule-file") != null && cmd.getOptionValue("rule-dfa-file") != null) {
                throw new ParseException("[FAILED] rule-file/rule-dfa-file required");
            }

            if (cmd.getArgs().length == 0) {
                throw new ParseException("[FAILED] DFA file(s) required");
            }

        } catch (ParseException e) {
            System.err.println(e.getMessage());
            formatter.printHelp("DFAEquivalenceTest [DFA file ...]", options);
            System.exit(-1);
        }

        // Do it
        // Alphabets
        File alphabetFile               = new File(cmd.getOptionValue("alphabet-file"));
        Alphabet<Character> alphabets   = Utils.readAlphabets(alphabetFile);

        // Rule DFA
        String ruleFileName     = cmd.getOptionValue("rule-file");
        String ruleDfaFileName  = cmd.getOptionValue("rule-dfa-file");

        DFA<?, Character> ruleDfa;

        if (ruleFileName != null) {
            // Convert (regex) rule to DFA
            File ruleFile   = new File(ruleFileName);
            String ruleStr  = Utils.readName(ruleFile);
            Regex regex     = new Regex(ruleStr, alphabets);
            ruleDfa         = regex.getDFA();

            // Save rule to DFA file
            File dotFile = new File(ruleFileName + ".dot");
            File dfaFile = new File(ruleFileName + ".dfa");
            Utils.writeDFA(ruleDfa, alphabets, dfaFile);
            Utils.writeDOT(ruleDfa, alphabets, dotFile);

        } else {
            File dfaFile    = new File(ruleDfaFileName);
            ruleDfa         = Utils.readDFA(dfaFile, alphabetFile);
        }

        // DFAs
        String[] dfaFileEntries         = cmd.getArgs();

        // Read all DFAs and do equivalent test with rule DFA

        for (int i = 0; i < dfaFileEntries.length; i++) {

            File dfaFile            = new File(dfaFileEntries[i]);
            DFA<?, Character> dfa   = Utils.readDFA(dfaFile, alphabetFile);

            Word<Character> word    = Utils.equivalenceTestDFA(ruleDfa, dfa, alphabets);

            System.out.print(dfaFileEntries[i] + ":\t");
            if (word == null) {
                System.out.println("NONE");
                continue;
            }

            String unEqString = Utils.getWordString(word);
            System.out.println(unEqString);

        }


        /*
        File dfaFileA        = new File(cmd.getOptionValue("dfa-A"));
        File dfaFileB        = new File(cmd.getOptionValue("dfa-B"));

        DFA<?, Character> dfaA = Utils.readDFA(dfaFileA, alphabetFile);
        DFA<?, Character> dfaB = Utils.readDFA(dfaFileB, alphabetFile);
        */





    }
}
