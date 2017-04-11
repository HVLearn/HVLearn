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

import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.io.File;

import net.automatalib.automata.fsa.DFA;
import net.automatalib.words.Alphabet;

import org.apache.commons.cli.*;

import org.learner.core.Utils;


public class GenDot {

	public static void main(String[] args)
            throws UnsupportedEncodingException, IOException {

        // Parse argument
        Options options = new Options();
        Option alphabetFileOpt = new Option("a", "alphabet-file", true, "Alphabet file path");
        alphabetFileOpt.setRequired(true);

        options.addOption(alphabetFileOpt);

        CommandLineParser parser    = new DefaultParser();
        HelpFormatter formatter     = new HelpFormatter();

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            formatter.printHelp("GetDot", options);
            System.exit(-1);
        }

        List<String> dfaFileList = cmd.getArgList();

        // Do it
        File alphabetFile   = new File(cmd.getOptionValue("alphabet-file"));
        Alphabet<Character> alphabets = Utils.readAlphabets(alphabetFile);

        Iterator<String> iter = dfaFileList.iterator();

        while (iter.hasNext()) {
            String dfaFilename = iter.next();
            File dfaFile = new File(dfaFilename);
            File dotFile = new File(dfaFile.getAbsolutePath() + ".dot");

            DFA<?, Character> dfa = Utils.readDFA(dfaFile, alphabetFile);
            Utils.writeDOT(dfa, alphabets, dotFile);
        }

    }
}
