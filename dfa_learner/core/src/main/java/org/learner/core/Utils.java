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

import de.learnlib.api.Query;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

import net.automatalib.words.Word;
import net.automatalib.words.Alphabet;
import net.automatalib.words.impl.Alphabets;
import net.automatalib.automata.concepts.StateIDs;
import net.automatalib.automata.fsa.DFA;
import net.automatalib.automata.fsa.NFA;
import net.automatalib.automata.fsa.impl.compact.CompactDFA;
import net.automatalib.automata.fsa.impl.compact.CompactNFA;
import net.automatalib.commons.util.IOUtil;
import net.automatalib.serialization.SerializationProvider;
import net.automatalib.util.automata.Automata;
import net.automatalib.util.automata.equivalence.DeterministicEquivalenceTest;
import net.automatalib.util.graphs.dot.GraphDOT;

public class Utils
{

    public static String getWordString(Word<Character> word) {
        String str = "";
        String wordStr = word.toString();

        if (word.size() == 0) {
            return str;
        }

        // Remove blank between characters
        for (int i = 0; i < wordStr.length(); i++) {
            if (i % 2 != 1) {
                str += wordStr.charAt(i);
            }
        }
        return str;

    }

    public static String getQueryString(Query<Character, Boolean> query) {
        String qstr = "";
        Word<Character> word = query.getInput();
        return Utils.getWordString(word);
    }

    public static Alphabet<Character> readAlphabets(File file) throws IOException {

        FileReader fileReader = new FileReader(file);
        String line = null;
        List<Character> lst = new ArrayList<Character>();

        BufferedReader bufferedReader = new BufferedReader(fileReader);

        while ((line = bufferedReader.readLine()) != null) {
            // read line by line
            // one character per each line
            lst.add(line.charAt(0));
        }
        bufferedReader.close();

        // Assign list to Alphabet List
        return Alphabets.fromList(lst);

    }

    public static void writeAlphabet(Alphabet<Character> alphabets, File file) throws IOException {
        int size = alphabets.size();
        PrintWriter writer = new PrintWriter(file);
        int index = 0;
        while (index < size) {

            if (index != 0) {
                writer.println();
            }
            writer.print(alphabets.getSymbol(index));
            index = index + 1;
        }
        writer.close();

    }


    public static DFA<?, Character> readDFA(File dfaFile, File alphabetFile)
        throws UnsupportedEncodingException, IOException {

        // Read serialize DFA file
        InputStream inStream            = new FileInputStream(dfaFile);
        DFASerialization serialization  = new DFASerialization();

        Alphabet<Character> alphabets   = Utils.readAlphabets(alphabetFile);
        DFA<?, Character> dfa = serialization.readCustomDFA(inStream, alphabets);

        return dfa;
    }


    public static void writeDFA(DFA<?, Character> dfa, Alphabet<Character> alphabets, File file)
        throws IOException {
        DFASerialization serial = new DFASerialization();
        OutputStream os = new FileOutputStream(file);
        serial.writeDFA(dfa, alphabets, os);
        os.close();

    }

    public static void writeDOT(DFA<?, Character> dfa, Alphabet<Character> alphabets, File file)
        throws FileNotFoundException, UnsupportedEncodingException, IOException {

        Writer writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(file), "utf-8"));

        GraphDOT.write(dfa, alphabets, writer);
        writer.close();

        // Replace NULL character with the string "null"
        Path dotFile    = Paths.get(file.getAbsolutePath());
        Charset charset = StandardCharsets.UTF_8;

        String dotContent   = new String(Files.readAllBytes(dotFile), "utf-8");
        dotContent          = dotContent.replaceAll("\0", "null");

        PrintWriter pWriter = new PrintWriter(file);
        pWriter.print(dotContent);
        pWriter.close();

    }

    public static Word<Character> equivalenceTestDFA(DFA<?, Character> dfa1, DFA<?, Character> dfa2,
            Alphabet<Character> alphabets) {
        Word<Character> word = null;
        word = DeterministicEquivalenceTest.findSeparatingWord(dfa1, dfa2, alphabets);
        return word;
    }



    public static String readName(File file) throws IOException {
        // Read just one line
        FileReader fr = new FileReader(file);
        BufferedReader bufferedReader = new BufferedReader(fr);
        String line = bufferedReader.readLine();
        bufferedReader.close();
        return line;
    }

    public static int readNumQueries(String filename) throws NumberFormatException, IOException {
        FileReader fileReader = new FileReader(filename);
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        int numOfQueires = Integer.parseInt(bufferedReader.readLine());
        bufferedReader.close();
        return numOfQueires;
    }


    public static void writeLog(List<String> output, File file) throws IOException {
        PrintWriter writer = new PrintWriter(file);

        Iterator<String> iter = output.iterator();
        while (iter.hasNext()) {
            writer.print(iter.next());

            if (iter.hasNext()) {
                writer.println();
            }

        }
        writer.close();

    }

    public static void writeLog(String output, File file) throws IOException {
        PrintWriter writer = new PrintWriter(file);
        writer.print(output);
        writer.close();
    }

}
