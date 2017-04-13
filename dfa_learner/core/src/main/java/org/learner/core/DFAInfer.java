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
import java.io.PrintWriter;
import java.io.Writer;
import java.io.File;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Random;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.kv.dfa.KearnsVaziraniDFA;
import de.learnlib.algorithms.kv.dfa.KearnsVaziraniDFABuilder;
import de.learnlib.api.EquivalenceOracle.DFAEquivalenceOracle;
import de.learnlib.api.MembershipOracle;
import de.learnlib.cache.dfa.DFACacheOracle;
import de.learnlib.cache.dfa.DFACaches;
import de.learnlib.eqtests.basic.EQOracleChain;
import de.learnlib.eqtests.basic.WpMethodEQOracle;
import de.learnlib.oracles.CounterOracle.DFACounterOracle;
import de.learnlib.oracles.DefaultQuery;
import de.learnlib.parallelism.ParallelOracle.PoolPolicy;
import de.learnlib.parallelism.ParallelOracleBuilders;
import net.automatalib.automata.fsa.DFA;
//import net.automatalib.serialization.AutomatonSerializationException;
//import net.automatalib.serialization.ParameterMismatchException;
import net.automatalib.util.graphs.dot.GraphDOT;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;


public class DFAInfer {

    // WP method depth
    public static final int WP_METHOD_DEPTH   = 1;

    // Parallel oracle builder setup
    public static final int NUM_INSTANCES     = 8;      // Number of threads
    public static final int MIN_BATCH_SIZE    = 200000; // Minimum batch size
    public static final String LOG_PATH       = "log";


    protected MembershipOracle<Character, Boolean> mqOracle;
    protected IdentityVerifier idVerifier;

    protected int idType;
    protected File alphabetFile;
    protected File nameFile;

    protected String name;
    protected Alphabet<Character> alphabets;

    protected int wpMethodDepth = DFAInfer.WP_METHOD_DEPTH;
    protected int numInstances  = DFAInfer.NUM_INSTANCES;
    protected int minBatchSize  = DFAInfer.MIN_BATCH_SIZE;

    protected String logPath    = DFAInfer.LOG_PATH;

    public void setNumInstance(int numInstances) {
        this.numInstances = numInstances;
    }

    public void setMinBatchSize(int minBatchSize) {
        this.minBatchSize = minBatchSize;
    }

    public void setWpMethodDepth(int wpMethodDepth) {
        this.wpMethodDepth = wpMethodDepth;
    }

    public void setLogPath(String logPath) {
        this.logPath = logPath;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setAlphabet(Alphabet<Character> alphabet) {
        this.alphabets = alphabets;
    }

    public void setAlphabetFile(File alphabetFile) {
        this.alphabetFile = alphabetFile;
    }

    public void setNameFile(File nameFile) {
        this.nameFile = nameFile;
    }

    public void setIdentityVerifier(IdentityVerifier idVerifier) {
        this.idVerifier = idVerifier;
    }

    public void setIdType(int idType) {
        this.idType = idType;
    }


    protected void do_setup()
    {

        // Check all require parameters
        // Read alphabet file
        if (this.alphabets == null) {
            try {
                this.alphabets = Utils.readAlphabets(this.alphabetFile);
            } catch (IOException e) {
                System.err.println("[FAILED] Read alphabet file " + this.alphabetFile);
                System.exit(-1);
            }
        }

        // Read name
        if (this.name == null) {
            try {
                this.name = Utils.readName(this.nameFile);
            } catch (IOException e) {
                System.err.println("[FAILED] Read name file " + this.nameFile);
                System.exit(-1);
            }
        }

        // Check IdentityVerifier
        if (this.idVerifier == null) {
            System.err.println("[FAILED] Identifier not set");
            System.exit(-1);
        }

        // Set log path
        this.logPath = this.logPath + "/" + this.idVerifier.getName();

        // Create Log directory
        this.makeLogPath();


    }

    public boolean makeLogPath() {

        boolean success = false;
        File file;

        try {
            file = new File(this.logPath);
            if (file.exists()) {
                // skipped if exists
                return success;
            }
            success = file.mkdirs();
        } catch(Exception e) {
            System.err.println("Cannot create directory: " + this.logPath);
            System.exit(-1);
        }

        success = true;
        return success;

    }


    public String getLogPrefix() {
        String logFile = this.name;
        // replace sign
        logFile = logFile.replace('*', 's');
        logFile = logFile.replace('.', '_');

        if (this.idType == CertificateTemplate.ID_TYPE_NONE) {
            logFile = logFile + "_CN";
        } else if (this.idType == CertificateTemplate.ID_TYPE_DNS) {
            logFile = logFile + "_DNS";
        } else if (this.idType == CertificateTemplate.ID_TYPE_IPADDR) {
            logFile = logFile + "_IP";
        } else if (this.idType == CertificateTemplate.ID_TYPE_EMAIL) {
            logFile = logFile + "_EMAIL";
        }


        File logPrefix = new File(this.logPath, logFile);
        return logPrefix.getAbsolutePath();
    }

    public List<String> getPossibleAcceptedStrings() {
        List<String> possibleAcceptedStrings    = new ArrayList<>();
        Set<String> set                         = new HashSet<>();

        // Remove identity type if exists (DNS:, IP:, EMAIL:)
        String noIdName = DFAInfer.getName(this.name);

        // Replace all wildcard with an alphabet letter [A-Za-z]
        for (char c : noIdName.toCharArray()) {
            if (Character.isLetter(c)) {
                set.add(noIdName.replace('*', c));
                set.add(noIdName.replace("*", ""));
                break;
            }
        }

        possibleAcceptedStrings.addAll(set);
        return possibleAcceptedStrings;

    }

    public static String getName(String name) {
        return name.replaceAll("^.*:", "");
    }

    public static List<Character> stringToQuery(String string) {
        // Convert string to query
        List<Character> query = new ArrayList<Character>();
        for (char c : string.toCharArray()) {
            query.add(c);
        }
        return query;
    }

}
