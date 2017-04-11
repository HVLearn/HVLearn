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

package org.learner.learners;

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
import net.automatalib.util.graphs.dot.GraphDOT;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;

import org.learner.core.DFAHostname;
import org.learner.core.IdentityVerifier;
import org.learner.core.CertificateTemplate;

public class JNIDFAHostname {

	public static void main(String[] args)
        throws IOException, IllegalAccessException, InterruptedException {

        File alphabetFile   = new File("../example-inputs/alphabets");
        File nameFile       = new File("../example-inputs/hostname");
        int idType          = CertificateTemplate.ID_TYPE_NONE; // Common name
        String libName      = args[0];


        IdentityVerifier idVerifier = new JNIVerifier(libName);
		DFAHostname dfaTest         = new DFAHostname();

        System.out.println(idVerifier.getName());

        dfaTest.setAlphabetFile(alphabetFile);
        dfaTest.setNameFile(nameFile);
        dfaTest.setIdentityVerifier(idVerifier);
        dfaTest.setIdType(idType);

        dfaTest.do_it();

	}

}


