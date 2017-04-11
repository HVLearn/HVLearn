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
import java.security.cert.CertificateException;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Iterator;

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

public class DFACertname extends DFAInfer {

    public void do_it() throws IOException {

        // Perform initial setup
        this.do_setup();

        //int covMode             = dfaTest.covMode;
        String logPrefix        = this.getLogPrefix() + "_certname";

        // TODO: Migrate Random mode

        // Setup MembershipOracle
        this.mqOracle = new MembershipOracleCertname(this.idVerifier, this.name, this.idType);

        // Setup DFACacheOracle
        this.mqOracle = ParallelOracleBuilders.newStaticParallelOracle(this.mqOracle)
                            .withPoolPolicy(PoolPolicy.CACHED)
                            .withNumInstances(this.numInstances)
                            .withMinBatchSize(this.minBatchSize)
                            .create();

        DFACounterOracle<Character> queryCounter        = new DFACounterOracle<>(this.mqOracle, "Queries to SUL");
        DFACacheOracle<Character> cache                 = DFACaches.createCache(this.alphabets, queryCounter);
        DFACounterOracle<Character> learnerQueryCounter = new DFACounterOracle<>(cache, "Queries from Learner");
        MembershipOracle<Character, Boolean> effOracle  = learnerQueryCounter;

        KearnsVaziraniDFABuilder<Character> learnerBuilder = new KearnsVaziraniDFABuilder<>();
        KearnsVaziraniDFA<Character> learner = learnerBuilder.withAlphabet(this.alphabets)
                .withCounterexampleAnalyzer(AcexAnalyzers.EXPONENTIAL_BWD).withOracle(effOracle).create();

        // Start learning
        long start = System.currentTimeMillis();
        System.out.println("Start time:" + start);
        learner.startLearning();

        // Equivalence oracle 1
        DFAEquivalenceOracle<Character> wpEqOracle =
                    new WpMethodEQOracle.DFAWpMethodEQOracle<>(WP_METHOD_DEPTH, effOracle);
        // Equivalence oracle 2
        DFAEquivalenceOracle<Character> consistencyEqOracle = cache.createCacheConsistencyTest();
        // Chain above two oracles together
        DFAEquivalenceOracle<Character> eqOracle =
                    new EQOracleChain.DFAEQOracleChain<>(consistencyEqOracle, wpEqOracle);

        DefaultQuery<Character, Boolean> counterexample = null;

        // Optimize learning process
        // Try to have DFA learns accepted string to reduce learning time
        boolean dfa_qresult = false;
        boolean sul_qresult = false;

        long numEqQuery         = 0;
        long numMemQueryByEq    = 0;
        long numMemQueryByEq1   = 0;

        String possibleAcceptedString = "";
        List<String> possibleAcceptedStrings = this.getPossibleAcceptedStrings();
        Iterator<String> iter = possibleAcceptedStrings.iterator();

        while (iter.hasNext() && !sul_qresult) {
            possibleAcceptedString = iter.next();
            sul_qresult = this.idVerifier.verify(possibleAcceptedString, this.idType) == 1 ? true : false;
        }

        List<Character> customQuery = stringToQuery(possibleAcceptedString);
        dfa_qresult = learner.getHypothesisModel().accepts(customQuery);


        long q  = queryCounter.getStatisticalData().getCount();
        //long q1 = learnerQueryCounter.getStatisticalData().getCount();

        if (dfa_qresult != sul_qresult && possibleAcceptedStrings.size() > 0) {
            // Use as the string as counter example
            counterexample = new DefaultQuery<>(Word.fromString(possibleAcceptedString), true);
        } else {
            counterexample   = eqOracle.findCounterExample(learner.getHypothesisModel(), this.alphabets);
            numMemQueryByEq += (queryCounter.getStatisticalData().getCount() - q);
            //numMemQueryByEq1    += (learnerQueryCounter.getStatisticalData().getCount() - q1);
            numEqQuery++;
        }

        while (counterexample != null) {
            System.out.println("Refine hypothesis");
            boolean refined = learner.refineHypothesis(counterexample);
            if (!refined)
                System.out.println("No refinement effected by counterexample");

            q = queryCounter.getStatisticalData().getCount();
            //q1 = learnerQueryCounter.getStatisticalData().getCount();
            counterexample = eqOracle.findCounterExample(learner.getHypothesisModel(), this.alphabets);
            numMemQueryByEq += (queryCounter.getStatisticalData().getCount() - q);
            //numMemQueryByEq1 += (learnerQueryCounter.getStatisticalData().getCount() - q1);
            numEqQuery++;
        }

        this.idVerifier.freeCert();

        // Done learning
        long end = System.currentTimeMillis();
        System.out.println("end time: " + end);
        System.out.println("running time: " + (end - start));


        // Output alphabet
        File alphabetFileOutput = new File(logPrefix + ".alphabet");
        Utils.writeAlphabet(this.alphabets, alphabetFileOutput);

        // Output name
        File nameFileOutput = new File(logPrefix + ".name");
        Utils.writeLog(this.name, nameFileOutput);

        // Output learning statistic
        DFA<?, Character> result = learner.getHypothesisModel();
        /*
        System.out.println("States: " + result.size());
        System.out.println("Sigma: " + this.alphabets.size());
        System.out.println(queryCounter.getStatisticalData());
        System.out.println("Number of membership query with cache: "
                + (queryCounter.getStatisticalData().getCount() - numMemQueryByEq));
        System.out.println("Number of membership query resulted from equivalence query with cache: "
                + numMemQueryByEq);

        System.out.println(learnerQueryCounter.getStatisticalData());
        System.out.println("Number of membership query without cache: "
                + (learnerQueryCounter.getStatisticalData().getCount() - numMemQueryByEq1));
        System.out.println("Number of membership query resulted from equivalence query without cache: "
                + numMemQueryByEq1);

        System.out.println("Number of equivalence query: " + numEqQuery);
        */


        // Output number of queries to the SUL
        File statFileOutput = new File(logPrefix + ".stat");
        Utils.writeLog(Long.toString(queryCounter.getStatisticalData().getCount()), statFileOutput);

        // Output automata as DOT file
        File dotFileOutput = new File(logPrefix + ".dot");
        Utils.writeDOT(result, this.alphabets, dotFileOutput);

        // Output automata as serialized file
        File dfaFileOutput = new File(logPrefix + ".dfa");
        Utils.writeDFA(result, this.alphabets, dfaFileOutput);

    }
}
