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

import java.util.Collection;
import java.util.Iterator;

import net.automatalib.words.Word;

import de.learnlib.api.MembershipOracle;
import de.learnlib.api.Query;

public class MembershipOracleHostname implements MembershipOracle<Character, Boolean>
{
    private IdentityVerifier idVerifier;

    private int idType;
    private String name = null;


    public MembershipOracleHostname(IdentityVerifier idVerifier, String name, int idType) {
        this.idVerifier = idVerifier;
        this.idType     = idType;
        this.name       = name; // hostname
    }

    @Override
    public void processQueries(Collection<? extends Query<Character, Boolean>> queries) {
        // Answer queries
        String qstr     = null;
        int accepted    = IdentityVerifier.REJECT;

        for (Iterator<? extends Query<Character, Boolean>> iter = queries.iterator(); iter.hasNext();) {
            Query<Character, Boolean> query = iter.next();
            qstr = Utils.getQueryString(query);

            // Create a new certificate for testing
            CertificateTemplate certTemplate    = null;
            String certFileName                 = null;
            String keyFileName                  = null;

            try {
                certTemplate    = new CertificateTemplate(qstr, idType);
                certFileName    = certTemplate.getCertFileName();
                keyFileName     = certTemplate.getKeyFileName();
            } catch (RuntimeException e) {
                System.err.println("[FAILED] " + e.getMessage());
                query.answer(false);
                return;
            }

            // Read the certificate
            try {
                this.idVerifier.readCert(certFileName, keyFileName);
            } catch (Exception e) {
                System.err.println("[FAILED] " + e.getMessage());
                query.answer(false);
                return;
            }

            accepted = this.idVerifier.verify(this.name, this.idType);

            // Free the certificate
            this.idVerifier.freeCert();


            System.out.print("query: " + qstr + " >> ");
            if (accepted == IdentityVerifier.ACCEPT) {
                query.answer(true);
                System.out.println("[accepted]");
            } else if (accepted == IdentityVerifier.REJECT) {
                query.answer(false);
                System.out.println("[rejected]");
            } else {
                // Error
                System.err.println("[FAILED] Unexpected format returned");
                System.exit(-1);
            }

        }

    }

}
