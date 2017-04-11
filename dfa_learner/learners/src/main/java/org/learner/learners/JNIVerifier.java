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

import java.util.Collection;
import java.util.Iterator;
import java.io.IOException;

import de.learnlib.api.MembershipOracle;
import de.learnlib.api.Query;

import org.learner.core.IdentityVerifier;

public class JNIVerifier extends IdentityVerifier
{
    static {
        System.loadLibrary("serverJNI");
    }

    // JNI functions
    //private native int initcert(String cname, String crtfile, String keyfile);
    private native int readcert(String crtfile);
    private native void freecert();
    private native int verifyname(String qstr, int idType);

    private String name;

    public JNIVerifier(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public void readCert(String crtFile, String keyFile) throws IOException {
        // ignore keyFile
        this.readcert(crtFile);
    }


    @Override
    public int verify(String qstr, int idType) {
        return this.verifyname(qstr, idType);
    }

    @Override
    public void freeCert() {
        this.freecert();
    }


}
