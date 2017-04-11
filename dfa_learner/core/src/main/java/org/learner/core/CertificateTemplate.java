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

import java.io.File;
import java.util.Date;

public class CertificateTemplate
{

    // IDENTIFIER TYPE [ NONE=0, DNS=1, IPADDR=2, EMAIL=3 ]
    public static final int ID_TYPE_NONE    = 0; // Common name
    public static final int ID_TYPE_DNS     = 1; // DNS
    public static final int ID_TYPE_IPADDR  = 2; // IP ADDRESS
    public static final int ID_TYPE_EMAIL   = 3; // EMAIL


    public String tempPath;

    private int idType;
    private String name;

    private File certFile;
    private File keyFile;

    public CertificateTemplate(String name) {
        this.idType = CertificateTemplate.ID_TYPE_NONE;
        this.name = name;
        this.do_setup();
    }

    public CertificateTemplate(String name, int idType) {
        this.idType = idType;
        this.name = name;
        this.do_setup();
    }

    protected void do_setup() {
        this.tempPath = System.getProperty("java.io.tmpdir");
        this.name = name;

        String idFile = String.valueOf(new Date().getTime());

        String certFileName = "cert-" + idFile + ".pem";
        String keyFileName  = "cert-" + idFile + ".key";

        this.certFile   = new File(tempPath, certFileName);
        this.keyFile    = new File(tempPath, keyFileName);

        //this.certFile.deleteOnExit();
        //this.keyFile.deleteOnExit();

        // Write certificate
        this.writeCert();

    }

    public String getCertFileName() {
        return this.certFile.getAbsolutePath();
    }

    public String getKeyFileName() {
        return this.keyFile.getAbsolutePath();
    }

    static {
        System.loadLibrary("serverJNI");
    }

    private native static int initcert(String cname, String crtFile, String keyFile);

    private void writeCert() {
        String cname = this.name;
        int ret = 0;
        // Handle type of identifier (idType)
        if (this.idType == CertificateTemplate.ID_TYPE_DNS) {
            cname = "DNS:" + this.name;
        } else if (this.idType == CertificateTemplate.ID_TYPE_IPADDR) {
            cname = "IP:" + this.name;
        } else if (this.idType == CertificateTemplate.ID_TYPE_EMAIL) {
            cname = "email:" + this.name;
        }

        ret = CertificateTemplate.initcert(cname,
                                           this.certFile.getAbsolutePath(),
                                           this.keyFile.getAbsolutePath());
        if (ret == 1) {
            throw new RuntimeException("certificate generation " + cname);
        }

    }

}
