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

#include "serverJNI.h"

gnutls_x509_crt_t crt;

JNIEXPORT jint JNICALL Java_org_learner_learners_JNIVerifier_readcert(
        JNIEnv *env, jobject jobj, jstring crtfile)
{
    int ret;
    const char *fnamestr;
    //int fnamelen;

    ret = 1;

    fnamestr = (*env)->GetStringUTFChars(env, crtfile, NULL);
    //fnamelen = (*env)->GetStringUTFLength(env, crtfile);

    if (gnutls_read_crt(fnamestr, &crt) != 0) {
        fprintf(stderr, "[FAILED] DFATest readcert()");
        return ret;
    }

    (*env)->ReleaseStringUTFChars(env, crtfile, fnamestr);

    ret = 0;
    return ret;

}

JNIEXPORT void JNICALL Java_org_learner_learners_JNIVerifier_freecert(
        JNIEnv *env, jobject jobj)
{
    /* free the common_name certificate */
    gnutls_x509_crt_deinit(crt);
}

JNIEXPORT jint JNICALL Java_org_learner_learners_JNIVerifier_verifyname(
        JNIEnv *env, jobject obj, jstring hostname, jint id)
{
    int ret;
    const char *hnamestr;
    int hnamelen;

    hnamestr = (*env)->GetStringUTFChars(env, hostname, NULL);
    hnamelen = (*env)->GetStringUTFLength(env, hostname);

    char hname[hnamelen + 1];
    hnamelen = jcstring(hnamestr, hnamelen, hname);

    if (id == ID_NONE || id == ID_DNS || id == ID_IPADDR)
        ret = gnutls_x509_crt_check_hostname(crt, hname);
    else if (id == ID_EMAIL)
        ret = gnutls_x509_crt_check_email(crt, hname, 0);
    else {
        fprintf(stderr, "[FAILED] verifyname() -- ID not found.\n");
        ret = ERROR;
    }
    //fprintf(stdout, "query: %s", hostname);
    //fprintf(stdout, " [%d]\n", ret);

    /* Non zero for a successful match, and zero on failure. */
    if (ret != 0) {
        ret = ACCEPT;
    }

    //free the pointer
    (*env)->ReleaseStringUTFChars(env, hostname, hnamestr);
    return ret;
}

