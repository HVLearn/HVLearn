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

/*
 * Generate certificate with given common name and save to given location
 * Reture 0 for success and 1 for failure
 *
 */

#include "crt.h"

#define DUMMY "dummy-value"

JNIEXPORT jint JNICALL Java_org_learner_core_CertificateTemplate_initcert(
        JNIEnv *env, jobject jobj, jstring commonname, jstring crtfile, jstring keyfile)
{
    int ret;

    gnutls_x509_crt_t crt;
    gnutls_x509_privkey_t pkey;

    const char *crt_fname;
    const char *key_fname;
    const char *cnamestr;
    int cnamelen;

    size_t buf_size;

    ret = 1;

    /* Generate private key */
    if (gnutls_gen_key(&pkey) != 0) {
        fprintf(stderr, "[FAILED] gnutls_gen_key().\n");
        return ret;
    }

    if (gnutls_gen_crt(&crt) != 0) {
        fprintf(stderr, "[FAILED] gnutls_gen_crt().\n");
        gnutls_x509_privkey_deinit(pkey);
        return ret;
    }

    /* Set name in common name or subject alternative name */
    cnamestr = (*env)->GetStringUTFChars(env, commonname, NULL);
    cnamelen = (*env)->GetStringUTFLength(env, commonname);


    /* Handle string from JNI */
    char cname[cnamelen + 1];
    cnamelen = jcstring(cnamestr, cnamelen, cname);

    if (gnutls_set_name(&crt, cname, cnamelen) != 0) {
        fprintf(stderr, "[FAILED] gnutls_set_name().\n");
        goto out;
    }

    ret = gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME,
            0, 1, NULL, &buf_size);
    //fprintf(stdout, "ret: %d data size: %lu\n", ret, buf_size);
    /* put dummy value in CN */
    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        if (gnutls_set_name(&crt, DUMMY, strlen(DUMMY)) != 0) {
            fprintf(stderr,
                    "[FAILED] gnutls_set_name(). -- cannot set dummy value\n");
            goto out;
        }
    }



    if (gnutls_sign_crt(&crt, &pkey) != 0) {
        fprintf(stderr, "[FAILED] gnutls_sign_crt().\n");
        goto out;
    }

    /* Write to disk */
    crt_fname = (*env)->GetStringUTFChars(env, crtfile, NULL);
    if (gnutls_write_crt(crt, crt_fname) != 0) {
        fprintf(stderr, "[FAILED] gnutls_write_crt().\n");
        goto out;
    }



    key_fname = (*env)->GetStringUTFChars(env, keyfile, NULL);
    if (gnutls_write_pkey(pkey, key_fname) != 0) {
        fprintf(stderr, "[FAILED] gnutls_write_pkey().\n");
        goto out;
    }

    ret = 0;

out:
    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(pkey);

    return ret;

}

