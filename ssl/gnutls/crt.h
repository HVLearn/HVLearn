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

#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define KEY_LENGTH  2048

#define CN          "CN" /* common name */

#define DNS         "DNS:"
#define IP          "IP:"
#define EMAIL       "email:"


/* generate a key-length-bit RSA key */
int gnutls_gen_key(gnutls_x509_privkey_t *pkey)
{
    int ret;

    ret = 1;
    if (gnutls_x509_privkey_init(pkey) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_privkey_init().\n");
        return ret;
    }

    if (gnutls_x509_privkey_generate(*pkey, GNUTLS_PK_RSA, KEY_LENGTH, 0)
        != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_privkey_generate().\n");
        return ret;
    }

    ret = 0;
    return ret;
}

/* certificate */
int gnutls_make_crt(gnutls_x509_crt_t *crt)
{
    int version = 3;
    int ret;

    ret = 1;

    if (gnutls_x509_crt_init(crt) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_init().\n");
        return ret;
    }

    gnutls_x509_crt_set_version(*crt, version);

    return 1;
}


int gnutls_gen_crt(gnutls_x509_crt_t *crt)
{
    int ret;
    time_t start, end;
    unsigned char serial;

    ret = 1;

    serial = 0x1;
    start = time(NULL);
    end = start + 31536000L;

    gnutls_make_crt(crt);

    gnutls_x509_crt_set_serial(*crt, &serial, sizeof(serial));

    /* Expired after one year */
    gnutls_x509_crt_set_activation_time(*crt, start);
    gnutls_x509_crt_set_expiration_time(*crt, end);

    ret = 0;
    return ret;
}

int gnutls_sign_crt(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t *pkey)
{
    int ret;

    ret = 1;
    /* Sign certificate (self) */
    if (gnutls_x509_crt_set_key(*crt, *pkey) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_set_key().\n");
        return ret;
    }

    if (gnutls_x509_crt_sign(*crt, *crt, *pkey) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_sign().\n");
        return ret;
    }

    ret = 0;
    return ret;
}


/* subject alternative name type */
int gnutls_set_san_type(gnutls_x509_subject_alt_name_t type,
    const char *name, size_t namelen, char *nm)
{
    int len;
    int nmlen;

    nmlen = 0;
    if (type == GNUTLS_SAN_DNSNAME)
        len = strlen(DNS);
    else if (type == GNUTLS_SAN_IPADDRESS)
        len = strlen(IP);
    else if (type == GNUTLS_SAN_RFC822NAME)
        len = strlen(EMAIL);

    nmlen = namelen - len;
    memset(nm, 0, namelen);
    memcpy(nm, &name[len], nmlen);

    return nmlen;
}

int gnutls_set_cname(gnutls_x509_crt_t *crt, const char *name, size_t namelen)
{
    int ret;

    ret = 1;

    if (gnutls_x509_crt_set_dn_by_oid(*crt, GNUTLS_OID_X520_COMMON_NAME,
            0, name, namelen) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_set_dn_by_oid() %s\n", name);
        goto out;

    }

    ret = 0;
out:
    return ret;
}

int gnutls_set_san(gnutls_x509_crt_t *crt, const char *name, size_t namelen)
{
    int ret;
    //int len;
    int nmlen;
    char nm[namelen];

    nmlen = 0;
    //len = 0;
    ret = 1;


    if (strncmp(name, DNS, strlen(DNS)) == 0) {
        /*
        len = strlen(DNS);
        memcpy(nm, &name[len], namelen - len);
        nmlen = namelen - len - 1;
        */
        nmlen = gnutls_set_san_type(GNUTLS_SAN_DNSNAME, name, namelen, nm);
        fprintf(stdout, "TYPE: DNS VALUE: %s (%d)\n", nm, nmlen);
        /*
        for (int i = 0; i < nmlen; i++) {
            if (nm[i] == '\0')
                fprintf(stdout, "\\0");
            else
                fprintf(stdout, "%c", nm[i]);
        }
        fprintf(stdout, "\n");
        */
        ret = gnutls_x509_crt_set_subject_alt_name(
                *crt, GNUTLS_SAN_DNSNAME, nm, nmlen, GNUTLS_FSAN_APPEND);

    } else if (strncmp(name, IP, strlen(IP)) == 0) {
        nmlen = gnutls_set_san_type(GNUTLS_SAN_IPADDRESS, name, namelen, nm);
        fprintf(stdout, "TYPE: IP VALUE: %s (%d)\n", nm, nmlen);
        /* convert IP string to binary format */

#if 0
        in_addr_t ip = inet_addr(nm);
        //ret = gnutls_x509_crt_set_subject_alt_name(
        //        *crt, GNUTLS_SAN_IPADDRESS, nm, nmlen, GNUTLS_FSAN_APPEND);
        ret = gnutls_x509_crt_set_subject_alt_name(
                *crt, GNUTLS_SAN_IPADDRESS, &ip, sizeof(in_addr_t), GNUTLS_FSAN_APPEND);
#endif
        struct sockaddr_in addr_v4;
        struct sockaddr_in6 addr_v6;
        if (inet_pton(AF_INET, nm, &(addr_v4.sin_addr)) != 0) {
            /* IP v4 */
            ret = gnutls_x509_crt_set_subject_alt_name(
                    *crt, GNUTLS_SAN_IPADDRESS,
                    &addr_v4.sin_addr, sizeof(addr_v4.sin_addr),
                    GNUTLS_FSAN_APPEND);
        }
        else if (inet_pton(AF_INET6, nm, &(addr_v6.sin6_addr)) != 0) {
            /* IP v6 */
            ret = gnutls_x509_crt_set_subject_alt_name(
                    *crt, GNUTLS_SAN_IPADDRESS,
                    &addr_v6.sin6_addr, sizeof(addr_v6.sin6_addr),
                    GNUTLS_FSAN_APPEND);
        } else {
            fprintf(stderr, "[FAILED] set_san().\n");
            return ret;
        }

    } else if (strncmp(name, EMAIL, strlen(EMAIL)) == 0) {
        nmlen = gnutls_set_san_type(GNUTLS_SAN_RFC822NAME, name, namelen, nm);
        fprintf(stdout, "TYPE: EMAIL VALUE: %s (%d)\n", nm, nmlen);
        ret = gnutls_x509_crt_set_subject_alt_name(
                *crt, GNUTLS_SAN_RFC822NAME, nm, nmlen, GNUTLS_FSAN_APPEND);
    } else {
        fprintf(stderr, "[FAILED] set_san().\n");
        return ret;
    }


    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_set_subject_alt_name().\n");
        fprintf(stderr, "%d\n", ret);
        ret = 1;
        return ret;
    }

    ret = 0;
    return ret;
}

int gnutls_set_name(gnutls_x509_crt_t *crt, const char *name, size_t namelen)
{
    int ret;
    int subjectaltname;

    ret = 1;
    subjectaltname = 0;

    for (int i = 0; i < namelen; i++) {
        if (name[i] == ':') {
            subjectaltname = 1;
            break;
        }
    }

    if (subjectaltname == 1) {
        return gnutls_set_san(crt, name, namelen);
    } else {
        return gnutls_set_cname(crt, name, namelen);
    }



    return ret;
}

char *fread_file (FILE *stream, size_t *length)
{
    char *buf = NULL;
    size_t alloc = 0;
    size_t size = 0;
    int save_errno;

    for (;;)
    {
        size_t count;
        size_t requested;

        if (size + BUFSIZ + 1 > alloc)
        {
            char *new_buf;

            alloc += alloc / 2;
            if (alloc < size + BUFSIZ + 1)
                alloc = size + BUFSIZ + 1;

            new_buf = realloc(buf, alloc);
            if (!new_buf)
            {
                save_errno = errno;
                break;

            }

            buf = new_buf;

        }

        requested = alloc - size - 1;
        count = fread (buf + size, 1, requested, stream);
        size += count;

        if (count != requested)
        {
            save_errno = errno;
            if (ferror (stream))
                break;
            buf[size] = '\0';
            *length = size;
            return buf;

        }

    }

    free (buf);
    errno = save_errno;
    return NULL;

}

char *internal_read_file (const char *filename,
    size_t *length, const char *mode)
{
    FILE *stream = fopen (filename, mode);
    char *out;
    int save_errno;

    if (!stream)
        return NULL;

    out = fread_file (stream, length);

    save_errno = errno;

    if (fclose (stream) != 0)
    {
        if (out)
        {
            save_errno = errno;
            free (out);

        }
        errno = save_errno;
        return NULL;

    }

    return out;
}


char *read_binary_file (const char *filename, size_t *length)
{
    return internal_read_file (filename, length, "rb");
}


/* crt from disk */
int gnutls_read_crt(const char *name, gnutls_x509_crt_t *crt)
{
    int ret;
    gnutls_datum_t      data;
    size_t              size;

    ret = 1;

    if (gnutls_x509_crt_init(crt) < 0) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_init().\n");
        crt = NULL;
        return ret;
    }

    data.data = (void *) read_binary_file(name, &size);
    data.size = size;
    if (gnutls_x509_crt_import(*crt, &data, GNUTLS_X509_FMT_PEM) < 0) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_import().\n");
        gnutls_x509_crt_deinit(*crt);
        return ret;
    }

    ret = 0;
    free(data.data);
    return ret;
}


/* crt to dist */
int gnutls_write_crt(gnutls_x509_crt_t crt, const char *name)
{
    FILE *crt_fp;
    int ret;
    gnutls_datum_t out;

    ret = 1;

    crt_fp = fopen(name, "wb");

    if ((ret = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &out)) != 0) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_export2(). %d\n", ret);
        goto out;
    }

    /* write to disk */
    fprintf(crt_fp, "%s", out.data);
    ret = 0;

out:
    fclose(crt_fp);
    gnutls_free(out.data);
    return ret;
}

int gnutls_print_crt(gnutls_x509_crt_t crt)
{
    int ret;
    gnutls_datum_t out;

    ret = 1;

    if (gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_FULL, &out)
            != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_crt_print().\n");
        return ret;
    }

    fprintf(stdout, "%s\n", out.data);

    gnutls_free(out.data);
    ret = 0;
    return ret;
}

/* pkey to disk */
int gnutls_write_pkey(gnutls_x509_privkey_t pkey, const char *name)
{
    FILE *pkey_fp;
    //char *buf;
    //size_t bufsize;
    gnutls_datum_t out;
    int ret;

    ret = 1;

    pkey_fp = fopen(name, "wb");
    if (!pkey_fp) {
        return ret;
    }

    if (gnutls_x509_privkey_export2(pkey, GNUTLS_X509_FMT_PEM, &out)
            != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "[FAILED] gnutls_x509_privkey_export().\n");
        goto out;
    }

    //buf = malloc(bufsize);
    //gnutls_x509_privkey_export(pkey, GNUTLS_X509_FMT_PEM, buf, &bufsize);

    /* write to disk */
    //fprintf(pkey_fp, "%s", buf);
    fprintf(pkey_fp, "%s", out.data);

    ret = 0;
    //free(buf);

out:
    fclose(pkey_fp);
    gnutls_free(out.data);
    return ret;
}
