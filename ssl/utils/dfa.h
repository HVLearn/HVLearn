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

#include <jni.h>

#include "jcstring.h"
//#include "org_learner_DFATest.h"
#include "jni_verifier.h"
#include "jni_initcert.h"

/* DFA return status */
#define ACCEPT  1
#define REJECT  0
#define ERROR   2


/* Define each matching identifier type: NONE, DNS, IP, EMAIL to test
 * Some libraries e.g., OpenSSL, GnuTLS need to picked type to check
 * */
#define ID_NONE     0
#define ID_DNS      1
#define ID_IPADDR   2
#define ID_EMAIL    3
