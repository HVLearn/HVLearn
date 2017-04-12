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
 * Handle UTF string from JNI
 * http://docs.oracle.com/javase/1.5.0/docs/guide/jni/spec/types.html#wp16542
 *
 * NULL character: 0xC0 0x80
 *
 */

size_t jcstring(const char *name, size_t namelen, char *out)
{
    unsigned int i = 0;
    unsigned int j = 0;

    memset(out, 0, namelen+1);

    for (i = 0; i < namelen; i++) {
        /* Check for NULL character */
        if ((i+1) <  namelen) {
            if (name[i] == (char)0xC0 && name[i+1] == (char)0x80) {
                out[j] = '\0';
                i++;
                j++;
                continue;
            }
            if (name[i] == (char)0xCE && name[i+1] == (char)0xB5
                    && namelen == 2) {
                /* empty string ε */
                return 0;
            }
        }

        out[j] = name[i];
        j++;

    }

    out[j] = '\0';
    return j; /* string length */

}
