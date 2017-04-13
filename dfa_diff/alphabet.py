"""
Copyright (c) 2017 Columbia University.
Network Security Lab, Columbia University, New York, NY, USA

This file is part of HVLearn Project, https://github.com/HVLearn/.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

"""This module configures that alphabet."""


def createalphabet():
    """
    Creates a sample alphabet containing printable ASCII characters
    """
    alpha = []
    for i in range(58, 64):
        alpha.append(str(unichr(i)))
    for i in range(32, 57):
        alpha.append(str(unichr(i)))
    for i in range(65, 126):
        alpha.append(str(unichr(i)))
    return alpha
