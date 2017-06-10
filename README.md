<h1>HVLearn</h1>
<p> HVLearn is an open-source tool/framework for analyzing hostname
verification in SSL/TLS implementations using automata learning.  It is good
for finding bugs, vulnerabilities and RFC discrepancies in implementations. The
core of this project is written in Java and mainly implemented with <a
href="https://learnlib.de/">LearnLib</a> project. Some parts of the code are
written in C, particularly for generating certificate template.
</p>

<p>
Given a specific pattern of certificate identifier (e.g., common name and
subject alternative name fields), HVLearn uses automata learning
algorithms to infer a Deterministic Finite Automaton (DFA) that describes the
set of all hostnames that match the given certificate identifier. The output
inferred DFA can be compared to DFAs from different implementations to find
discrepancies or performed an equivalence test against a DFA which is derived
from any regular expression as an expected rule.
</p>

<p> For more detail about algorithm and evaluation, see our paper:<br />
<b>HVLearn: Automated Black-box Analysis of Hostname Verification in SSL/TLS
Implementations </b>
<a href="https://github.com/HVLearn/HVLearn/raw/master/HVLearn.pdf">[PDF]</a><br />
Suphannee Sivakorn, George Argyros, Kexin Pei, Angelos D. Keromytis and Suman Jana
</p>

<p><b>Want to try?</b> Please refer to our <a href="https://github.com/HVLearn/HVLearn/wiki">Wiki</a> page for setting up instruction and framework implementation.
Look for certificate templates we have used in testing, they are in our <a href="https://github.com/HVLearn/HVLearn/tree/master/CERT_TEMPLATES">CERT_TEMPLATES</a> directory.
</p>

<p>
HVLearn is developed at Columbia University, New York, NY, USA in 2016-2017.
</p>

<h2>Useful Resources</h2>
<ul>
<li><b><a href="https://github.com/HVLearn/HVLearn/wiki">HVLearn Project Wiki</a></b>
<li><a href="https://maven.apache.org/">Apache Maven</a></li>
<li><a href="https://www.gnutls.org/">GnuTLS</a></li>
</ul>

<h2>Developers/Maintainers</h2>
HVLearn is developed and maintained by (alphabetically):
<ul>
<li><a href="https://github.com/GeorgeArgyros">George Argyros</a></li>
<li><a href="https://sites.google.com/site/kexinpeisite/">Kexin Pei</a></li>
<li><a href="https://www.cs.columbia.edu/~suphannee">Suphannee Sivakorn</a></li>
</ul>

<h2>Bugs</h2>
<p>
Found a bug? Please open a new issue!
</p>

<h2>Copyright and License</h2>
All code and documentation copyright the <a href="https://github.com/HVLearn/HVLearn/graphs/contributors">HVLearn Authors</a>
and <a href="http://nsl.cs.columbia.edu">Network Security Lab</a> at Columbia University, New York, NY, USA.
Code released under <a href="https://github.com/HVLearn/HVLearn/blob/master/LICENSE">MIT License</a> and document released under <a href="">Creative Commons</a>.
