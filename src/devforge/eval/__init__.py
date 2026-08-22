"""Measurement of DevForge itself.

Every other package in this repository makes DevForge do something. This one asks
whether it worked, on cases with known answers, and writes the answer down in a
form that can be compared against another configuration or against yesterday.

The rule the whole package is built around: **nothing here decides what a number
means.** It reports what was measured, what could not be measured, and how the two
runs differed. A configuration that scores higher on eight small cases has scored
higher on eight small cases.
"""
