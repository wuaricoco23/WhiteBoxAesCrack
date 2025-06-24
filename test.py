import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from WBModule.getRoundKey import crack_from_traces
traces = []

last_round_key = crack_from_traces(traces, filename='tracefile.txt')
print(last_round_key)