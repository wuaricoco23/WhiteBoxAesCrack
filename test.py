import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from WBModule.getRoundKey import crack_from_traces
traces = []

last_round_key = crack_from_traces(traces, filename='tracefile.txt')
print(last_round_key)

from WBModule.GetAllKey import AESKeySchedule

last_round = "400D59138E5C1E1A65598EC3A842D3CA"
scheduler = AESKeySchedule(last_round, 10)
keys = scheduler.derive()
print(keys[0])  # 应输出：44306E5175317830746535616E636830
