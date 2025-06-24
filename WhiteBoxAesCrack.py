# -*- coding: utf-8 -*-
# IDA Python plugin: Whitebox AES Fault Injection with Direct Address Input
# Author: ChatGPT (modified for GenTYI by request)
# Date: 2025-06-23

import idaapi
import ida_kernwin
import ida_bytes
import struct
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from WBModule.getRoundKey import crack_from_traces
from WBModule.GetAllKey import AESKeySchedule
traces = []
from random import seed, randint

# GF(2^8) multiplication (strict C-style)
def gmul(a, b):
    p = 0
    while a != 0 and b != 0:
        if b & 1:
            p ^= a
        if a & 0x80:
            a = ((a << 1) ^ 0x1b) & 0xFF
        else:
            a = (a << 1) & 0xFF
        b >>= 1
    return p & 0xFF

def build_tyibox_from_3d(base):
    raw = ida_bytes.get_bytes(base, 10 * 16 * 256)
    if not raw:
        raise ValueError(f"Failed to read 3D TBox at 0x{base:X}")
    tbox = [[[raw[r * 4096 + i * 256 + x] for x in range(256)] for i in range(16)] for r in range(10)]
    # Construct tyitable
    tyitable = [[[0] * 4 for _ in range(256)] for _ in range(4)]
    for i in range(256):
        tyitable[0][i][0] = gmul(i, 0x02)
        tyitable[0][i][1] = gmul(i, 0x03)
        tyitable[0][i][2] = i
        tyitable[0][i][3] = i

        tyitable[1][i][0] = i
        tyitable[1][i][1] = gmul(i, 0x02)
        tyitable[1][i][2] = gmul(i, 0x03)
        tyitable[1][i][3] = i

        tyitable[2][i][0] = i
        tyitable[2][i][1] = i
        tyitable[2][i][2] = gmul(i, 0x02)
        tyitable[2][i][3] = gmul(i, 0x03)

        tyitable[3][i][0] = gmul(i, 0x03)
        tyitable[3][i][1] = i
        tyitable[3][i][2] = i
        tyitable[3][i][3] = gmul(i, 0x02)

    tyibox = [[[0] * 256 for _ in range(16)] for _ in range(9)]
    for r in range(9):
        for x in range(256):
            for j in range(4):
                for i in range(4):
                    val = tbox[r][j * 4 + i][x]
                    v0 = tyitable[0][val][i]
                    v1 = tyitable[1][val][i]
                    v2 = tyitable[2][val][i]
                    v3 = tyitable[3][val][i]
                    tyibox[r][j * 4 + i][x] = (v0 << 24) | (v1 << 16) | (v2 << 8) | v3
    return tbox[9], tyibox

class UnifiedForm(ida_kernwin.Form):
    def __init__(self):
        fmt = """STARTITEM 0
Whitebox AES Fault Injection

- Fill TBox and TYiBox for Direct Mode
- Or, leave TYiBox blank and fill 3D TBox Base for GenTYI Mode

<TBox Base     :{tbox}>
<TYiBox Base   :{tyi}>
<3D TBox Base  :{tbox3d}>
"""
        super(UnifiedForm, self).__init__(fmt, {
            'tbox': ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_ADDR, swidth=20, value=0),
            'tyi': ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_ADDR, swidth=20, value=0),
            'tbox3d': ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_ADDR, swidth=20, value=0)
        })

def shift_rows(state):
    tmp = state[1]; state[1]=state[5]; state[5]=state[9]; state[9]=state[13]; state[13]=tmp
    tmp = state[2]; state[2]=state[10]; state[10]=tmp
    tmp = state[6]; state[6]=state[14]; state[14]=tmp
    tmp = state[15]; state[15]=state[11]; state[11]=state[7]; state[7]=state[3]; state[3]=tmp

def load_tables_direct(tbase, tyibase):
    raw_t = ida_bytes.get_bytes(tbase, 16*256)
    if not raw_t:
        raise ValueError(f"Failed to read TBox at 0x{tbase:X}")
    tbox = [list(raw_t[i*256:(i+1)*256]) for i in range(16)]
    raw_y = ida_bytes.get_bytes(tyibase, 9*16*256*4)
    if not raw_y:
        raise ValueError(f"Failed to read TYiBox at 0x{tyibase:X}")
    tyibox = []
    off = 0
    for r in range(9):
        round_tab = []
        for i in range(16):
            row = []
            for x in range(256):
                val = struct.unpack_from('<I', raw_y, off)[0]
                row.append(val)
                off += 4
            round_tab.append(row)
        tyibox.append(round_tab)
    return tbox, tyibox

def aes_encrypt(input_bytes, tbox, tyibox, isDFA=False, fault_idx=0):
    state = list(input_bytes)
    xortable = [[i ^ j for j in range(16)] for i in range(16)]
    for r in range(9):
        if isDFA and r == 8:
            seed(fault_idx)
            state[fault_idx] = randint(0, 255)
        shift_rows(state)
        new_state = [0]*16
        for j in range(4):
            a = tyibox[r][4*j+0][state[4*j+0]]
            b = tyibox[r][4*j+1][state[4*j+1]]
            c = tyibox[r][4*j+2][state[4*j+2]]
            d = tyibox[r][4*j+3][state[4*j+3]]
            aa = xortable[(a >> 28) & 0xF][(b >> 28) & 0xF]
            bb = xortable[(c >> 28) & 0xF][(d >> 28) & 0xF]
            cc = xortable[(a >> 24) & 0xF][(b >> 24) & 0xF]
            dd = xortable[(c >> 24) & 0xF][(d >> 24) & 0xF]
            new_state[4*j+0] = ((aa ^ bb) << 4) | (cc ^ dd)
            aa = xortable[(a >> 20) & 0xF][(b >> 20) & 0xF]
            bb = xortable[(c >> 20) & 0xF][(d >> 20) & 0xF]
            cc = xortable[(a >> 16) & 0xF][(b >> 16) & 0xF]
            dd = xortable[(c >> 16) & 0xF][(d >> 16) & 0xF]
            new_state[4*j+1] = ((aa ^ bb) << 4) | (cc ^ dd)
            aa = xortable[(a >> 12) & 0xF][(b >> 12) & 0xF]
            bb = xortable[(c >> 12) & 0xF][(d >> 12) & 0xF]
            cc = xortable[(a >> 8) & 0xF][(b >> 8) & 0xF]
            dd = xortable[(c >> 8) & 0xF][(d >> 8) & 0xF]
            new_state[4*j+2] = ((aa ^ bb) << 4) | (cc ^ dd)
            aa = xortable[(a >> 4) & 0xF][(b >> 4) & 0xF]
            bb = xortable[(c >> 4) & 0xF][(d >> 4) & 0xF]
            cc = xortable[a & 0xF][b & 0xF]
            dd = xortable[c & 0xF][d & 0xF]
            new_state[4*j+3] = ((aa ^ bb) << 4) | (cc ^ dd)
        state = new_state
    shift_rows(state)
    for i in range(16):
        state[i] = tbox[i][state[i]]
    return state

class WhiteboxPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Whitebox AES Fault Injection"
    help = "Input TBox/TYiBox or 3D TBox to simulate AES and inject faults"
    wanted_name = "WhiteBoxAesCrack"
    wanted_hotkey = "Ctrl-Shift-W"

    def init(self):
        idaapi.msg("[WhiteboxAES] initialized\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        form = UnifiedForm()
        form.Compile()
        form.Execute()
        tbase = form.tbox.value
        ybase = form.tyi.value
        base3d = form.tbox3d.value
        form.Free()
        try:
            if ybase != 0:
                tbox, tyibox = load_tables_direct(tbase, ybase)
                idaapi.msg("[*] Using Direct Mode\n")
            else:
                tbox, tyibox = build_tyibox_from_3d(base3d)
                idaapi.msg("[*] Using GenTYI Mode from 3D TBox\n")
        except ValueError as e:
            idaapi.warning(str(e))
            return

        # 收集所有 trace
        traces = []
        traces.append(aes_encrypt([0x33] * 16, tbox, tyibox, False))
        for i in range(16):
            traces.append(aes_encrypt([0x33] * 16, tbox, tyibox, True, i))
        idaapi.msg(f"FaultData:\n")
        # 先把每条 trace 打印出来
        for idx, trace in enumerate(traces):
            hexstr = ''.join(f"{b:02x}" for b in trace)
            idaapi.msg(f"{hexstr}\n")

        # 调用封装函数，获取最后一轮密钥
        last_round_key = crack_from_traces(traces, filename='tracefile.txt')
        idaapi.msg(f"# Last round key found: {last_round_key}\n")

    def term(self):
        idaapi.msg("[WhiteboxAES] terminated\n")

def PLUGIN_ENTRY():
    return WhiteboxPlugin()
