#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


import os
import json
import time
import codecs
import re

from jarray import zeros

from ghidra.app.decompiler import DecompInterface
from ghidra.framework import Application

from kingaidra.ghidra import GhidraUtilImpl


SEGMENT_HEXDUMP_CHUNK = 0x10000


def _make_dir(p):
    if not os.path.isdir(p):
        os.makedirs(p)

def _addr_to_str(addr):
    return "0x" + addr.toString()

def write_text(path, s):
    with codecs.open(path, "w", encoding="utf-8") as f:
        f.write(s)

def write_json(path, obj):
    write_text(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def collect_imports_json(prog):
    fm = prog.getFunctionManager()
    externs = []
    it = fm.getExternalFunctions()
    for f in it:
        try:
            lib = f.getParentNamespace().getName() if f.getParentNamespace() else ""
            externs.append({
                "library": lib,
                "name": f.getName(),
                "address": str(f.getEntryPoint()),
                "prototype": f.getSignature().getPrototypeString(),
            })
        except Exception:
            pass
    return externs

def collect_exports_json(prog):
    symtab = prog.getSymbolTable()
    fm = prog.getFunctionManager()

    exports = []
    it = symtab.getExternalEntryPointIterator()

    seen = set()
    for addr in it:
        try:
            if addr in seen:
                continue
            seen.add(addr)

            f = fm.getFunctionAt(addr)
            if f is None:
                continue

            sym = symtab.getPrimarySymbol(addr)
            exports.append({
                "name": sym.getName() if sym else f.getName(),
                "address": _addr_to_str(addr),
                "prototype": f.getSignature().getPrototypeString(),
            })
        except Exception:
            pass

    return exports


def make_decompiler(prog):
    dif = DecompInterface()
    dif.openProgram(prog)
    return dif


def _sanitize_file_name(name):
    return re.sub(r"[^0-9A-Za-z_]+", "_", name)

def _hexdump_char(b):
    return chr(b) if 32 <= b <= 126 else "."

def format_hexdump(buf, base_offset=0):
    WIDTH = 16
    lines = []

    for i in range(0, len(buf), WIDTH):
        chunk = buf[i:i + WIDTH]
        hex_bytes = ["{:02x}".format(chunk[j]) if j < len(chunk) else "  " for j in range(WIDTH)]
        hex_part = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])

        ascii_part = "".join(_hexdump_char(b) for b in chunk)
        lines.append("{:08x}  {}  |{}|".format(base_offset + i, hex_part, ascii_part))

    return "\n".join(lines)

def hexdump_memory(addr, size):
    if size <= 0:
        return ""

    mem = currentProgram.getMemory()
    buf = zeros(size, 'b')

    try:
        read = mem.getBytes(addr, buf)
    except Exception:
        read = -1

    py_buf = bytearray((b & 0xff) for b in buf)

    if read < size:
        py_buf = py_buf[:max(read, 0)]

    return format_hexdump(py_buf, base_offset=addr.getOffset())


def dump_memory_segments(mem, hexdump_dir, base_dir, chunk_size=SEGMENT_HEXDUMP_CHUNK):
    manifest = []

    blocks = mem.getBlocks()
    for block in blocks:
        block_size = int(block.getSize())
        if block_size <= 0:
            continue

        block_name = block.getName()
        safe_name = _sanitize_file_name(block_name)
        block_dir = os.path.join(hexdump_dir, "segment_%s" % safe_name)
        _make_dir(block_dir)

        block_entry = {
            "segment": block_name,
            "start": _addr_to_str(block.getStart()),
            "end": _addr_to_str(block.getEnd()),
            "size": block_size,
            "initialized": bool(block.isInitialized()),
            "chunks": []
        }

        if not block.isInitialized():
            manifest.append(block_entry)
            continue

        offset = 0
        while offset < block_size:
            chunk_len = min(chunk_size, block_size - offset)
            if chunk_len <= 0:
                break

            start_addr = block.getStart().add(offset)
            end_addr = start_addr.add(chunk_len - 1)
            chunk_filename = "chunk_%s_%s.hex" % (start_addr.toString(), end_addr.toString())
            chunk_path = os.path.join(block_dir, chunk_filename)

            dump = hexdump_memory(start_addr, chunk_len)
            write_text(chunk_path, dump)

            block_entry["chunks"].append({
                "start": _addr_to_str(start_addr),
                "end": _addr_to_str(end_addr),
                "path": os.path.relpath(chunk_path, base_dir),
                "length": chunk_len
            })

            offset += chunk_len

        manifest.append(block_entry)

    return manifest

def run():
    args = getScriptArgs() or ["./"]
    if not args:
        raise RuntimeError("Usage: kingaidra_export.py <OUT_DIR>")
    has_hexdump = False
    if "--hexdump" in args:
        has_hexdump = True

    out_root = os.path.abspath(args[0])

    prog = currentProgram
    pname = os.path.basename(prog.getExecutablePath() or prog.getName())
    base_dir = os.path.join(out_root, pname)
    decomp_dir = os.path.join(base_dir, "decomp")
    asm_dir = os.path.join(base_dir, "asm")
    if has_hexdump:
        hexdump_dir = os.path.join(base_dir, "hexdumps")

    _make_dir(base_dir)
    _make_dir(decomp_dir)
    _make_dir(asm_dir)
    if has_hexdump:
        _make_dir(hexdump_dir)

    kai = GhidraUtilImpl(prog, monitor);

    # manifest
    manifest = {
        "program_name": pname,
        "language_id": str(prog.getLanguageID()),
        "arch": str(prog.getLanguage().getProcessor()),
        "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
        "image_base": _addr_to_str(prog.getImageBase()),
        "ghidra_version": Application.getApplicationVersion(),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    write_json(os.path.join(base_dir, "manifest.json"), manifest)

    # hexdump
    if has_hexdump:
        mem = prog.getMemory()
        hexdump_manifest = dump_memory_segments(mem, hexdump_dir, base_dir)
        hexdump_manifest_path = os.path.join(hexdump_dir, "hexdump.json")
        write_json(hexdump_manifest_path, {
            "segments": hexdump_manifest
        })

    # strings
    str_ref = {}
    str_list = kai.get_strings();
    str_lines = []
    for data in str_list:
        str_lines.append("%s\t%s" % (_addr_to_str(data.getAddress()), data.getDefaultValueRepresentation()))

        for ref in data.getReferenceIteratorTo():
            addr = ref.getFromAddress()
            f = kai.get_func(addr)
            if f is None:
                continue
            faddr_off = f.getEntryPoint().getOffset()
            d = str_ref.get(faddr_off, [])
            d.append(data.getDefaultValueRepresentation())
            str_ref[faddr_off] = d
    write_text(os.path.join(base_dir, "strings.txt"), "\n".join(str_lines) + ("\n" if str_lines else ""))

    # imports
    imports = collect_imports_json(prog)
    write_json(os.path.join(base_dir, "imports.json"), {"imports": imports})

    # exports
    exports = collect_exports_json(prog)
    write_json(os.path.join(base_dir, "exports.json"), {"exports": exports})

    # call graph edges (for xrefs.csv)
    edges = set()

    functions_meta_path = os.path.join(base_dir, "functions.jsonl")
    meta_lines = []
    itr = currentProgram.getListing().getFunctions(True)
    dif = make_decompiler(prog)
    while itr.hasNext() and not monitor.isCancelled():
        try:
            f = itr.next()
            faddr = f.getEntryPoint()

            # decompile
            decomp_func = dif.decompileFunction(f, 0, monitor).getDecompiledFunction()
            if decomp_func:
                decomp = decomp_func.getC()
            else:
                decomp = "/* decompilation failed or empty */\n"

            c_path = os.path.join(decomp_dir, "func_%s.c" % faddr.toString())
            write_text(c_path, decomp)

            # asm
            asm_path = os.path.join(asm_dir, "func_%s.asm" % faddr.toString())
            asm = kai.get_asm(faddr, True)
            write_text(asm_path, asm if asm else "/* assembly dump failed or empty */\n")

            callers = kai.get_caller(f)
            callees = kai.get_callee(f)
            for c in callees:
                edges.add((_addr_to_str(faddr), _addr_to_str(c.getEntryPoint())))

            proto = f.getSignature().getPrototypeString()

            rec = {
                "addr": _addr_to_str(faddr),
                "name": f.getName(),
                "prototype": proto,
                "strings": sorted(list(str_ref.get(faddr.getOffset(), [])))[:2000],
                "callers": [{"name": c.getName(), "addr":_addr_to_str(c.getEntryPoint())} for c in callers],
                "callees": [{"name": c.getName(), "addr":_addr_to_str(c.getEntryPoint())} for c in callees],
                "decompiled_path": os.path.relpath(c_path, base_dir),
                "asm_path": os.path.relpath(asm_path, base_dir),
            }
            meta_lines.append(json.dumps(rec, ensure_ascii=False) + "\n")

        except Exception as e:
            print("Function export failed at %s: %s" % (_addr_to_str(f.getEntryPoint()), e))
            raise

    # per-function meta (JSONL)
    if meta_lines:
        write_text(functions_meta_path, "".join(meta_lines))
    else:
        write_text(functions_meta_path, "")

    # xrefs
    if edges:
        xrefs_lines = []
        for u,v in sorted(edges):
            xrefs_lines.append("%s,%s" % (u, v))
        write_text(os.path.join(base_dir, "xrefs.csv"), "caller,callee\n" + "\n".join(xrefs_lines))

if __name__ == "__main__":
    run()
