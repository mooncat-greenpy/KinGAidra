#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


import os
import json
import time
import codecs

from ghidra.framework import Application

from kingaidra.ghidra import GhidraUtilImpl


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


def run():
    args = getScriptArgs() or ["./"]
    if not args:
        raise RuntimeError("Usage: kingaidra_export.py <OUT_DIR>")

    out_root = os.path.abspath(args[0])

    prog = currentProgram
    pname = os.path.basename(prog.getExecutablePath() or prog.getName())
    base_dir = os.path.join(out_root, pname)
    decomp_dir = os.path.join(base_dir, "decomp")
    asm_dir = os.path.join(base_dir, "asm")

    _make_dir(base_dir)
    _make_dir(decomp_dir)
    _make_dir(asm_dir)

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
    while itr.hasNext() and not monitor.isCancelled():
        try:
            f = itr.next()
            faddr = f.getEntryPoint()

            # decompile
            decomp = kai.get_decom(faddr)
            c_path = os.path.join(decomp_dir, "func_%s.c" % faddr.toString())
            write_text(c_path, decomp if decomp else "/* decompilation failed or empty */\n")

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

    print(str_ref)

    # xrefs
    if edges:
        xrefs_lines = []
        for u,v in sorted(edges):
            xrefs_lines.append("%s,%s" % (u, v))
        write_text(os.path.join(base_dir, "xrefs.csv"), "caller,callee\n" + "\n".join(xrefs_lines))

if __name__ == "__main__":
    run()
