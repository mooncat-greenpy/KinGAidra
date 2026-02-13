#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 

# pyghidraRun + pip install mcp

import anyio
import uvicorn
import socket

from typing import List
from pydantic import BaseModel, Field

from mcp.server.fastmcp import FastMCP

import kingaidra
import ghidra.util.task.TaskMonitor as TaskMonitor

import java.util.AbstractMap as AbstractMap
import java.util.LinkedList as LinkedList

import logging
logging.disable(logging.CRITICAL)

DEFAULT_HOST = "127.0.0.1"


class RefactorParam(BaseModel):
    orig_param_name: str = Field(..., description="Original parameter name")
    new_param_name: str = Field(..., description="New parameter name")
    new_datatype: str = Field(..., description="New datatype (Ghidra datatype string)")


class RefactorVar(BaseModel):
    orig_var_name: str = Field(..., description="Original variable name")
    new_var_name: str = Field(..., description="New variable name")
    new_datatype: str = Field(..., description="New datatype (Ghidra datatype string)")


class CodeComment(BaseModel):
    source_code_line: str = Field(..., description="Source code line (as string key)")
    comment: str = Field(..., description="Comment text")

def _parse_hex_address(addr_str: str) -> int:
    s = addr_str.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("Invalid address format")
    return int(s, 16)

def _hexdump(base_addr, buf) -> str:
    if buf is None:
        return ""
    lines = []
    length = len(buf)
    for i in range(0, length, 16):
        line = "%s  " % base_addr.add(i)
        for j in range(16):
            if i + j >= length:
                break
            b = buf[i + j]
            if b < 0:
                b += 256
            line += "%02X " % b
        lines.append(line.rstrip())
    return "\n".join(lines)

def _is_valid_hex_string(hex_str: str) -> bool:
    if hex_str is None:
        return False
    s = hex_str.replace(" ", "").strip().lower()
    if not s or (len(s) % 2) != 0:
        return False
    for c in s:
        if c not in "0123456789abcdef":
            return False
    return True

def _parse_port(value):
    try:
        port = int(value)
    except Exception:
        return None
    if port <= 0 or port > 65535:
        return None
    return port

def _reserve_socket(host):
    for candidate in [host, DEFAULT_HOST]:
        sock = None
        try:
            family = socket.AF_INET6 if ":" in candidate else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((candidate, 0))
            sock.listen(1024)
            port = sock.getsockname()[1]
            return candidate, port, sock
        except Exception:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
    raise RuntimeError("Failed to reserve a free port")

def _get_program_identity():
    return currentProgram.getDomainFile().getPathname()

def _hash_identity(value):
    raw = value.encode("utf-8")
    import hashlib
    return hashlib.sha1(raw).hexdigest()

def _set_mcp_state(host, port, identity):
    url = "http://%s:%s/mcp" % (host, port)
    try:
        import java.lang.System as JavaSystem
        hash_key = _hash_identity(identity)
        JavaSystem.setProperty("kingaidra.mcp.url.%s" % hash_key, url)
    except Exception:
        pass

def _resolve_host_port(args):
    host = DEFAULT_HOST
    port = None
    sock = None
    if len(args) == 1:
        port = _parse_port(args[0])
    elif len(args) >= 2:
        host = args[0]
        port = _parse_port(args[1])
    if port is None:
        host, port, sock = _reserve_socket(host)
    return host, port, sock

def build_server(binary_id: str) -> FastMCP:
    ghidra = kingaidra.ghidra.GhidraUtilImpl(currentProgram, TaskMonitor.DUMMY)

    mcp = FastMCP(
        name=f"{binary_id}",
        json_response=True,
        stateless_http=True,
    )

    @mcp.tool()
    def get_current_address() -> str:
        """Returns the user's selected address."""
        try:
            addr = ghidra.get_current_addr()
            return "%#x" % (addr.getOffset())
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_function_address_by_name(name: str) -> str:
        """Retrieve the address of a function by its name. If multiple functions have the same name, return a list of addresses."""
        try:
            same_name_funcs = ghidra.get_func(name)
            if not same_name_funcs:
                return "None"
            out = "Addresses list.\n"
            for f in same_name_funcs:
                out += "- %#x\n" % (f.getEntryPoint().getOffset())
            return out
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_function_list() -> str:
        """Retrieve functions in the binary and return their names and addresses."""
        try:
            func_itr = currentProgram.getListing().getFunctions(True)
            out = "Functions list.\n"
            while func_itr.hasNext():
                f = func_itr.next()
                out += "- [%#x]: %s\n" % (f.getEntryPoint().getOffset(), f.getName())
            return out
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_callee_function(func_name: str) -> str:
        """Retrieve functions that are called by the specified function and return their names and addresses."""
        try:
            func_list = ghidra.get_func(func_name)
            if not func_list or len(func_list) == 0:
                return "Invalid function name"

            out = ""
            for f in func_list:
                callees = ghidra.get_callee(f)
                out += "%s\n" % f.getName()
                for c in callees:
                    out += "- [%#x]: %s\n" % (c.getEntryPoint().getOffset(), c.getName())
                out += "\n"
            return out or "Failed"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_caller_function(func_name: str) -> str:
        """Retrieve functions that call the specified function and return their names and addresses."""
        try:
            func_list = ghidra.get_func(func_name)
            if not func_list or len(func_list) == 0:
                return "Invalid function name"

            out = ""
            for f in func_list:
                callers = ghidra.get_caller(f)
                out += "%s\n" % f.getName()
                for c in callers:
                    out += "- [%#x]: %s\n" % (c.getEntryPoint().getOffset(), c.getName())
                out += "\n"
            return out or "Failed"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_asm_by_address(address: str) -> str:
        """Retrieve the assembly code of the specified function. Address is hex string (e.g. 0x401000)."""
        try:
            addr_int = _parse_hex_address(address)
            addr = ghidra.get_addr(addr_int)
            if not addr:
                return "Invalid address"
            content = ghidra.get_asm(addr)
            return content if content else "Invalid address"
        except ValueError:
            return "Invalid address format"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_asm(func_name: str) -> str:
        """Retrieve the assembly code of the specified function."""
        try:
            funcs = ghidra.get_func(func_name)
            if not funcs or len(funcs) != 1:
                return "Failed"
            f = funcs[0]
            content = ghidra.get_asm(f.getEntryPoint(), True)
            return content if content else "Failed"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_decompiled_code_by_address(address: str) -> str:
        """Retrieve the decompiled code of the specified function in C language. Address is hex string (e.g. 0x401000)."""
        try:
            addr_int = _parse_hex_address(address)
            addr = ghidra.get_addr(addr_int)
            if not addr:
                return "Invalid address"
            content = ghidra.get_decom(addr)
            return content if content else "Invalid address"
        except ValueError:
            return "Invalid address format"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_decompiled_code(func_name: str) -> str:
        """Retrieve the decompiled code of the specified function in C language."""
        try:
            funcs = ghidra.get_func(func_name)
            if not funcs or len(funcs) != 1:
                return "Failed"
            f = funcs[0]
            content = ghidra.get_decom(f.getEntryPoint())
            return (content + "\n\n") if content else "Failed"
        except Exception:
            return "Failed"

    @mcp.tool()
    def refactoring(
        address: str,
        new_func_name: str,
        params: List[RefactorParam],
        variables: List[RefactorVar],
    ) -> str:
        """Refactoring the decompiled code of the specified function in C language."""
        try:
            addr_int = _parse_hex_address(address)
            addr = ghidra.get_addr(addr_int)
            if not addr:
                return "Invalid address"

            diff = ghidra.get_decomdiff(addr)
            if not diff:
                return "Invalid address"

            diff.set_name(new_func_name)

            for p in params:
                diff.set_param_new_name(p.orig_param_name, p.new_param_name)
                diff.set_datatype_new_name(p.orig_param_name, p.new_datatype)

            for v in variables:
                diff.set_var_new_name(v.orig_var_name, v.new_var_name)
                diff.set_datatype_new_name(v.orig_var_name, v.new_datatype)

            return "Success" if ghidra.refact(diff) else "Failed"
        except ValueError:
            return "Invalid address format"
        except Exception:
            return "Failed"

    @mcp.tool()
    def add_comments(address: str, comments: List[CodeComment]) -> str:
        """Adds comments to the specified function based on the provided list."""
        try:
            addr_int = _parse_hex_address(address)
            addr = ghidra.get_addr(addr_int)
            if not addr:
                return "Invalid address"
            ghidra.clear_comments(addr)

            comments_list = LinkedList()
            for cmt in comments:
                comments_list.add(AbstractMap.SimpleEntry(cmt.source_code_line, cmt.comment))

            return "Success" if ghidra.add_comments(addr, comments_list) else "Failed"
        except ValueError:
            return "Invalid address format"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_strings() -> str:
        """Retrieve strings in the binary and their addresses."""
        try:
            data_list = ghidra.get_strings()
            if not data_list:
                return "None"
            out = "Strings list.\n"
            for d in data_list:
                out += "- [%#x]: %s\n" % (d.getAddress().getOffset(), d.getDefaultValueRepresentation())
            return out
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_imports() -> str:
        """Retrieve imported functions and their addresses."""
        try:
            fm = currentProgram.getFunctionManager()
            itr = fm.getExternalFunctions()
            content = "Imports list.\n"
            has_any = False
            while itr.hasNext():
                f = itr.next()
                name = f.getName()
                ns = f.getParentNamespace()
                if ns:
                    content += "- %s (%s)\n" % (name, ns.getName())
                else:
                    content += "- %s\n\n" % (name)
                has_any = True
            return content if has_any else "None"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_exports() -> str:
        """Retrieve exported functions and their addresses."""
        try:
            symtab = currentProgram.getSymbolTable()
            itr = symtab.getExternalEntryPointIterator()
            content = "Exports list.\n"
            has_any = False
            while itr.hasNext():
                addr = itr.next()
                sym = symtab.getPrimarySymbol(addr)
                if sym is None:
                    continue
                name = sym.getName()
                content += "- [%#x]: %s\n" % (addr.getOffset(), name)
                has_any = True
            return content if has_any else "None"
        except Exception:
            return "Failed"

    @mcp.tool()
    def get_ref_to(address: str) -> str:
        """Returns a list of reference source addresses to the specified address. Address is hex string."""
        try:
            addr_int = _parse_hex_address(address)
            addr = ghidra.get_addr(addr_int)
            if not addr:
                return "Invalid address"

            ref_list = ghidra.get_ref_to(addr)
            if not ref_list:
                return "None"

            out = "Reference address.\n"
            for r in ref_list:
                out += "- %#x\n" % (r.getFromAddress().getOffset())
            return out

        except ValueError:
            return "Invalid address format"
        except Exception:
            return "Failed"


    @mcp.tool()
    def get_bytes(address: str, size: int = 1) -> str:
        """Get bytes at address and return a hexdump. Address is hex string, size is byte count."""
        try:
            addr_int = _parse_hex_address(address)
            addr = ghidra.get_addr(addr_int)
            if not addr:
                return "Invalid address"
            if size is None or size <= 0:
                return "Size must be > 0"
            buf = ghidra.get_bytes(addr, size)
            if buf is None:
                return "Error reading memory"
            return _hexdump(addr, buf)
        except ValueError:
            return "Invalid address format"
        except Exception:
            return "Failed"

    @mcp.tool()
    def search_asm(query: str) -> list:
        """Search assembly by substring match with whitespace ignored. Use ';' or newline to separate multiple instructions (sequence search)."""
        if not query:
            return ["Error: query required"]
        try:
            hits = ghidra.search_asm(query)
            out = []
            listing = currentProgram.getListing()
            for addr in hits:
                inst = listing.getInstructionAt(addr)
                asm = inst.toString() if inst else "(no instruction)"
                out.append("%s: %s" % (addr, asm))
            return out
        except Exception:
            return ["Failed"]

    @mcp.tool()
    def search_decom(query: str) -> list:
        """Search decompiled C code by substring match with whitespace ignored. Searches all functions and can be slow."""
        if not query:
            return ["Error: query required"]
        try:
            hits = ghidra.search_decom(query)
            out = []
            for addr in hits:
                func = ghidra.get_func(addr)
                if func is not None:
                    out.append("%s: %s" % (addr, func.getName()))
                else:
                    out.append(str(addr))
            return out
        except Exception:
            return ["Failed"]

    @mcp.tool()
    def search_bytes(bytes_hex: str) -> list:
        """Search for byte sequence in memory and return addresses. bytes_hex is hex string, spaces allowed (e.g. '55 8B EC')."""
        if not _is_valid_hex_string(bytes_hex):
            return ["Error: invalid hex"]
        try:
            hits = ghidra.search_bytes(bytes_hex)
            return [str(a) for a in hits] if hits else []
        except Exception:
            return ["Failed"]

    return mcp


class NoSignalServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return


def is_ghidra_cancelled() -> bool:
    try:
        return monitor.isCancelled()
    except Exception:
        return False


async def serve(name: str, host: str, port: int, sock=None) -> None:
    print(f"[KinGAidra MCP] starting binary_name={name} host={host} port={port}")

    mcp = build_server(name)
    mcp_app = mcp.streamable_http_app()

    stopped = anyio.Event()

    config = uvicorn.Config(
        mcp_app,
        host=host,
        port=port,
        log_config=None,
        lifespan="off",
    )
    uv_server = NoSignalServer(config)

    async def run_uvicorn() -> None:
        try:
            async with mcp.session_manager.run():
                if sock is not None:
                    try:
                        await uv_server.serve(sockets=[sock])
                    except TypeError:
                        try:
                            sock.close()
                        except Exception:
                            pass
                        await uv_server.serve()
                else:
                    await uv_server.serve()
        except Exception as e:
            raise
        finally:
            stopped.set()

    async def watch_cancel_and_stop() -> None:
        while not stopped.is_set():
            if is_ghidra_cancelled():
                print("[KinGAidra MCP] Cancel detected")
                uv_server.should_exit = True

                await anyio.sleep(0.5)
                if not stopped.is_set():
                    uv_server.force_exit = True
                return

            await anyio.sleep(0.2)

    async with anyio.create_task_group() as tg:
        tg.start_soon(run_uvicorn)
        tg.start_soon(watch_cancel_and_stop)
        await stopped.wait()

    print("[KinGAidra MCP] server stopped")


def main() -> None:
    host, port, sock = _resolve_host_port(getScriptArgs())
    ident = _get_program_identity()
    _set_mcp_state(host, port, ident)
    anyio.run(serve, currentProgram.getName(), host, port, sock)


if __name__ == "__main__":
    main()
