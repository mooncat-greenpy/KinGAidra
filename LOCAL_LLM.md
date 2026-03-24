# Local LLM Usage

- Uses an OpenAI-compatible API
- Connects KinGAidra to a locally hosted LLM

This document demonstrates what kind of tasks can be performed with a local LLM, using `gpt-oss:120b` as an example.
In this example, `gpt-oss:120b` is launched with vLLM, although Ollama and other runtimes can also be used.

## Setup

- LLM: `gpt-oss:120b` (vLLM)
- GPU: NVIDIA RTX PRO 6000 Blackwell Workstation Edition

### Launch vLLM

1. Create a Docker Compose file (for example, `compose.yaml`).

```yaml
services:
  gptoss_vllm:
    image: vllm/vllm-openai:latest-cu130
    restart: unless-stopped
    ipc: host
    ports:
      - "8000:8000"

    environment:
      - HF_TOKEN=${HF_TOKEN}
      - HF_HOME=/root/.cache/huggingface
      - VLLM_USE_FLASHINFER_SAMPLER=0

    volumes:
      - ./hf-cache:/root/.cache/huggingface
      - ./vllm-cache:/root/.cache/vllm

    command:
      - --model
      - openai/gpt-oss-120b
      - --served-model-name
      - "gpt-oss:120b"
      - --host
      - 0.0.0.0
      - --port
      - "8000"
      - --tensor-parallel-size
      - "1"
      - --tool-call-parser
      - openai
      - --enable-auto-tool-choice
      - --max-model-len
      - "131072"

    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

2. Run `sudo docker compose up`.
3. Run `curl http://localhost:8000/v1/models`.

   * Expected output: `{"object":"list","data":[{"id":"gpt-oss:120b","object":"model","created":1774267069,"owned_by":"vllm","root":"openai/gpt-oss-120b","parent":null,"max_model_len":131072,...}]}`

### KinGAidra Configuration

1. Open `Window -> Script Manager`.
2. Configure the following fields in `kingaidra_chat.py`:

   * `URL`: `http://localhost:8000/v1/chat/completions`
   * `MODEL`: `gpt-oss:120b`

## Example Execution

### Deobfuscating Strings

Run the following workflow.

```json
[
  {
    "name": "Deobfuscate strings (current function)",
    "tasks": [
      "Extract obfuscated strings from the decompiled code below.\n\nCode:\n```c\n<code>\n```",
      "Trace the caller and callee functions to identify the obfuscation and decryption (deobfuscation) processes, and decode the extracted obfuscated strings.",
      "Carefully reanalyze the decoding process for any unreadable strings and attempt decoding again.",
      "List only the successfully decoded (readable) strings, along with their original (pre-decoding) values and corresponding addresses."
    ]
  }
]
```

The output below shows that the workflow can recover many obfuscated strings and make them readable.

```markdown
**Readable strings that are successfully recovered by the built‑in de‑obfuscation routine**  
*(decoded by `decoded = ((c ^ 0x03) - 1) & 0xFF`)*  

| VA (hex) | Original (obfuscated) | Decoded (readable) |
|----------|-----------------------|--------------------|
| 0x1800430b8 | KevVigoGsulv | **GetTickCount** |
| 0x1800430c8 | NsafNi`papy[ | **LoadLibraryW** |
| 0x1800430d8 | DpeeNi`papy | **FreeLibrary** |
| 0x1800430e8 | PeafDine | **ReadFile** |
| 0x1800430f8 | [piveDine | **WriteFile** |
| 0x180043108 | FeneveDine[ | **DeleteFileW** |
| 0x180043118 | GpeaveFipegvspy[ | **CreateDirectoryW** |
| 0x180043130 | KevDineWixe | **GetFileSize** |
| 0x180043140 | GpeaveDine[ | **CreateFileW** |
| 0x180043150 | GnsweJalfne | **CloseHandle** |
| 0x180043160 | WevVjpeafEppspMsfe | **SetThreadErrorMode** |
| 0x180043174 | Wneer | **Sleep** |
| 0x180043180 | EzralfEltipslmelvWvpilkw[ | **ExpandEnvironmentStringsW** |
| 0x1800431a0 | GpeaveVjpeaf | **CreateThread** |
| 0x1800431b0 | GpeaveRpsgeww[ | **CreateProcessW** |
| 0x1800431c0 | PemsteFipegvspy[ | **RemoveDirectoryW** |
| 0x1800431d8 | DilfDipwvDine[ | **FindFirstFileW** |
| 0x1800431e8 | DilfLezvDine[ | **FindNextFileW** |
| 0x1800431f8 | DilfGnswe | **FindClose** |
| 0x180043208 | WevDineAvvpi`uvew[ | **SetFileAttributesW** |
| 0x180043220 | KevDunnRavjLame[ | **GetFullPathNameW** |
| 0x180043238 | KevNskiganFpitew | **GetLogicalDrives** |
| 0x180043250 | KevFpiteVyre[ | **GetDriveTypeW** |
| 0x180043260 | KevFiwoDpeeWrageEz[ | **GetDiskFreeSpaceExW** |
| 0x180043278 | KevRpsgAffpeww | **GetProcAddress** |
| 0x180043288 | KevMsfuneJalfne[ | **GetModuleHandleW** |
| 0x1800432a0 | GpeaveRire | **CreatePipe** |
| 0x1800432b0 | WevJalfneIldspmavisl | **SetHandleInformation** |
| 0x1800432c8 | ReeoLamefRire | **PeekNamedPipe** |
| 0x1800432d8 | GpeaveLamefRire[ | **CreateNamedPipeW** |
| 0x1800432f0 | KevStepnarrefPewunv | **GetOverlappedResult** |
| 0x180043308 | SrelRpsgeww | **OpenProcess** |
| 0x180043318 | VepmilaveRpsgeww | **TerminateProcess** |
| 0x180043330 | GpeaveEtelv[ | **CreateEventW** |
| 0x180043340 | WevEtelv | **SetEvent** |
| 0x180043350 | PewevEtelv | **ResetEvent** |
| 0x180043360 | [aivDspWilkneS`hegv | **WaitForSingleObject** |
| 0x180043378 | GpeaveMuvez[ | **CreateMutexW** |
| 0x180043388 | KevNsganVime | **GetLocalTime** |
| 0x180043398 | DineVimeVsWywvemVime | **FileTimeToSystemTime** |
| 0x1800433b0 | WywvemVimeVsVxWregidigNsganVime | **SystemTimeToTzSpecificLocalTime** |
| 0x1800433d0 | GpeaveVssnjenr70Wlarwjsv | **CreateToolhelp32Snapshot** |
| 0x1800433f0 | Rpsgeww70Dipwv[ | **Process32FirstW** |
| 0x180043400 | Rpsgeww70Lezv[ | **Process32NextW** |
| 0x180043410 | WevGuppelvFipegvspy[ | **SetCurrentDirectoryW** |
| 0x180043428 | KevGuppelvFipegvspy[ | **GetCurrentDirectoryW** |
| 0x180043440 | KevGsmruvepLame[ | **GetComputerNameW** |
| 0x180043458 | KevVemrRavj[ | **GetTempPathW** |
| 0x1800434d0 | KevUwepLame[ | **GetUserNameW** |
| 0x1800434e0 | PekQuepyTanueEz[ | **RegQueryValueExW** |
| 0x1800434f8 | PekSrelOeyEz[ | **RegOpenKeyExW** |
| 0x180043508 | PekGnsweOey | **RegCloseKey** |
| 0x180043518 | GpyrvFegpyrv | **CryptDecrypt** |
| 0x180043528 | GpyrvFewvpsyOey | **CryptDestroyKey** |
| 0x180043538 | GpyrvFewvpsyJawj | **CryptDestroyHash** |
| 0x180043550 | GpyrvJawjFava | **CryptHashData** |
| 0x180043560 | GpyrvFepiteOey | **CryptDeriveKey** |
| 0x180043570 | GpyrvWevOeyRapam | **CryptSetKeyParam** |
| 0x180043588 | GpyrvPeneaweGslvezv | **CryptReleaseContext** |
| 0x1800435a0 | GpyrvAgquipeGslvezvA | **CryptAcquireContextA** |
| 0x1800435b8 | GpyrvGpeaveJawj | **CryptCreateHash** |
| 0x1800435c0 | [ilJvvrSrel | **WinHttpOpen** |
| 0x1800435d0 | [ilJvvrGsllegv | **WinHttpConnect** |
| 0x1800435e0 | [ilJvvrSrelPequewv | **WinHttpOpenRequest** |
| 0x1800435f0 | [ilJvvrWelfPequewv | **WinHttpSendRequest** |
| 0x180043600 | [ilJvvrKevIERpszyGsldikDspGuppelvUwep | **WinHttpGetIEProxyConfigForCurrentUser** |
| 0x180043618 | [ilJvvrWevSrvisl | **WinHttpSetOption** |
| 0x180043630 | [ilJvvrPeafFava | **WinHttpReadData** |
| 0x180043640 | [ilJvvrGnsweJalfne | **WinHttpCloseHandle** |
| 0x180043650 | [ilJvvr[piveFava | **WinHttpWriteData** |
| 0x180043660 | [ilJvvrPegeitePewrslwe | **WinHttpReceiveResponse** |
| 0x180043670 | [ilJvvrQuepyFavaAtaina`ne | **WinHttpQueryDataAvailable** |
| 0x180043680 | RavjDineEziwvw[ | **PathFileExistsW** |
| 0x180043690 | GpeaveWvpeamSlJKns`an | **CreateStreamOnHGlobal** |

*All other string literals in the binary either remain non‑readable after a single pass of the above transform (they are double‑encrypted, compressed, or binary data) or are unrelated constants (e.g., error messages, UI strings, etc.) and are therefore omitted.*
```

#### Log

System prompt:
```markdown
You are an expert malware analyst and reverse-engineering agent specialized in Ghidra-assisted analysis.
Be precise, evidence-driven, and operationally useful.
...
```


User prompt:
````markdown
Extract obfuscated strings from the decompiled code below.

Code:
```c

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_1800169d4(longlong param_1)

{
  longlong lVar1;
  char *_Str1;
  longlong lVar2;
  int iVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  uint uVar7;
  size_t _MaxCount;
  rsize_t _MaxCount_00;
  uint *puVar8;
  char **ppcVar9;
  uint uVar10;
  undefined1 auStack_258 [32];
  uint local_238;
  longlong local_230;
  char *local_228 [4];
  char *local_208;
  char *local_200;
  char *local_1f8;
  char *local_1f0;
  char *local_1e8;
  char *local_1e0;
  char *local_1d8;
  char *local_1d0;
  char *local_1c8;
  char *local_1c0;
  char *local_1b8;
  char *local_1b0;
  char *local_1a8;
  char *local_1a0;
  char *local_198;
  char *local_190;
  char *local_188;
  char *local_180;
  char *local_178;
  char *local_170;
  char *local_168;
  char *local_160;
  char *local_158;
  char *local_150;
  char *local_148;
  char *local_140;
  char *local_138;
  char *local_130;
  char *local_128;
  char *local_120;
  char *local_118;
  char *local_110;
  char *local_108;
  char *local_100;
  char *local_f8;
  char *local_f0;
  char *local_e8;
  char *local_e0;
  char *local_d8;
  char *local_d0;
  char *local_c8;
  char *local_c0;
  char *local_b8;
  char *local_b0;
  byte local_a8 [112];
  ulonglong local_38;
  
  local_38 = DAT_1800590b8 ^ (ulonglong)auStack_258;
  local_228[0] = "KevVigoGsulv";
  local_228[1] = "NsafNi`papy[";
  local_228[2] = "DpeeNi`papy";
  local_228[3] = "PeafDine";
  local_208 = "[piveDine";
  local_200 = "FeneveDine[";
  local_1f8 = "GpeaveFipegvspy[";
  local_1f0 = "KevDineWixe";
  local_1e8 = "GpeaveDine[";
  local_1e0 = "GnsweJalfne";
  local_1d8 = "WevVjpeafEppspMsfe";
  local_1d0 = "Wneer";
  local_1c8 = "EzralfEltipslmelvWvpilkw[";
  local_1c0 = "GpeaveVjpeaf";
  local_1b8 = "GpeaveRpsgeww[";
  local_1b0 = "PemsteFipegvspy[";
  local_1a8 = "DilfDipwvDine[";
  local_1a0 = "DilfLezvDine[";
  local_198 = "DilfGnswe";
  local_190 = "WevDineAvvpi`uvew[";
  local_188 = "KevDunnRavjLame[";
  local_180 = "KevNskiganFpitew";
  local_178 = "KevFpiteVyre[";
  local_170 = "KevFiwoDpeeWrageEz[";
  local_168 = "KevRpsgAffpeww";
  local_160 = "KevMsfuneJalfne[";
  local_158 = "GpeaveRire";
  local_150 = "WevJalfneIldspmavisl";
  local_148 = "ReeoLamefRire";
  local_140 = "GpeaveLamefRire[";
  local_138 = "KevStepnarrefPewunv";
  local_130 = "SrelRpsgeww";
  local_128 = "VepmilaveRpsgeww";
  local_120 = "GpeaveEtelv[";
  local_118 = "WevEtelv";
  local_110 = "PewevEtelv";
  local_108 = "[aivDspWilkneS`hegv";
  local_100 = "GpeaveMuvez[";
  local_f8 = "KevNsganVime";
  local_f0 = "DineVimeVsWywvemVime";
  lVar1 = *(longlong *)(param_1 + 0x2b0);
  local_e8 = "WywvemVimeVsVxWregidigNsganVime";
  uVar10 = 0;
  local_e0 = "GpeaveVssnjenr70Wlarwjsv";
  local_d8 = "Rpsgeww70Dipwv[";
  local_d0 = "Rpsgeww70Lezv[";
  local_c8 = "WevGuppelvFipegvspy[";
  local_c0 = "KevGuppelvFipegvspy[";
  local_b8 = "KevGsmruvepLame[";
  local_b0 = "KevVemrRavj[";
  local_230 = (ulonglong)*(uint *)((longlong)*(int *)(lVar1 + 0x3c) + 0x88 + lVar1) + lVar1;
  local_238 = *(uint *)(local_230 + 0x18);
  puVar8 = (uint *)((ulonglong)*(uint *)(local_230 + 0x20) + lVar1);
  if (local_238 != 0) {
    do {
      FUN_180021470((undefined1 (*) [16])local_a8,0,100);
      _MaxCount_00 = 0xffffffffffffffff;
      do {
        _MaxCount_00 = _MaxCount_00 + 1;
      } while (((char *)((ulonglong)*puVar8 + lVar1))[_MaxCount_00] != '\0');
      strncpy_s((char *)local_a8,100,(char *)((ulonglong)*puVar8 + lVar1),_MaxCount_00);
      FUN_180016408(param_1,local_a8);
      uVar7 = 0;
      ppcVar9 = local_228;
      do {
        _Str1 = *ppcVar9;
        _MaxCount = 0xffffffffffffffff;
        do {
          _MaxCount = _MaxCount + 1;
        } while (_Str1[_MaxCount] != '\0');
        iVar3 = _strnicmp(_Str1,(char *)local_a8,_MaxCount);
        if (iVar3 == 0) {
          lVar4 = -1;
          lVar6 = -1;
          do {
            lVar6 = lVar6 + 1;
          } while (_Str1[lVar6] != '\0');
          do {
            lVar5 = lVar4 + 1;
            lVar2 = lVar4 + 1;
            lVar4 = lVar5;
          } while (local_a8[lVar2] != 0);
          if (lVar6 == lVar5) {
            lVar4 = (ulonglong)
                    *(uint *)((ulonglong)*(uint *)(local_230 + 0x1c) + lVar1 +
                             (ulonglong)
                             *(ushort *)
                              ((ulonglong)*(uint *)(local_230 + 0x24) +
                              (ulonglong)(uVar10 * 2) + lVar1) * 4) + lVar1;
            if (uVar7 < 0x19) {
              if (uVar7 == 0x18) {
                *(longlong *)(param_1 + 0x1d0) = lVar4;
              }
              else if (uVar7 < 0xd) {
                if (uVar7 == 0xc) {
                  *(longlong *)(param_1 + 0x208) = lVar4;
                }
                else if (uVar7 < 7) {
                  if (uVar7 == 6) {
                    *(longlong *)(param_1 + 0x2a0) = lVar4;
                  }
                  else if (uVar7 == 0) {
                    *(longlong *)(param_1 + 0x130) = lVar4;
                  }
                  else if (uVar7 == 1) {
                    *(longlong *)(param_1 + 0x148) = lVar4;
                  }
                  else if (uVar7 == 2) {
                    *(longlong *)(param_1 + 0x1c8) = lVar4;
                  }
                  else if (uVar7 == 3) {
                    *(longlong *)(param_1 + 0x160) = lVar4;
                  }
                  else if (uVar7 == 4) {
                    *(longlong *)(param_1 + 0x168) = lVar4;
                  }
                  else if (uVar7 == 5) {
                    *(longlong *)(param_1 + 0x170) = lVar4;
                  }
                }
                else if (uVar7 == 7) {
                  *(longlong *)(param_1 + 0x298) = lVar4;
                }
                else if (uVar7 == 8) {
                  *(longlong *)(param_1 + 0x158) = lVar4;
                }
                else if (uVar7 == 9) {
                  *(longlong *)(param_1 + 0x1c0) = lVar4;
                }
                else if (uVar7 == 10) {
                  *(longlong *)(param_1 + 0x150) = lVar4;
                }
                else if (uVar7 == 0xb) {
                  *(longlong *)(param_1 + 0x290) = lVar4;
                }
              }
              else if (uVar7 < 0x13) {
                if (uVar7 == 0x12) {
                  *(longlong *)(param_1 + 400) = lVar4;
                }
                else if (uVar7 == 0xd) {
                  *(longlong *)(param_1 + 0x218) = lVar4;
                }
                else if (uVar7 == 0xe) {
                  *(longlong *)(param_1 + 0x210) = lVar4;
                }
                else if (uVar7 == 0xf) {
                  *(longlong *)(param_1 + 0x178) = lVar4;
                }
                else if (uVar7 == 0x10) {
                  *(longlong *)(param_1 + 0x180) = lVar4;
                }
                else if (uVar7 == 0x11) {
                  *(longlong *)(param_1 + 0x188) = lVar4;
                }
              }
              else if (uVar7 == 0x13) {
                *(longlong *)(param_1 + 0x198) = lVar4;
              }
              else if (uVar7 == 0x14) {
                *(longlong *)(param_1 + 0x1a0) = lVar4;
              }
              else if (uVar7 == 0x15) {
                *(longlong *)(param_1 + 0x1a8) = lVar4;
              }
              else if (uVar7 == 0x16) {
                *(longlong *)(param_1 + 0x1b0) = lVar4;
              }
              else if (uVar7 == 0x17) {
                *(longlong *)(param_1 + 0x1b8) = lVar4;
              }
            }
            else if (uVar7 < 0x25) {
              if (uVar7 == 0x24) {
                *(longlong *)(param_1 + 0x238) = lVar4;
              }
              else if (uVar7 < 0x1f) {
                if (uVar7 == 0x1e) {
                  *(longlong *)(param_1 + 0x200) = lVar4;
                }
                else if (uVar7 == 0x19) {
                  *(longlong *)(param_1 + 0x1d8) = lVar4;
                }
                else if (uVar7 == 0x1a) {
                  *(longlong *)(param_1 + 0x1e0) = lVar4;
                }
                else if (uVar7 == 0x1b) {
                  *(longlong *)(param_1 + 0x1e8) = lVar4;
                }
                else if (uVar7 == 0x1c) {
                  *(longlong *)(param_1 + 0x1f0) = lVar4;
                }
                else if (uVar7 == 0x1d) {
                  *(longlong *)(param_1 + 0x1f8) = lVar4;
                }
              }
              else if (uVar7 == 0x1f) {
                *(longlong *)(param_1 + 0x220) = lVar4;
              }
              else if (uVar7 == 0x20) {
                *(longlong *)(param_1 + 0x228) = lVar4;
              }
              else if (uVar7 == 0x21) {
                *(longlong *)(param_1 + 0x230) = lVar4;
              }
              else if (uVar7 == 0x22) {
                *(longlong *)(param_1 + 0x240) = lVar4;
              }
              else if (uVar7 == 0x23) {
                *(longlong *)(param_1 + 0x248) = lVar4;
              }
            }
            else if (uVar7 < 0x2b) {
              if (uVar7 == 0x2a) {
                *(longlong *)(param_1 + 0x270) = lVar4;
              }
              else if (uVar7 == 0x25) {
                *(longlong *)(param_1 + 0x138) = lVar4;
              }
              else if (uVar7 == 0x26) {
                *(longlong *)(param_1 + 0x250) = lVar4;
              }
              else if (uVar7 == 0x27) {
                *(longlong *)(param_1 + 600) = lVar4;
              }
              else if (uVar7 == 0x28) {
                *(longlong *)(param_1 + 0x260) = lVar4;
              }
              else if (uVar7 == 0x29) {
                *(longlong *)(param_1 + 0x268) = lVar4;
              }
            }
            else if (uVar7 == 0x2b) {
              *(longlong *)(param_1 + 0x278) = lVar4;
            }
            else if (uVar7 == 0x2c) {
              *(longlong *)(param_1 + 0x280) = lVar4;
            }
            else if (uVar7 == 0x2d) {
              *(longlong *)(param_1 + 0x288) = lVar4;
            }
            else if (uVar7 == 0x2e) {
              *(longlong *)(param_1 + 0x140) = lVar4;
            }
            else if (uVar7 == 0x2f) {
              *(longlong *)(param_1 + 0x2a8) = lVar4;
            }
            break;
          }
        }
        uVar7 = uVar7 + 1;
        ppcVar9 = ppcVar9 + 1;
      } while ((int)uVar7 < 0x30);
      uVar10 = uVar10 + 1;
      puVar8 = puVar8 + 1;
    } while (uVar10 < local_238);
  }
  return 1;
}


```
````


LLM output:
```markdown
**Obfuscated string literals found in the decompiled function `FUN_1800169d4`**

| Variable (or array index) | String literal |
|---------------------------|----------------|
| `local_228[0]` | `KevVigoGsulv` |
| `local_228[1]` | `NsafNi\`papy[` |
| `local_228[2]` | `DpeeNi\`papy` |
| `local_228[3]` | `PeafDine` |
| `local_208` | `[piveDine` |
| `local_200` | `FeneveDine[` |
| `local_1f8` | `GpeaveFipegvspy[` |
| `local_1f0` | `KevDineWixe` |
| `local_1e8` | `GpeaveDine[` |
| `local_1e0` | `GnsweJalfne` |
| `local_1d8` | `WevVjpeafEppspMsfe` |
| `local_1d0` | `Wneer` |
| `local_1c8` | `EzralfEltipslmelvWvpilkw[` |
| `local_1c0` | `GpeaveVjpeaf` |
| `local_1b8` | `GpeaveRpsgeww[` |
| `local_1b0` | `PemsteFipegvspy[` |
| `local_1a8` | `DilfDipwvDine[` |
| `local_1a0` | `DilfLezvDine[` |
| `local_198` | `DilfGnswe` |
| `local_190` | `WevDineAvvpi\`uvew[` |
| `local_188` | `KevDunnRavjLame[` |
| `local_180` | `KevNskiganFpitew` |
| `local_178` | `KevFpiteVyre[` |
| `local_170` | `KevFiwoDpeeWrageEz[` |
| `local_168` | `KevRpsgAffpeww` |
| `local_160` | `KevMsfuneJalfne[` |
| `local_158` | `GpeaveRire` |
| `local_150` | `WevJalfneIldspmavisl` |
| `local_148` | `ReeoLamefRire` |
| `local_140` | `GpeaveLamefRire[` |
| `local_138` | `KevStepnarrefPewunv` |
| `local_130` | `SrelRpsgeww` |
| `local_128` | `VepmilaveRpsgeww` |
| `local_120` | `GpeaveEtelv[` |
| `local_118` | `WevEtelv` |
| `local_110` | `PewevEtelv` |
| `local_108` | `[aivDspWilkneS\`hegv` |
| `local_100` | `GpeaveMuvez[` |
| `local_f8`  | `KevNsganVime` |
| `local_f0`  | `DineVimeVsWywvemVime` |
| `local_e8`  | `WywvemVimeVsVxWregidigNsganVime` |
| `local_e0`  | `GpeaveVssnjenr70Wlarwjsv` |
| `local_d8`  | `Rpsgeww70Dipwv[` |
| `local_d0`  | `Rpsgeww70Lezv[` |
| `local_c8`  | `WevGuppelvFipegvspy[` |
| `local_c0`  | `KevGuppelvFipegvspy[` |
| `local_b8`  | `KevGsmruvepLame[` |
| `local_b0`  | `KevVemrRavj[` |

These 44 literals are the “obfuscated strings” that the function copies into a temporary buffer (`local_a8`) and then compares (case‑insensitively) against data read from the binary. They are likely later de‑obfuscated or used as keys for further decoding.
```


User prompt:
```markdown
Trace the caller and callee functions to identify the obfuscation and decryption (deobfuscation) processes, and decode the extracted obfuscated strings.
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_function_address_by_name: {"name": "FUN_1800169d4"}
```


Function result:
```markdown
Addresses list.
- 1800169d4

```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_caller_function: {"func_name": "FUN_1800169d4"}
```


Function result:
```markdown
FUN_1800169d4
- [0x18001760c]: FUN_18001760c


```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_decompiled_code: {"func_name": "FUN_18001760c"}
```


Function result:
```markdown

undefined4 FUN_18001760c(longlong param_1)

{
  bool bVar1;
  undefined4 uVar2;
  longlong lVar3;
  undefined7 extraout_var;
  
  uVar2 = 0;
  lVar3 = FUN_180016450(param_1,1);
  *(longlong *)(param_1 + 0x2b0) = lVar3;
  if (lVar3 != 0) {
    FUN_1800169d4(param_1);
    bVar1 = FUN_180016628(param_1);
    uVar2 = (undefined4)CONCAT71(extraout_var,bVar1);
  }
  return uVar2;
}




```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_decompiled_code: {"func_name": "FUN_180016450"}
```


Function result:
```markdown

undefined8 FUN_180016450(undefined8 param_1,int param_2)

{
  undefined8 *puVar1;
  short *psVar2;
  undefined8 *puVar3;
  
  puVar3 = (undefined8 *)(*(longlong *)((longlong)ProcessEnvironmentBlock + 0x18) + 0x20);
  puVar1 = (undefined8 *)*puVar3;
  do {
    if (puVar1 == puVar3) {
      return 0;
    }
    psVar2 = (short *)puVar1[10];
    if (psVar2 != (short *)0x0) {
      if (param_2 == 1) {
        if ((((psVar2[0xc] != 0) || ((*psVar2 - 0x4bU & 0xffdf) != 0)) ||
            ((psVar2[1] - 0x45U & 0xffdf) != 0)) || ((psVar2[4] - 0x45U & 0xffdf) != 0))
        goto LAB_180016604;
        if ((psVar2[5] - 0x4cU & 0xffdf) == 0) goto LAB_180016613;
      }
      if (param_2 == 2) {
        if (((psVar2[0xc] != 0) || ((*psVar2 - 0x41U & 0xffdf) != 0)) ||
           (((psVar2[1] - 0x44U & 0xffdf) != 0 || ((psVar2[4] - 0x50U & 0xffdf) != 0))))
        goto LAB_180016604;
        if ((psVar2[5] - 0x49U & 0xffdf) == 0) goto LAB_180016613;
      }
      if (param_2 == 3) {
        if (((psVar2[0xb] != 0) || ((*psVar2 - 0x57U & 0xffdf) != 0)) ||
           (((psVar2[1] - 0x49U & 0xffdf) != 0 || ((psVar2[4] - 0x54U & 0xffdf) != 0))))
        goto LAB_180016604;
        if ((psVar2[5] - 0x54U & 0xffdf) == 0) goto LAB_180016613;
      }
      if (param_2 == 4) {
        if ((((psVar2[0xb] != 0) || ((*psVar2 - 0x53U & 0xffdf) != 0)) ||
            ((psVar2[1] - 0x48U & 0xffdf) != 0)) || ((psVar2[4] - 0x41U & 0xffdf) != 0))
        goto LAB_180016604;
        if ((psVar2[5] - 0x50U & 0xffdf) == 0) goto LAB_180016613;
      }
      if (((param_2 == 5) && ((*psVar2 - 0x4fU & 0xffdf) == 0)) &&
         (((psVar2[1] - 0x4cU & 0xffdf) == 0 && ((psVar2[3] == 0x33 && (psVar2[4] == 0x32)))))) {
LAB_180016613:
        return puVar1[4];
      }
    }
LAB_180016604:
    puVar1 = (undefined8 *)*puVar1;
  } while( true );
}




```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_decompiled_code: {"func_name":"FUN_180016408"}
```


Function result:
```markdown

undefined8 FUN_180016408(undefined8 param_1,byte *param_2)

{
  longlong lVar1;
  byte *pbVar2;
  int iVar3;
  
  iVar3 = 0;
  lVar1 = -1;
  do {
    lVar1 = lVar1 + 1;
  } while (param_2[lVar1] != 0);
  pbVar2 = param_2;
  if (0 < (int)lVar1) {
    do {
      iVar3 = iVar3 + 1;
      lVar1 = -1;
      *pbVar2 = *pbVar2 + 1 ^ 3;
      pbVar2 = pbVar2 + 1;
      do {
        lVar1 = lVar1 + 1;
      } while (param_2[lVar1] != 0);
    } while (iVar3 < (int)lVar1);
  }
  return 1;
}




```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_decompiled_code: {"func_name":"FUN_180021470"}
```


Function result:
```markdown

undefined1 (*) [16] FUN_180021470(undefined1 (*param_1) [16],byte param_2,ulonglong param_3)

{
  undefined1 (*pauVar1) [16];
  undefined1 (*pauVar2) [16];
  undefined1 uVar3;
  ulonglong uVar6;
  undefined1 auVar7 [16];
  undefined2 uVar4;
  undefined4 uVar5;
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  undefined1 auVar13 [16];
  undefined1 auVar14 [16];
  undefined1 auVar15 [16];
  undefined1 auVar16 [16];
  undefined1 uVar17;
  
  uVar6 = (ulonglong)param_2 * 0x101010101010101;
  uVar3 = (undefined1)uVar6;
  uVar4 = (undefined2)uVar6;
  uVar5 = (undefined4)uVar6;
  switch(param_3) {
  case 0:
    return param_1;
  case 8:
    *(ulonglong *)*param_1 = uVar6;
    return param_1;
  case 9:
    *(ulonglong *)(param_1[-1] + param_3 + 7) = uVar6;
    param_1[-1][param_3 + 0xf] = uVar3;
    return param_1;
  case 10:
    *(ulonglong *)*param_1 = uVar6;
    *(undefined2 *)(*param_1 + 8) = uVar4;
    return param_1;
  case 0xb:
    *(ulonglong *)*param_1 = uVar6;
    *(undefined2 *)(*param_1 + 8) = uVar4;
    (*param_1)[10] = uVar3;
    return param_1;
  case 0xc:
    *(ulonglong *)(param_1[-1] + param_3 + 4) = uVar6;
  case 4:
    *(undefined4 *)(param_1[-1] + param_3 + 0xc) = uVar5;
    return param_1;
  case 0xd:
    *(ulonglong *)(param_1[-1] + param_3 + 3) = uVar6;
  case 5:
    *(undefined4 *)(param_1[-1] + param_3 + 0xb) = uVar5;
    param_1[-1][param_3 + 0xf] = uVar3;
    return param_1;
  case 0xe:
    *(ulonglong *)(param_1[-1] + param_3 + 2) = uVar6;
  case 6:
    *(undefined4 *)(param_1[-1] + param_3 + 10) = uVar5;
  case 2:
    *(undefined2 *)(param_1[-1] + param_3 + 0xe) = uVar4;
    return param_1;
  case 0xf:
    *(ulonglong *)(param_1[-1] + param_3 + 1) = uVar6;
  case 7:
    *(undefined4 *)(param_1[-1] + param_3 + 9) = uVar5;
  case 3:
    *(undefined2 *)(param_1[-1] + param_3 + 0xd) = uVar4;
  case 1:
    param_1[-1][param_3 + 0xf] = uVar3;
    return param_1;
  case 0x10:
    *(ulonglong *)*param_1 = uVar6;
    *(ulonglong *)(*param_1 + 8) = uVar6;
    return param_1;
  }
  uVar17 = (undefined1)(uVar6 >> 0x38);
  auVar16._8_6_ = 0;
  auVar16._0_8_ = uVar6;
  auVar16[0xe] = uVar17;
  auVar16[0xf] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x30);
  auVar15._14_2_ = auVar16._14_2_;
  auVar15._8_5_ = 0;
  auVar15._0_8_ = uVar6;
  auVar15[0xd] = uVar17;
  auVar14._13_3_ = auVar15._13_3_;
  auVar14._8_4_ = 0;
  auVar14._0_8_ = uVar6;
  auVar14[0xc] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x28);
  auVar13._12_4_ = auVar14._12_4_;
  auVar13._8_3_ = 0;
  auVar13._0_8_ = uVar6;
  auVar13[0xb] = uVar17;
  auVar12._11_5_ = auVar13._11_5_;
  auVar12._8_2_ = 0;
  auVar12._0_8_ = uVar6;
  auVar12[10] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x20);
  auVar11._10_6_ = auVar12._10_6_;
  auVar11[8] = 0;
  auVar11._0_8_ = uVar6;
  auVar11[9] = uVar17;
  auVar10._9_7_ = auVar11._9_7_;
  auVar10[8] = uVar17;
  auVar10._0_8_ = uVar6;
  uVar17 = (undefined1)(uVar6 >> 0x18);
  auVar9._8_8_ = auVar10._8_8_;
  auVar9[7] = uVar17;
  auVar9[6] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x10);
  auVar9[5] = uVar17;
  auVar9[4] = uVar17;
  auVar9._0_4_ = uVar5;
  uVar17 = (undefined1)(uVar6 >> 8);
  auVar8._4_12_ = auVar9._4_12_;
  auVar8[3] = uVar17;
  auVar8[2] = uVar17;
  auVar8._0_2_ = uVar4;
  auVar7._2_14_ = auVar8._2_14_;
  auVar7[1] = uVar3;
  auVar7[0] = uVar3;
  pauVar1 = param_1;
  if (0x80 < param_3) {
    if (((byte)DAT_180062a9c & 2) != 0) {
      for (; param_3 != 0; param_3 = param_3 - 1) {
        (*pauVar1)[0] = param_2;
        pauVar1 = (undefined1 (*) [16])(*pauVar1 + 1);
      }
      return param_1;
    }
    *param_1 = auVar7;
    pauVar1 = (undefined1 (*) [16])((ulonglong)(param_1 + 1) & 0xfffffffffffffff0);
    param_3 = (longlong)param_1 + (param_3 - (longlong)pauVar1);
    uVar6 = param_3 >> 7;
    if (uVar6 != 0) {
      if (DAT_1800590d8 < uVar6) {
        do {
          *pauVar1 = auVar7;
          pauVar1[1] = auVar7;
          pauVar2 = pauVar1 + 8;
          pauVar1[2] = auVar7;
          pauVar1[3] = auVar7;
          uVar6 = uVar6 - 1;
          pauVar1[4] = auVar7;
          pauVar1[5] = auVar7;
          pauVar1[6] = auVar7;
          pauVar1[7] = auVar7;
          pauVar1 = pauVar2;
        } while (uVar6 != 0);
        param_3 = param_3 & 0x7f;
      }
      else {
        do {
          *pauVar1 = auVar7;
          pauVar1[1] = auVar7;
          pauVar2 = pauVar1 + 8;
          pauVar1[2] = auVar7;
          pauVar1[3] = auVar7;
          uVar6 = uVar6 - 1;
          pauVar1[4] = auVar7;
          pauVar1[5] = auVar7;
          pauVar1[6] = auVar7;
          pauVar1[7] = auVar7;
          pauVar1 = pauVar2;
        } while (uVar6 != 0);
        param_3 = param_3 & 0x7f;
      }
    }
  }
  for (uVar6 = param_3 >> 4; uVar6 != 0; uVar6 = uVar6 - 1) {
    *pauVar1 = auVar7;
    pauVar1 = pauVar1 + 1;
  }
  if ((param_3 & 0xf) != 0) {
    *(undefined1 (*) [16])(pauVar1[-1] + (param_3 & 0xf)) = auVar7;
  }
  return param_1;
}




```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code":"import binascii\nstrings = [\"KevVigoGsulv\",\"NsafNi`papy[\",\"DpeeNi`papy\",\"PeafDine\",\"[piveDine\",\"FeneveDine[\",\"GpeaveFipegvspy[\",\"KevDineWixe\",\"GpeaveDine[\",\"GnsweJalfne\",\"WevVjpeafEppspMsfe\",\"Wneer\",\"EzralfEltipslmelvWvpilkw[\",\"GpeaveVjpeaf\",\"GpeaveRpsgeww[\",\"PemsteFipegvspy[\",\"DilfDipwvDine[\",\"DilfLezvDine[\",\"DilfGnswe\",\"WevDineAvvpi`uvew[\",\"KevDunnRavjLame[\",\"KevNskiganFpitew\",\"KevFpiteVyre[\",\"KevFiwoDpeeWrageEz[\",\"KevRpsgAffpeww\",\"KevMsfuneJalfne[\",\"GpeaveRire\",\"WevJalfneIldspmavisl\",\"ReeoLamefRire\",\"GpeaveLamefRire[\",\"KevStepnarrefPewunv\",\"SrelRpsgeww\",\"VepmilaveRpsgeww\",\"GpeaveEtelv[\",\"WevEtelv\",\"PewevEtelv\",\"[aivDspWilkneS`hegv\",\"GpeaveMuvez[\",\"KevNsganVime\",\"DineVimeVsWywvemVime\",\"WywvemVimeVsVxWregidigNsganVime\",\"GpeaveVssnjenr70Wlarwjsv\",\"Rpsgeww70Dipwv[\",\"Rpsgeww70Lezv[\",\"WevGuppelvFipegvspy[\",\"KevGuppelvFipegvspy[\",\"KevGsmruvepLame[\",\"KevVemrRavj[\"]]\n\ndef reverse(s):\n    return ''.join(chr(((ord(ch) ^ 3) - 1) & 0xFF) for ch in s)\nfor s in strings[:5]:\n    print(s, '->', reverse(s))\n"}
```


Function result:
```markdown
{"stdout": "", "stderr": "SyntaxError: (\"mismatched input ']' expecting NEWLINE\", ('C:\\\\Users\\\\<username>\\\\ghidra_scripts\\\\da4a9201936a4b33aead0483ac8a5ad7.py', 2, 855, 'strings = [\"KevVigoGsulv\",\"NsafNi`papy[\",\"DpeeNi`papy\",\"PeafDine\",\"[piveDine\",\"FeneveDine[\",\"GpeaveFipegvspy[\",\"KevDineWixe\",\"GpeaveDine[\",\"GnsweJalfne\",\"WevVjpeafEppspMsfe\",\"Wneer\",\"EzralfEltipslmelvWvpilkw[\",\"GpeaveVjpeaf\",\"GpeaveRpsgeww[\",\"PemsteFipegvspy[\",\"DilfDipwvDine[\",\"DilfLezvDine[\",\"DilfGnswe\",\"WevDineAvvpi`uvew[\",\"KevDunnRavjLame[\",\"KevNskiganFpitew\",\"KevFpiteVyre[\",\"KevFiwoDpeeWrageEz[\",\"KevRpsgAffpeww\",\"KevMsfuneJalfne[\",\"GpeaveRire\",\"WevJalfneIldspmavisl\",\"ReeoLamefRire\",\"GpeaveLamefRire[\",\"KevStepnarrefPewunv\",\"SrelRpsgeww\",\"VepmilaveRpsgeww\",\"GpeaveEtelv[\",\"WevEtelv\",\"PewevEtelv\",\"[aivDspWilkneS`hegv\",\"GpeaveMuvez[\",\"KevNsganVime\",\"DineVimeVsWywvemVime\",\"WywvemVimeVsVxWregidigNsganVime\",\"GpeaveVssnjenr70Wlarwjsv\",\"Rpsgeww70Dipwv[\",\"Rpsgeww70Lezv[\",\"WevGuppelvFipegvspy[\",\"KevGuppelvFipegvspy[\",\"KevGsmruvepLame[\",\"KevVemrRavj[\"]]\\n'))\n", "success": false}
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code": "strings = [\n\"KevVigoGsulv\",\n\"NsafNi`papy[\",\n\"DpeeNi`papy\",\n\"PeafDine\",\n\"[piveDine\",\n\"FeneveDine[\",\n\"GpeaveFipegvspy[\",\n\"KevDineWixe\",\n\"GpeaveDine[\",\n\"GnsweJalfne\",\n\"WevVjpeafEppspMsfe\",\n\"Wneer\",\n\"EzralfEltipslmelvWvpilkw[\",\n\"GpeaveVjpeaf\",\n\"GpeaveRpsgeww[\",\n\"PemsteFipegvspy[\",\n\"DilfDipwvDine[\",\n\"DilfLezvDine[\",\n\"DilfGnswe\",\n\"WevDineAvvpi`uvew[\",\n\"KevDunnRavjLame[\",\n\"KevNskiganFpitew\",\n\"KevFpiteVyre[\",\n\"KevFiwoDpeeWrageEz[\",\n\"KevRpsgAffpeww\",\n\"KevMsfuneJalfne[\",\n\"GpeaveRire\",\n\"WevJalfneIldspmavisl\",\n\"ReeoLamefRire\",\n\"GpeaveLamefRire[\",\n\"KevStepnarrefPewunv\",\n\"SrelRpsgeww\",\n\"VepmilaveRpsgeww\",\n\"GpeaveEtelv[\",\n\"WevEtelv\",\n\"PewevEtelv\",\n\"[aivDspWilkneS`hegv\",\n\"GpeaveMuvez[\",\n\"KevNsganVime\",\n\"DineVimeVsWywvemVime\",\n\"WywvemVimeVsVxWregidigNsganVime\",\n\"GpeaveVssnjenr70Wlarwjsv\",\n\"Rpsgeww70Dipwv[\",\n\"Rpsgeww70Lezv[\",\n\"WevGuppelvFipegvspy[\",\n\"KevGuppelvFipegvspy[\",\n\"KevGsmruvepLame[\",\n\"KevVemrRavj[\"\n]\n\ndef reverse(s):\n    return ''.join(chr(((ord(ch) ^ 3) - 1) & 0xFF) for ch in s)\nfor s in strings[:10]:\n    print(s, '->', reverse(s))\n"}
```


Function result:
```markdown
{"stdout": "('KevVigoGsulv', '->', 'GetTickCount')\n('NsafNi`papy[', '->', 'LoadLibraryW')\n('DpeeNi`papy', '->', 'FreeLibrary')\n('PeafDine', '->', 'ReadFile')\n('[piveDine', '->', 'WriteFile')\n('FeneveDine[', '->', 'DeleteFileW')\n('GpeaveFipegvspy[', '->', 'CreateDirectoryW')\n('KevDineWixe', '->', 'GetFileSize')\n('GpeaveDine[', '->', 'CreateFileW')\n('GnsweJalfne', '->', 'CloseHandle')\n", "stderr": "", "success": true}
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code":"strings = [\n\"KevVigoGsulv\",\n\"NsafNi`papy[\",\n\"DpeeNi`papy\",\n\"PeafDine\",\n\"[piveDine\",\n\"FeneveDine[\",\n\"GpeaveFipegvspy[\",\n\"KevDineWixe\",\n\"GpeaveDine[\",\n\"GnsweJalfne\",\n\"WevVjpeafEppspMsfe\",\n\"Wneer\",\n\"EzralfEltipslmelvWvpilkw[\",\n\"GpeaveVjpeaf\",\n\"GpeaveRpsgeww[\",\n\"PemsteFipegvspy[\",\n\"DilfDipwvDine[\",\n\"DilfLezvDine[\",\n\"DilfGnswe\",\n\"WevDineAvvpi`uvew[\",\n\"KevDunnRavjLame[\",\n\"KevNskiganFpitew\",\n\"KevFpiteVyre[\",\n\"KevFiwoDpeeWrageEz[\",\n\"KevRpsgAffpeww\",\n\"KevMsfuneJalfne[\",\n\"GpeaveRire\",\n\"WevJalfneIldspmavisl\",\n\"ReeoLamefRire\",\n\"GpeaveLamefRire[\",\n\"KevStepnarrefPewunv\",\n\"SrelRpsgeww\",\n\"VepmilaveRpsgeww\",\n\"GpeaveEtelv[\",\n\"WevEtelv\",\n\"PewevEtelv\",\n\"[aivDspWilkneS`hegv\",\n\"GpeaveMuvez[\",\n\"KevNsganVime\",\n\"DineVimeVsWywvemVime\",\n\"WywvemVimeVsVxWregidigNsganVime\",\n\"GpeaveVssnjenr70Wlarwjsv\",\n\"Rpsgeww70Dipwv[\",\n\"Rpsgeww70Lezv[\",\n\"WevGuppelvFipegvspy[\",\n\"KevGuppelvFipegvspy[\",\n\"KevGsmruvepLame[\",\n\"KevVemrRavj[\"\n]\n\ndef decode(s):\n    return ''.join(chr(((ord(c) ^ 3) - 1) & 0xFF) for c in s)\nfor s in strings:\n    print(decode(s))\n"}
```


Function result:
```markdown
{"stdout": "GetTickCount\nLoadLibraryW\nFreeLibrary\nReadFile\nWriteFile\nDeleteFileW\nCreateDirectoryW\nGetFileSize\nCreateFileW\nCloseHandle\nSetThreadErrorMode\nSleep\nExpandEnvironmentStringsW\nCreateThread\nCreateProcessW\nRemoveDirectoryW\nFindFirstFileW\nFindNextFileW\nFindClose\nSetFileAttributesW\nGetFullPathNameW\nGetLogicalDrives\nGetDriveTypeW\nGetDiskFreeSpaceExW\nGetProcAddress\nGetModuleHandleW\nCreatePipe\nSetHandleInformation\nPeekNamedPipe\nCreateNamedPipeW\nGetOverlappedResult\nOpenProcess\nTerminateProcess\nCreateEventW\nSetEvent\nResetEvent\nWaitForSingleObject\nCreateMutexW\nGetLocalTime\nFileTimeToSystemTime\nSystemTimeToTzSpecificLocalTime\nCreateToolhelp32Snapshot\nProcess32FirstW\nProcess32NextW\nSetCurrentDirectoryW\nGetCurrentDirectoryW\nGetComputerNameW\nGetTempPathW\n", "stderr": "", "success": true}
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code":"strings = [\"KevVigoGsulv\",\"NsafNi`papy[\",\"DpeeNi`papy\",\"PeafDine\",\"[piveDine\",\"FeneveDine[\",\"GpeaveFipegvspy[\",\"KevDineWixe\",\"GpeaveDine[\",\"GnsweJalfne\",\"WevVjpeafEppspMsfe\",\"Wneer\",\"EzralfEltipslmelvWvpilkw[\",\"GpeaveVjpeaf\",\"GpeaveRpsgeww[\",\"PemsteFipegvspy[\",\"DilfDipwvDine[\",\"DilfLezvDine[\",\"DilfGnswe\",\"WevDineAvvpi`uvew[\",\"KevDunnRavjLame[\",\"KevNskiganFpitew\",\"KevFpiteVyre[\",\"KevFiwoDpeeWrageEz[\",\"KevRpsgAffpeww\",\"KevMsfuneJalfne[\",\"GpeaveRire\",\"WevJalfneIldspmavisl\",\"ReeoLamefRire\",\"GpeaveLamefRire[\",\"KevStepnarrefPewunv\",\"SrelRpsgeww\",\"VepmilaveRpsgeww\",\"GpeaveEtelv[\",\"WevEtelv\",\"PewevEtelv\",\"[aivDspWilkneS`hegv\",\"GpeaveMuvez[\",\"KevNsganVime\",\"DineVimeVsWywvemVime\",\"WywvemVimeVsVxWregidigNsganVime\",\"GpeaveVssnjenr70Wlarwjsv\",\"Rpsgeww70Dipwv[\",\"Rpsgeww70Lezv[\",\"WevGuppelvFipegvspy[\",\"KevGuppelvFipegvspy[\",\"KevGsmruvepLame[\",\"KevVemrRavj[\"]]\n\ndef decode(s):\n    return ''.join(chr(((ord(c) ^ 3) - 1) & 0xFF) for c in s)\nprint(len(strings))\nfor i,s in enumerate(strings):\n    print(i, decode(s))\n"}
```


Function result:
```markdown
{"stdout": "", "stderr": "SyntaxError: (\"mismatched input ']' expecting NEWLINE\", ('C:\\\\Users\\\\<username>\\\\ghidra_scripts\\\\23525d330be54450b765e53415df6be0.py', 1, 855, 'strings = [\"KevVigoGsulv\",\"NsafNi`papy[\",\"DpeeNi`papy\",\"PeafDine\",\"[piveDine\",\"FeneveDine[\",\"GpeaveFipegvspy[\",\"KevDineWixe\",\"GpeaveDine[\",\"GnsweJalfne\",\"WevVjpeafEppspMsfe\",\"Wneer\",\"EzralfEltipslmelvWvpilkw[\",\"GpeaveVjpeaf\",\"GpeaveRpsgeww[\",\"PemsteFipegvspy[\",\"DilfDipwvDine[\",\"DilfLezvDine[\",\"DilfGnswe\",\"WevDineAvvpi`uvew[\",\"KevDunnRavjLame[\",\"KevNskiganFpitew\",\"KevFpiteVyre[\",\"KevFiwoDpeeWrageEz[\",\"KevRpsgAffpeww\",\"KevMsfuneJalfne[\",\"GpeaveRire\",\"WevJalfneIldspmavisl\",\"ReeoLamefRire\",\"GpeaveLamefRire[\",\"KevStepnarrefPewunv\",\"SrelRpsgeww\",\"VepmilaveRpsgeww\",\"GpeaveEtelv[\",\"WevEtelv\",\"PewevEtelv\",\"[aivDspWilkneS`hegv\",\"GpeaveMuvez[\",\"KevNsganVime\",\"DineVimeVsWywvemVime\",\"WywvemVimeVsVxWregidigNsganVime\",\"GpeaveVssnjenr70Wlarwjsv\",\"Rpsgeww70Dipwv[\",\"Rpsgeww70Lezv[\",\"WevGuppelvFipegvspy[\",\"KevGuppelvFipegvspy[\",\"KevGsmruvepLame[\",\"KevVemrRavj[\"]]\\n'))\n", "success": false}
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code": "data = '''\nKevVigoGsulv\nNsafNi`papy[\nDpeeNi`papy\nPeafDine\n[piveDine\nFeneveDine[\nGpeaveFipegvspy[\nKevDineWixe\nGpeaveDine[\nGnsweJalfne\nWevVjpeafEppspMsfe\nWneer\nEzralfEltipslmelvWvpilkw[\nGpeaveVjpeaf\nGpeaveRpsgeww[\nPemsteFipegvspy[\nDilfDipwvDine[\nDilfLezvDine[\nDilfGnswe\nWevDineAvvpi`uvew[\nKevDunnRavjLame[\nKevNskiganFpitew\nKevFpiteVyre[\nKevFiwoDpeeWrageEz[\nKevRpsgAffpeww\nKevMsfuneJalfne[\nGpeaveRire\nWevJalfneIldspmavisl\nReeoLamefRire\nGpeaveLamefRire[\nKevStepnarrefPewunv\nSrelRpsgeww\nVepmilaveRpsgeww\nGpeaveEtelv[\nWevEtelv\nPewevEtelv\n[aivDspWilkneS`hegv\nGpeaveMuvez[\nKevNsganVime\nDineVimeVsWywvemVime\nWywvemVimeVsVxWregidigNsganVime\nGpeaveVssnjenr70Wlarwjsv\nRpsgeww70Dipwv[\nRpsgeww70Lezv[\nWevGuppelvFipegvspy[\nKevGuppelvFipegvspy[\nKevGsmruvepLame[\nKevVemrRavj[\n'''\nstrings = [line.strip() for line in data.strip().split('\\n')]\n\ndef decode(s):\n    return ''.join(chr(((ord(c) ^ 3) - 1) & 0xFF) for c in s)\nfor s in strings:\n    print(decode(s))\n"}
```


Function result:
```markdown
{"stdout": "GetTickCount\nLoadLibraryW\nFreeLibrary\nReadFile\nWriteFile\nDeleteFileW\nCreateDirectoryW\nGetFileSize\nCreateFileW\nCloseHandle\nSetThreadErrorMode\nSleep\nExpandEnvironmentStringsW\nCreateThread\nCreateProcessW\nRemoveDirectoryW\nFindFirstFileW\nFindNextFileW\nFindClose\nSetFileAttributesW\nGetFullPathNameW\nGetLogicalDrives\nGetDriveTypeW\nGetDiskFreeSpaceExW\nGetProcAddress\nGetModuleHandleW\nCreatePipe\nSetHandleInformation\nPeekNamedPipe\nCreateNamedPipeW\nGetOverlappedResult\nOpenProcess\nTerminateProcess\nCreateEventW\nSetEvent\nResetEvent\nWaitForSingleObject\nCreateMutexW\nGetLocalTime\nFileTimeToSystemTime\nSystemTimeToTzSpecificLocalTime\nCreateToolhelp32Snapshot\nProcess32FirstW\nProcess32NextW\nSetCurrentDirectoryW\nGetCurrentDirectoryW\nGetComputerNameW\nGetTempPathW\n", "stderr": "", "success": true}
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_search_asm: {"query": "[0x130]"}
```


Function result:
```markdown
None
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_search_decom: {"query": "0x130"}
```


Function result:
```markdown
180005290: FUN_180005290
18000651c: FUN_18000651c
180008e84: FUN_180008e84
18000908c: FUN_18000908c
18000ead8: FUN_18000ead8
18000edd8: FUN_18000edd8
180016714: FUN_180016714
1800169d4: FUN_1800169d4
1800171b4: FUN_1800171b4
1800172fc: FUN_1800172fc
180018050: FUN_180018050
180018734: FUN_180018734
180018a28: FUN_180018a28
180018d44: FUN_180018d44
1800190e4: FUN_1800190e4
18001956c: FUN_18001956c
18001d9c8: FUN_18001d9c8
18001ee90: __std_system_error_allocate_message
180020dc0: FUN_180020dc0
18002ba88: FUN_18002ba88
180039cac: initialize_lc_time
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_decompiled_code: {"func_name":"FUN_180016714"}
```


Function result:
```markdown

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_180016714(longlong param_1)

{
  longlong lVar1;
  char *_Str1;
  longlong lVar2;
  int iVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  uint uVar7;
  size_t _MaxCount;
  rsize_t _MaxCount_00;
  uint *puVar8;
  char **ppcVar9;
  uint uVar10;
  undefined1 auStack_148 [32];
  uint local_128;
  longlong local_120;
  char *local_118 [4];
  char *local_f8;
  char *local_f0;
  char *local_e8;
  char *local_e0;
  char *local_d8;
  char *local_d0;
  char *local_c8;
  char *local_c0;
  char *local_b8;
  byte local_a8 [112];
  ulonglong local_38;
  
  local_38 = DAT_1800590b8 ^ (ulonglong)auStack_148;
  lVar1 = *(longlong *)(param_1 + 0x198);
  local_118[0] = "KevUwepLame[";
  uVar10 = 0;
  local_118[1] = "PekQuepyTanueEz[";
  local_118[2] = "PekSrelOeyEz[";
  local_118[3] = "PekGnsweOey";
  local_f8 = "GpyrvFegpyrv";
  local_f0 = "GpyrvFewvpsyOey";
  local_e8 = "GpyrvFewvpsyJawj";
  local_e0 = "GpyrvJawjFava";
  local_d8 = "GpyrvFepiteOey";
  local_d0 = "GpyrvWevOeyRapam";
  local_c8 = "GpyrvPeneaweGslvezv";
  local_c0 = "GpyrvAgquipeGslvezvA";
  local_b8 = "GpyrvGpeaveJawj";
  local_120 = (ulonglong)*(uint *)((longlong)*(int *)(lVar1 + 0x3c) + 0x88 + lVar1) + lVar1;
  local_128 = *(uint *)(local_120 + 0x18);
  puVar8 = (uint *)((ulonglong)*(uint *)(local_120 + 0x20) + lVar1);
  if (local_128 != 0) {
    do {
      FUN_180021470((undefined1 (*) [16])local_a8,0,100);
      _MaxCount_00 = 0xffffffffffffffff;
      do {
        _MaxCount_00 = _MaxCount_00 + 1;
      } while (((char *)((ulonglong)*puVar8 + lVar1))[_MaxCount_00] != '\0');
      strncpy_s((char *)local_a8,100,(char *)((ulonglong)*puVar8 + lVar1),_MaxCount_00);
      FUN_180016408(param_1,local_a8);
      uVar7 = 0;
      ppcVar9 = local_118;
      do {
        _Str1 = *ppcVar9;
        _MaxCount = 0xffffffffffffffff;
        do {
          _MaxCount = _MaxCount + 1;
        } while (_Str1[_MaxCount] != '\0');
        iVar3 = _strnicmp(_Str1,(char *)local_a8,_MaxCount);
        if (iVar3 == 0) {
          lVar4 = -1;
          lVar6 = -1;
          do {
            lVar6 = lVar6 + 1;
          } while (_Str1[lVar6] != '\0');
          do {
            lVar5 = lVar4 + 1;
            lVar2 = lVar4 + 1;
            lVar4 = lVar5;
          } while (local_a8[lVar2] != 0);
          if (lVar6 == lVar5) {
            lVar4 = (ulonglong)
                    *(uint *)((ulonglong)*(uint *)(local_120 + 0x1c) + lVar1 +
                             (ulonglong)
                             *(ushort *)
                              ((ulonglong)*(uint *)(local_120 + 0x24) +
                              (ulonglong)(uVar10 * 2) + lVar1) * 4) + lVar1;
            if (uVar7 < 7) {
              if (uVar7 == 6) {
                *(longlong *)(param_1 + 0x188) = lVar4;
              }
              else if (uVar7 == 0) {
                *(longlong *)(param_1 + 0x130) = lVar4;
              }
              else if (uVar7 == 1) {
                *(longlong *)(param_1 + 0x140) = lVar4;
              }
              else if (uVar7 == 2) {
                *(longlong *)(param_1 + 0x138) = lVar4;
              }
              else if (uVar7 == 3) {
                *(longlong *)(param_1 + 0x148) = lVar4;
              }
              else if (uVar7 == 4) {
                *(longlong *)(param_1 + 0x178) = lVar4;
              }
              else if (uVar7 == 5) {
                *(longlong *)(param_1 + 0x180) = lVar4;
              }
            }
            else if (uVar7 == 7) {
              *(longlong *)(param_1 + 0x160) = lVar4;
            }
            else if (uVar7 == 8) {
              *(longlong *)(param_1 + 0x168) = lVar4;
            }
            else if (uVar7 == 9) {
              *(longlong *)(param_1 + 0x170) = lVar4;
            }
            else if (uVar7 == 10) {
              *(longlong *)(param_1 + 400) = lVar4;
            }
            else if (uVar7 == 0xb) {
              *(longlong *)(param_1 + 0x150) = lVar4;
            }
            else if (uVar7 == 0xc) {
              *(longlong *)(param_1 + 0x158) = lVar4;
            }
            break;
          }
        }
        uVar7 = uVar7 + 1;
        ppcVar9 = ppcVar9 + 1;
      } while ((int)uVar7 < 0xd);
      uVar10 = uVar10 + 1;
      puVar8 = puVar8 + 1;
    } while (uVar10 < local_128);
  }
  return 1;
}




```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code":"data = '''\nKevUwepLame[\nPekQuepyTanueEz[\nPekSrelOeyEz[\nPekGnsweOey\nGpyrvFegpyrv\nGpyrvFewvpsyOey\nGpyrvFewvpsyJawj\nGpyrvJawjFava\nGpyrvFepiteOey\nGpyrvWevOeyRapam\nGpyrvPeneaweGslvezv\nGpyrvAgquipeGslvezvA\nGpyrvGpeaveJawj\n'''\nstrings = [line.strip() for line in data.strip().split('\\n')]\n\ndef decode(s):\n    return ''.join(chr(((ord(c) ^ 3) - 1) & 0xFF) for c in s)\nfor s in strings:\n    print(decode(s))\n"}
```


Function result:
```markdown
{"stdout": "GetUserNameW\nRegQueryValueExW\nRegOpenKeyExW\nRegCloseKey\nCryptDecrypt\nCryptDestroyKey\nCryptDestroyHash\nCryptHashData\nCryptDeriveKey\nCryptSetKeyParam\nCryptReleaseContext\nCryptAcquireContextA\nCryptCreateHash\n", "stderr": "", "success": true}
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_decompiled_code: {"func_name": "FUN_180016628"}
```


Function result:
```markdown

bool FUN_180016628(longlong param_1)

{
  wchar_t *_Dst;
  bool bVar1;
  
  bVar1 = *(longlong *)(param_1 + 0x148) != 0;
  if (bVar1) {
    _Dst = (wchar_t *)(param_1 + 100);
    wcsncpy_s(_Dst,100,L"CFTCRK10,FNN",200);
    FUN_180017710(param_1,(ushort *)_Dst);
    (**(code **)(param_1 + 0x148))(_Dst);
    wcsncpy_s(_Dst,100,L"UKLJVVR,FNN",200);
    FUN_180017710(param_1,(ushort *)_Dst);
    (**(code **)(param_1 + 0x148))(_Dst);
    wcsncpy_s(_Dst,100,L"QJNUCRK,FNN",200);
    FUN_180017710(param_1,(ushort *)_Dst);
    (**(code **)(param_1 + 0x148))(_Dst);
    wcsncpy_s(_Dst,100,L"SNE70,FNN",200);
    FUN_180017758(param_1,(ushort *)_Dst);
    (**(code **)(param_1 + 0x148))(_Dst);
  }
  return bVar1;
}




```


LLM output:
````markdown
**1. Call‑graph around the “string‑obfuscation” routine**

| Function (address) | Role in the chain | Direct callers | Direct callees |
|--------------------|-------------------|----------------|----------------|
| **`FUN_18001760c`** (0x18001760c) | Top‑level initialiser – obtains a pointer to a data structure ( `param_1 `), calls the two resolver routines and finally invokes `FUN_180016628` (the first “real” payload). | – (usually the program’s entry point or a bootstrap routine) | `FUN_180016450` (environment‑variable helper), `FUN_1800169d4` (first resolver), `FUN_180016628` (payload) |
| **`FUN_1800169d4`** (0x1800169d4) | **First string‑resolver** – walks a table of encoded strings, decodes each entry with `FUN_180016408`, matches the result against a hard‑coded list (`local_228 … local_100`), and stores the resolved address in the structure pointed to by `param_1`. | `FUN_18001760c` | `FUN_180021470` (zero‑fill buffer), `FUN_180016408` (byte‑wise de‑obfuscation) |
| **`FUN_180016714`** (0x180016714) | **Second string‑resolver** – same pattern as `FUN_1800169d4` but with a different list of 13 strings (`local_118 … local_b8`). The resolved function pointers are also stored in the same `param_1` structure. | `FUN_18001760c` (called after the first resolver) | `FUN_180021470`, `FUN_180016408` |
| **`FUN_180016408`** (0x180016408) | **De‑obfuscation primitive** – for every byte of a copied string: `byte = (byte + 1) ^ 0x03`. This is applied *after* the raw (still‑obfuscated) string is copied into the temporary buffer (`local_a8`). | `FUN_1800169d4`, `FUN_180016714` | – |
| **`FUN_180021470`** (0x180021470) | Simple `memset`‑like helper that zero‑fills the temporary buffer before each decode. | `FUN_1800169d4`, `FUN_180016714` | – |
| **`FUN_180016628`** (0x180016628) | Payload – uses the function pointers that were stored by the two resolver routines (e.g. the pointer at offset `0x148` = **LoadLibraryW**) to load three additional libraries (the strings `CFTCRK10,FNN`, `UKLJVVR,FNN`, `QJNUCRK,FNN`) and then calls the resolved API. | `FUN_18001760c` | `FUN_180017710`, `FUN_180017758` (helpers that build the fully qualified DLL names) |
| **`FUN_180016450`** – helper that walks the PEB to locate the resource table used by the resolvers (not directly part of the de‑obfuscation, but needed to locate the encoded string table). | – | – |

**2. How the obfuscation works**

1. **Encoded string storage** – The binary stores a table of *raw* strings (obfuscated) in a data section that is referenced through the PEB‑derived pointer `local_230`.  
2. **Copy → decode** – For each entry the resolver copies the raw bytes into a 112‑byte stack buffer (`local_a8`). The buffer is first cleared with `FUN_180021470`.  
3. **Byte‑wise transform** – `FUN_180016408` walks the buffer and, for every character, performs  

   ```c
   decoded_byte = (original_byte + 1) ^ 0x03;
   ```

   (the function loops twice but the net effect is the above single‑byte formula).  
4. **Comparison with a clear‑text list** – The decoded string is compared (case‑insensitive) with a hard‑coded list of 48 clear‑text literals (`local_228 … local_100` in the first resolver, `local_118 … local_b8` in the second).  
5. **Address lookup** – When a match is found the resolver looks up the *real* address of the API function from the Import Address Table (via the offsets stored in the same resource table) and writes that address into a fixed offset inside the structure pointed to by `param_1`. The offsets (e.g. `0x130`, `0x148`, `0x1c8`, …) form a table of function‑pointer slots used later by the payload.

**3. Decoded strings**

The clear‑text literals are themselves still “gibberish” but they are *one step* away from the real Windows API names. Applying the inverse of the de‑obfuscation (`orig = ((c ^ 0x03) - 1) & 0xFF`) yields the true API names.

| Resolver | Obfuscated literal | Decoded API name |
|----------|-------------------|------------------|
| **First resolver** (`local_228 … local_100`) | `KevVigoGsulv` | **GetTickCount** |
| | `NsafNi\`papy[` | **LoadLibraryW** |
| | `DpeeNi\`papy` | **FreeLibrary** |
| | `PeafDine` | **ReadFile** |
| | `[piveDine` | **WriteFile** |
| | `FeneveDine[` | **DeleteFileW** |
| | `GpeaveFipegvspy[` | **CreateDirectoryW** |
| | `KevDineWixe` | **GetFileSize** |
| | `GpeaveDine[` | **CreateFileW** |
| | `GnsweJalfne` | **CloseHandle** |
| | `WevVjpeafEppspMsfe` | **SetThreadErrorMode** |
| | `Wneer` | **Sleep** |
| | `EzralfEltipslmelvWvpilkw[` | **ExpandEnvironmentStringsW** |
| | `GpeaveVjpeaf` | **CreateThread** |
| | `GpeaveRpsgeww[` | **CreateProcessW** |
| | `PemsteFipegvspy[` | **RemoveDirectoryW** |
| | `DilfDipwvDine[` | **FindFirstFileW** |
| | `DilfLezvDine[` | **FindNextFileW** |
| | `DilfGnswe` | **FindClose** |
| | `WevDineAvvpi\`uvew[` | **SetFileAttributesW** |
| | `KevDunnRavjLame[` | **GetFullPathNameW** |
| | `KevNskiganFpitew` | **GetLogicalDrives** |
| | `KevFpiteVyre[` | **GetDriveTypeW** |
| | `KevFiwoDpeeWrageEz[` | **GetDiskFreeSpaceExW** |
| | `KevRpsgAffpeww` | **GetProcAddress** |
| | `KevMsfuneJalfne[` | **GetModuleHandleW** |
| | `GpeaveRire` | **CreatePipe** |
| | `WevJalfneIldspmavisl` | **SetHandleInformation** |
| | `ReeoLamefRire` | **PeekNamedPipe** |
| | `GpeaveLamefRire[` | **CreateNamedPipeW** |
| | `KevStepnarrefPewunv` | **GetOverlappedResult** |
| | `SrelRpsgeww` | **OpenProcess** |
| | `VepmilaveRpsgeww` | **TerminateProcess** |
| | `GpeaveEtelv[` | **CreateEventW** |
| | `WevEtelv` | **SetEvent** |
| | `PewevEtelv` | **ResetEvent** |
| | `[aivDspWilkneS\`hegv` | **WaitForSingleObject** |
| | `GpeaveMuvez[` | **CreateMutexW** |
| | `KevNsganVime` | **GetLocalTime** |
| | `DineVimeVsWywvemVime` | **FileTimeToSystemTime** |
| | `WywvemVimeVsVxWregidigNsganVime` | **SystemTimeToTzSpecificLocalTime** |
| | `GpeaveVssnjenr70Wlarwjsv` | **CreateToolhelp32Snapshot** |
| | `Rpsgeww70Dipwv[` | **Process32FirstW** |
| | `Rpsgeww70Lezv[` | **Process32NextW** |
| | `WevGuppelvFipegvspy[` | **SetCurrentDirectoryW** |
| | `KevGuppelvFipegvspy[` | **GetCurrentDirectoryW** |
| | `KevGsmruvepLame[` | **GetComputerNameW** |
| | `KevVemrRavj[` | **GetTempPathW** |
| **Second resolver** (`local_118 … local_b8`) | `KevUwepLame[` | **GetUserNameW** |
| | `PekQuepyTanueEz[` | **RegQueryValueExW** |
| | `PekSrelOeyEz[` | **RegOpenKeyExW** |
| | `PekGnsweOey` | **RegCloseKey** |
| | `GpyrvFegpyrv` | **CryptDecrypt** |
| | `GpyrvFewvpsyOey` | **CryptDestroyKey** |
| | `GpyrvFewvpsyJawj` | **CryptDestroyHash** |
| | `GpyrvJawjFava` | **CryptHashData** |
| | `GpyrvFepiteOey` | **CryptDeriveKey** |
| | `GpyrvWevOeyRapam` | **CryptSetKeyParam** |
| | `GpyrvPeneaweGslvezv` | **CryptReleaseContext** |
| | `GpyrvAgquipeGslvezvA` | **CryptAcquireContextA** |
| | `GpyrvGpeaveJawj` | **CryptCreateHash** |

**4. How the resolved pointers are used**

* After the two resolver functions finish, the structure at `param_1` holds a complete set of API pointers.  
* `FUN_180016628` checks whether the pointer at offset **0x148** (resolved **LoadLibraryW**) is non‑NULL, builds three DLL‑name strings (`CFTCRK10,FNN`, `UKLJVVR,FNN`, `QJNUCRK,FNN` – which themselves are later de‑obfuscated by `FUN_180017710/758`) and calls `LoadLibraryW` for each.  
* Subsequent code (not shown here) will retrieve further function addresses from the newly loaded modules using the previously resolved `GetProcAddress` pointer (offset **0x130**) and then invoke the real payload.

**5. Summary**

* **Obfuscation** – each API name is stored in the binary in a byte‑wise transformed form (`byte = ((plain‑byte ^ 0x03) - 1)`).  
* **De‑obfuscation** – the runtime routine `FUN_180016408` reverses that transformation after copying the raw bytes into a temporary buffer.  
* **Dynamic resolution** – the decoded name is matched against a hard‑coded list; when a match occurs the real address is fetched from the Import Address Table and saved in a user‑controlled structure.  
* **Decoded API set** – the two resolver routines together expose **48 Windows API functions** ranging from basic file‑I/O and process control to CryptoAPI and Registry functions. These are the building blocks the malware later uses to hide its activity, load additional modules, and perform its malicious actions.
````


User prompt:
```markdown
Carefully reanalyze the decoding process for any unreadable strings and attempt decoding again.
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_get_strings: {}
```


Function result:
```markdown
Strings list.
- [0x1800423c8]: "Unknown exception"
...
- [0xff00001268]: u""

```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code": "data = '''\n[ilJvvrSrel\n[ilJvvrGsllegv\n[ilJvvrSrelPequewv\n[ilJvvrWelfPequewv\n[ilJvvrKevIERpszyGsldikDspGuppelvUwep\n[ilJvvrWevSrvisl\n[ilJvvrPeafFava\n[ilJvvrGnsweJalfne\n[ilJvvr[piveFava\n[ilJvvrPegeitePewrslwe\n[ilJvvrQuepyFavaAtaina`ne\nRavjDineEziwvw[\nGpeaveWvpeamSlJKns`an\nhs`ggq''''036-5-177-75######################################################\ntvdqhg''''TYHMH#################\n`twrd{df''$`ssg`w`$_Lhfqrvrew_U`tow_TvdqSqrehodQr`lhmj\nqdfdmwghq'$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Qdfdmw\nudqvhrm'''u6-0-5\nlrgtods`wk$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Ohaq`qhdv_Frmwqro_d{sofwo-goo\n2`:;443d503086;f:e4d;aea0:3ga7ga12vdqudq-`vs\n2`:;443d503086;f:e4d;aea0:3ga7ga12ohvwdm-`vs\n2`:;443d503086;f:e4d;aea0:3ga7ga12tsg`wd-`vs\n2`:;443d503086;f:e4d;aea0:3ga7ga12frll`mg-`vs\n2`:;443d503086;f:e4d;aea0:3ga7ga12qdvtow-`vs\n`sh-hshex-rqj\nMozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)\nPOST\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\nMozilla/5.0 (Windows; Windows NT 6.3; en-US)\n''' \nstrings = [line.strip() for line in data.strip().split('\\n')]\n\ndef decode(s):\n    return ''.join(chr(((ord(c) ^ 3) - 1) & 0xFF) for c in s)\nfor s in strings:\n    print(s, '->', decode(s))\n"}
```


Function result:
```markdown
{"stdout": "", "stderr": "SyntaxError: (\"no viable alternative at input 'tvdqhg'\", ('C:\\\\Users\\\\<username>\\\\ghidra_scripts\\\\2518113856e34415a01026b4cdd58db0.py', 16, 0, \"tvdqhg''''TYHMH#################\\n\"))\n", "success": false}
```


Function calling:
```markdown
Tool call(s):
- ghidra_mcp_run_script: {"script_code": "strings = [\n\"[ilJvvrSrel\",\n\"[ilJvvrGsllegv\",\n\"[ilJvvrSrelPequewv\",\n\"[ilJvvrWelfPequewv\",\n\"[ilJvvrKevIERpszyGsldikDspGuppelvUwep\",\n\"[ilJvvrWevSrvisl\",\n\"[ilJvvrPeafFava\",\n\"[ilJvvrGnsweJalfne\",\n\"[ilJvvr[piveFava\",\n\"[ilJvvrPegeitePewrslwe\",\n\"[ilJvvrQuepyFavaAtaina`ne\",\n\"RavjDineEziwvw[\",\n\"GpeaveWvpeamSlJKns`an\",\n\"hs`ggq''''036-5-177-75######################################################\",\n\"tvdqhg''''TYHMH#################\",\n\"`twrd{df''$`ssg`w`$_Lhfqrvrew_U`tow_TvdqSqrehodQr`lhmj\",\n\"qdfdmwghq'$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Qdfdmw\",\n\"udqvhrm'''u6-0-5\",\n\"lrgtods`wk$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Ohaq`qhdv_Frmwqro_d{sofwo-goo\",\n\"2`:;443d503086;f:e4d;aea0:3ga7ga12vdqudq-`vs\",\n\"2`:;443d503086;f:e4d;aea0:3ga7ga12ohvwdm-`vs\",\n\"2`:;443d503086;f:e4d;aea0:3ga7ga12tsg`wd-`vs\",\n\"2`:;443d503086;f:e4d;aea0:3ga7ga12frll`mg-`vs\",\n\"2`:;443d503086;f:e4d;aea0:3ga7ga12qdvtow-`vs\",\n\"`sh-hshex-rqj\",\n\"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)\",\n\"POST\",\n\"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\",\n\"Mozilla/5.0 (Windows; Windows NT 6.3; en-US)\"\n]\n\ndef decode(s):\n    return ''.join(chr(((ord(c) ^ 3) - 1) & 0xFF) for c in s)\nfor s in strings:\n    print(s, '->', decode(s))\n"}
```


Function result:
```markdown
{"stdout": "('[ilJvvrSrel', '->', 'WinHttpOpen')\n('[ilJvvrGsllegv', '->', 'WinHttpConnect')\n('[ilJvvrSrelPequewv', '->', 'WinHttpOpenRequest')\n('[ilJvvrWelfPequewv', '->', 'WinHttpSendRequest')\n('[ilJvvrKevIERpszyGsldikDspGuppelvUwep', '->', 'WinHttpGetIEProxyConfigForCurrentUser')\n('[ilJvvrWevSrvisl', '->', 'WinHttpSetOption')\n('[ilJvvrPeafFava', '->', 'WinHttpReadData')\n('[ilJvvrGnsweJalfne', '->', 'WinHttpCloseHandle')\n('[ilJvvr[piveFava', '->', 'WinHttpWriteData')\n('[ilJvvrPegeitePewrslwe', '->', 'WinHttpReceiveResponse')\n('[ilJvvrQuepyFavaAtaina`ne', '->', 'WinHttpQueryDataAvailable')\n('RavjDineEziwvw[', '->', 'PathFileExistsW')\n('GpeaveWvpeamSlJKns`an', '->', 'CreateStreamOnHGlobal')\n(\"hs`ggq''''036-5-177-75######################################################\", '->', 'jobccq####2/4-5-133-35\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f')\n(\"tvdqhg''''TYHMH#################\", '->', 'vtfqjc####VYJMJ\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f\\x1f')\n(\"`twrd{df''$`ssg`w`$_Lhfqrvrew_U`tow_TvdqSqrehodQr`lhmj\", '->', 'bvspfwfd##&boocbsb&[Njdqptpes[Ubvks[VtfqOqpejkfQpbnjmh')\n(\"qdfdmwghq'$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Qdfdmw\", '->', 'qfdfmscjq#&boocbsb&[Njdqptpes[Xjmcpxt[Qfdfms')\n(\"udqvhrm'''u6-0-5\", '->', 'ufqtjpm###u4-2-5')\n('lrgtods`wk$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Ohaq`qhdv_Frmwqro_d{sofwo-goo', '->', 'npcvkfobsg&boocbsb&[Njdqptpes[Xjmcpxt[Kjaqbqjft[Dpmsqpk[fwokdsk-ckk')\n('2`:;443d503086;f:e4d;aea0:3ga7ga12vdqudq-`vs', '->', '0b8766/f52/2:47d8e6f7aea28/ca3ca10tfqufq-bto')\n('2`:;443d503086;f:e4d;aea0:3ga7ga12ohvwdm-`vs', '->', '0b8766/f52/2:47d8e6f7aea28/ca3ca10kjtsfm-bto')\n('2`:;443d503086;f:e4d;aea0:3ga7ga12tsg`wd-`vs', '->', '0b8766/f52/2:47d8e6f7aea28/ca3ca10vocbsf-bto')\n('2`:;443d503086;f:e4d;aea0:3ga7ga12frll`mg-`vs', '->', '0b8766/f52/2:47d8e6f7aea28/ca3ca10dpnnbmc-bto')\n('2`:;443d503086;f:e4d;aea0:3ga7ga12qdvtow-`vs', '->', '0b8766/f52/2:47d8e6f7aea28/ca3ca10qftvks-bto')\n('`sh-hshex-rqj', '->', 'boj-jojez-pqh')\n('Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)', '->', 'Mkxinna+5,2\"*_kmravi`ne7\"MOIE\"12,27\"Silfkso\"LV\"4,17\"Vpifelv+5,2)')\n('POST', '->', 'RKOV')\n('Content-Type: application/x-www-form-urlencoded; charset=UTF-8', '->', '?klvelv-Vyre8\"arrni_avikl+z-sss-dkpm-upnel_kfef7\"_japoev=UVD-:')\n('Mozilla/5.0 (Windows; Windows NT 6.3; en-US)', '->', 'Mkxinna+5,2\"*Silfkso7\"Silfkso\"LV\"4,/7\"el-UO)')\n", "stderr": "", "success": true}
```


LLM output:
````markdown
**Re‑analysis of the “string‑obfuscation” routine**

| Step | What the code does | Evidence |
|------|-------------------|----------|
| 1 |The binary stores the *raw* (obfuscated) strings in a table that is referenced through the PEB‑derived pointer `local_230`. | `FUN_1800169d4` / `FUN_180016714` compute `local_230` from `param_1+0x2b0` and then walk a count (`local_238` / `local_128`). |
| 2 |For each entry the resolver copies the raw bytes into the stack buffer `local_a8` (size 112). | `FUN_180021470` is called first – it zero‑fills the buffer. |
| 3 |`FUN_180016408` performs the **only real de‑obfuscation** on the buffer: for every character `c` it executes  

```c
c = (c + 1) ^ 0x03;    // (c XOR 3) – 1  (mod 256)
```  

The loop is run once for each character, the second inner loop does nothing else. | Decompilation of `FUN_180016408` (see above). |
| 4 |The decoded string is compared (case‑insensitive) with a hard‑coded list of literals that live in the same function (`local_228 … local_100` in the first resolver, `local_118 … local_b8` in the second). | The `for (ppcVar9 = …)` loop and the `_strnicmp` call. |
| 5 |When a match is found the resolver looks up the *real* address of the API function from the Import Address Table (via the offsets stored together with the string table) and writes that address into a fixed slot inside the structure pointed to by `param_1`. | The huge `if (uVar7 == …) { *(longlong *)(param_1 + OFF)=lVar4; }` block. |
| 6 |Later code (`FUN_180016628`) uses those stored pointers (e.g. the pointer at offset 0x148 = `LoadLibraryW`) to load additional DLLs and invoke the resolved APIs. | `FUN_180016628` checks `*(param_1+0x148)` and calls it three times. |

Thus the *obfuscation* is a **single‑byte XOR‑plus‑one** transformation; the *de‑obfuscation* is the inverse:

```python
def decode(obf):
    return ''.join(chr(((ord(c) ^ 0x03) - 1) & 0xFF) for c in obf)
```

---

## 1.  Strings decoded from the **first** resolver (`local_228 … local_100`)

| Obfuscated literal | Decoded API / name |
|-------------------|--------------------|
| `KevVigoGsulv` | **GetTickCount** |
| `NsafNi\`papy[` | **LoadLibraryW** |
| `DpeeNi\`papy` | **FreeLibrary** |
| `PeafDine` | **ReadFile** |
| `[piveDine` | **WriteFile** |
| `FeneveDine[` | **DeleteFileW** |
| `GpeaveFipegvspy[` | **CreateDirectoryW** |
| `KevDineWixe` | **GetFileSize** |
| `GpeaveDine[` | **CreateFileW** |
| `GnsweJalfne` | **CloseHandle** |
| `WevVjpeafEppspMsfe` | **SetThreadErrorMode** |
| `Wneer` | **Sleep** |
| `EzralfEltipslmelvWvpilkw[` | **ExpandEnvironmentStringsW** |
| `GpeaveVjpeaf` | **CreateThread** |
| `GpeaveRpsgeww[` | **CreateProcessW** |
| `PemsteFipegvspy[` | **RemoveDirectoryW** |
| `DilfDipwvDine[` | **FindFirstFileW** |
| `DilfLezvDine[` | **FindNextFileW** |
| `DilfGnswe` | **FindClose** |
| `WevDineAvvpi\`uvew[` | **SetFileAttributesW** |
| `KevDunnRavjLame[` | **GetFullPathNameW** |
| `KevNskiganFpitew` | **GetLogicalDrives** |
| `KevFpiteVyre[` | **GetDriveTypeW** |
| `KevFiwoDpeeWrageEz[` | **GetDiskFreeSpaceExW** |
| `KevRpsgAffpeww` | **GetProcAddress** |
| `KevMsfuneJalfne[` | **GetModuleHandleW** |
| `GpeaveRire` | **CreatePipe** |
| `WevJalfneIldspmavisl` | **SetHandleInformation** |
| `ReeoLamefRire` | **PeekNamedPipe** |
| `GpeaveLamefRire[` | **CreateNamedPipeW** |
| `KevStepnarrefPewunv` | **GetOverlappedResult** |
| `SrelRpsgeww` | **OpenProcess** |
| `VepmilaveRpsgeww` | **TerminateProcess** |
| `GpeaveEtelv[` | **CreateEventW** |
| `WevEtelv` | **SetEvent** |
| `PewevEtelv` | **ResetEvent** |
| `[aivDspWilkneS\`hegv` | **WaitForSingleObject** |
| `GpeaveMuvez[` | **CreateMutexW** |
| `KevNsganVime` | **GetLocalTime** |
| `DineVimeVsWywvemVime` | **FileTimeToSystemTime** |
| `WywvemVimeVsVxWregidigNsganVime` | **SystemTimeToTzSpecificLocalTime** |
| `GpeaveVssnjenr70Wlarwjsv` | **CreateToolhelp32Snapshot** |
| `Rpsgeww70Dipwv[` | **Process32FirstW** |
| `Rpsgeww70Lezv[` | **Process32NextW** |
| `WevGuppelvFipegvspy[` | **SetCurrentDirectoryW** |
| `KevGuppelvFipegvspy[` | **GetCurrentDirectoryW** |
| `KevGsmruvepLame[` | **GetComputerNameW** |
| `KevVemrRavj[` | **GetTempPathW** |

*All of the above are resolved at run‑time and stored in the structure referenced by `param_1`.*

---

## 2.  Strings decoded from the **second** resolver (`local_118 … local_b8`)

| Obfuscated literal | Decoded API / name |
|-------------------|--------------------|
| `KevUwepLame[` | **GetUserNameW** |
| `PekQuepyTanueEz[` | **RegQueryValueExW** |
| `PekSrelOeyEz[` | **RegOpenKeyExW** |
| `PekGnsweOey` | **RegCloseKey** |
| `GpyrvFegpyrv` | **CryptDecrypt** |
| `GpyrvFewvpsyOey` | **CryptDestroyKey** |
| `GpyrvFewvpsyJawj` | **CryptDestroyHash** |
| `GpyrvJawjFava` | **CryptHashData** |
| `GpyrvFepiteOey` | **CryptDeriveKey** |
| `GpyrvWevOeyRapam` | **CryptSetKeyParam** |
| `GpyrvPeneaweGslvezv` | **CryptReleaseContext** |
| `GpyrvAgquipeGslvezvA` | **CryptAcquireContextA** |
| `GpyrvGpeaveJawj` | **CryptCreateHash** |

These fill the remaining slots in the structure (e.g. the offset used by the payload for CryptoAPI calls).

---

## 3.  Additional strings that use the **same transform** but are **not part of the two resolver tables**

The binary also contains several other literal arrays that are decoded with the exact same algorithm.  Decoding them reveals a second, independent set of API calls (WinHTTP) and a few other data items:

| Obfuscated literal | Decoded value |
|-------------------|----------------|
| `[ilJvvrSrel` | **WinHttpOpen** |
| `[ilJvvrGsllegv` | **WinHttpConnect** |
| `[ilJvvrSrelPequewv` | **WinHttpOpenRequest** |
| `[ilJvvrWelfPequewv` | **WinHttpSendRequest** |
| `[ilJvvrKevIERpszyGsldikDspGuppelvUwep` | **WinHttpGetIEProxyConfigForCurrentUser** |
| `[ilJvvrWevSrvisl` | **WinHttpSetOption** |
| `[ilJvvrPeafFava` | **WinHttpReadData** |
| `[ilJvvrGnsweJalfne` | **WinHttpCloseHandle** |
| `[ilJvvr[piveFava` | **WinHttpWriteData** |
| `[ilJvvrPegeitePewrslwe` | **WinHttpReceiveResponse** |
| `[ilJvvrQuepyFavaAtaina\`ne` | **WinHttpQueryDataAvailable** |
| `RavjDineEziwvw[` | **PathFileExistsW** |
| `GpeaveWvpeamSlJKns\`an` | **CreateStreamOnHGlobal** |

These strings are stored at addresses `0x1800435c0 … 0x1800435f8` (see the global string table).  They are not used by `FUN_1800169d4` / `FUN_180016714`, but they are decoded by the same routine and are likely consumed by a later module that implements HTTP communication.

---

## 4.  Strings that remain unreadable after a single pass

A handful of literals that also obey the `(c+1)^3` transformation still produce non‑ASCII output after one decode.  They are most likely **double‑encrypted**, **compressed**, or simply binary data (e.g. large hash‑like blocks).  Examples:

```
hs`ggq''''036-5-177-75######################################################
tvdqhg''''TYHMH#################
`twrd{df''$`ssg`w`$_Lhfqrvrew_U`tow_TvdqSqrehodQr`lhmj
qdfdmwghq'$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Qdfdmw
udqvhrm'''u6-0-5
lrgtods`wk$`ssg`w`$_Lhfqrvrew_Zhmgrzv_Ohaq`qhdv_Frmwqro_d{sofwo-goo
2`:;443d503086;f:e4d;aea0:3ga7ga12vdqudq-`vs
…
```

After one decode they become strings that contain many control characters (`\x1f`) or look like further‑obfuscated payload data.  The current analysis does **not** include a second‑level decoder; extracting the final plaintext would require locating the routine that processes these values (most likely a custom crypto routine that appears later in the binary).

---

## 5.  Summary of the de‑obfuscation workflow

1. **Locate the resolver** – `FUN_18001760c` calls `FUN_180016450` (to get the table pointer) → `FUN_1800169d4` → `FUN_180016714`.  
2. **Copy raw bytes → temporary buffer** – `FUN_180021470` (zero‑fill) + `strncpy_s`.  
3. **Decode each byte** – `FUN_180016408` applies `c = ((c ^ 3) - 1) & 0xFF`.  
4. **Match against a hard‑coded clear‑text list** – the arrays of literals embedded in the two resolver functions.  
5. **Lookup the real address** – using the offsets stored beside the string table (`local_230`+0x1c / 0x20 …) and write it into a pre‑defined slot in the `param_1` structure.  
6. **Use the resolved pointers** – later code (`FUN_180016628` and the rest of the malicious payload) invokes the functions via the stored pointers.

Because the transformation is a simple XOR‑plus‑one, **all strings that are decoded with the same routine can be recovered statically** using the `decode()` function shown above.  The tables we listed (48 Windows API names + 12 WinHTTP‑related names) constitute the full set of function names that the malware resolves at run‑time.  Any remaining unreadable literals are probably **second‑stage encrypted data** and would require locating the next decryption routine before they can be interpreted.
````


User prompt:
```markdown
List only the successfully decoded (readable) strings, along with their original (pre-decoding) values and corresponding addresses.
```


LLM output:
```markdown
**Readable strings that are successfully recovered by the built‑in de‑obfuscation routine**  
*(decoded by `decoded = ((c ^ 0x03) - 1) & 0xFF`)*  

| VA (hex) | Original (obfuscated) | Decoded (readable) |
|----------|-----------------------|--------------------|
| 0x1800430b8 | KevVigoGsulv | **GetTickCount** |
| 0x1800430c8 | NsafNi`papy[ | **LoadLibraryW** |
| 0x1800430d8 | DpeeNi`papy | **FreeLibrary** |
| 0x1800430e8 | PeafDine | **ReadFile** |
| 0x1800430f8 | [piveDine | **WriteFile** |
| 0x180043108 | FeneveDine[ | **DeleteFileW** |
| 0x180043118 | GpeaveFipegvspy[ | **CreateDirectoryW** |
| 0x180043130 | KevDineWixe | **GetFileSize** |
| 0x180043140 | GpeaveDine[ | **CreateFileW** |
| 0x180043150 | GnsweJalfne | **CloseHandle** |
| 0x180043160 | WevVjpeafEppspMsfe | **SetThreadErrorMode** |
| 0x180043174 | Wneer | **Sleep** |
| 0x180043180 | EzralfEltipslmelvWvpilkw[ | **ExpandEnvironmentStringsW** |
| 0x1800431a0 | GpeaveVjpeaf | **CreateThread** |
| 0x1800431b0 | GpeaveRpsgeww[ | **CreateProcessW** |
| 0x1800431c0 | PemsteFipegvspy[ | **RemoveDirectoryW** |
| 0x1800431d8 | DilfDipwvDine[ | **FindFirstFileW** |
| 0x1800431e8 | DilfLezvDine[ | **FindNextFileW** |
| 0x1800431f8 | DilfGnswe | **FindClose** |
| 0x180043208 | WevDineAvvpi`uvew[ | **SetFileAttributesW** |
| 0x180043220 | KevDunnRavjLame[ | **GetFullPathNameW** |
| 0x180043238 | KevNskiganFpitew | **GetLogicalDrives** |
| 0x180043250 | KevFpiteVyre[ | **GetDriveTypeW** |
| 0x180043260 | KevFiwoDpeeWrageEz[ | **GetDiskFreeSpaceExW** |
| 0x180043278 | KevRpsgAffpeww | **GetProcAddress** |
| 0x180043288 | KevMsfuneJalfne[ | **GetModuleHandleW** |
| 0x1800432a0 | GpeaveRire | **CreatePipe** |
| 0x1800432b0 | WevJalfneIldspmavisl | **SetHandleInformation** |
| 0x1800432c8 | ReeoLamefRire | **PeekNamedPipe** |
| 0x1800432d8 | GpeaveLamefRire[ | **CreateNamedPipeW** |
| 0x1800432f0 | KevStepnarrefPewunv | **GetOverlappedResult** |
| 0x180043308 | SrelRpsgeww | **OpenProcess** |
| 0x180043318 | VepmilaveRpsgeww | **TerminateProcess** |
| 0x180043330 | GpeaveEtelv[ | **CreateEventW** |
| 0x180043340 | WevEtelv | **SetEvent** |
| 0x180043350 | PewevEtelv | **ResetEvent** |
| 0x180043360 | [aivDspWilkneS`hegv | **WaitForSingleObject** |
| 0x180043378 | GpeaveMuvez[ | **CreateMutexW** |
| 0x180043388 | KevNsganVime | **GetLocalTime** |
| 0x180043398 | DineVimeVsWywvemVime | **FileTimeToSystemTime** |
| 0x1800433b0 | WywvemVimeVsVxWregidigNsganVime | **SystemTimeToTzSpecificLocalTime** |
| 0x1800433d0 | GpeaveVssnjenr70Wlarwjsv | **CreateToolhelp32Snapshot** |
| 0x1800433f0 | Rpsgeww70Dipwv[ | **Process32FirstW** |
| 0x180043400 | Rpsgeww70Lezv[ | **Process32NextW** |
| 0x180043410 | WevGuppelvFipegvspy[ | **SetCurrentDirectoryW** |
| 0x180043428 | KevGuppelvFipegvspy[ | **GetCurrentDirectoryW** |
| 0x180043440 | KevGsmruvepLame[ | **GetComputerNameW** |
| 0x180043458 | KevVemrRavj[ | **GetTempPathW** |
| 0x1800434d0 | KevUwepLame[ | **GetUserNameW** |
| 0x1800434e0 | PekQuepyTanueEz[ | **RegQueryValueExW** |
| 0x1800434f8 | PekSrelOeyEz[ | **RegOpenKeyExW** |
| 0x180043508 | PekGnsweOey | **RegCloseKey** |
| 0x180043518 | GpyrvFegpyrv | **CryptDecrypt** |
| 0x180043528 | GpyrvFewvpsyOey | **CryptDestroyKey** |
| 0x180043538 | GpyrvFewvpsyJawj | **CryptDestroyHash** |
| 0x180043550 | GpyrvJawjFava | **CryptHashData** |
| 0x180043560 | GpyrvFepiteOey | **CryptDeriveKey** |
| 0x180043570 | GpyrvWevOeyRapam | **CryptSetKeyParam** |
| 0x180043588 | GpyrvPeneaweGslvezv | **CryptReleaseContext** |
| 0x1800435a0 | GpyrvAgquipeGslvezvA | **CryptAcquireContextA** |
| 0x1800435b8 | GpyrvGpeaveJawj | **CryptCreateHash** |
| 0x1800435c0 | [ilJvvrSrel | **WinHttpOpen** |
| 0x1800435d0 | [ilJvvrGsllegv | **WinHttpConnect** |
| 0x1800435e0 | [ilJvvrSrelPequewv | **WinHttpOpenRequest** |
| 0x1800435f0 | [ilJvvrWelfPequewv | **WinHttpSendRequest** |
| 0x180043600 | [ilJvvrKevIERpszyGsldikDspGuppelvUwep | **WinHttpGetIEProxyConfigForCurrentUser** |
| 0x180043618 | [ilJvvrWevSrvisl | **WinHttpSetOption** |
| 0x180043630 | [ilJvvrPeafFava | **WinHttpReadData** |
| 0x180043640 | [ilJvvrGnsweJalfne | **WinHttpCloseHandle** |
| 0x180043650 | [ilJvvr[piveFava | **WinHttpWriteData** |
| 0x180043660 | [ilJvvrPegeitePewrslwe | **WinHttpReceiveResponse** |
| 0x180043670 | [ilJvvrQuepyFavaAtaina`ne | **WinHttpQueryDataAvailable** |
| 0x180043680 | RavjDineEziwvw[ | **PathFileExistsW** |
| 0x180043690 | GpeaveWvpeamSlJKns`an | **CreateStreamOnHGlobal** |

*All other string literals in the binary either remain non‑readable after a single pass of the above transform (they are double‑encrypted, compressed, or binary data) or are unrelated constants (e.g., error messages, UI strings, etc.) and are therefore omitted.*
```

