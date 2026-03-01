# KinGAidra

KinGAidra is a Ghidra extension that brings AI-assisted reverse engineering workflows into the Ghidra workspace.
It stores analysis conversations per program and supports repeatable GUI/headless operations.

## What You Get

- **Keep analysis context in one place**: conversations and generated results stay with each program, and you can access that history directly from Ghidra without using external chat tools.
- **Standardize team procedures**: define repeatable multi-step workflows and run them from the Ghidra UI.
- **Use the same flow in automation**: execute the same named actions/workflows in headless mode for batch processing and reporting.
- **Go beyond chat responses**: generate explanations, refactor suggestions, comments, key-function priorities, and full-program exports.

## Quick Start

1. Install the extension ZIP from the [releases page](https://github.com/mooncat-greenpy/KinGAidra/releases).
2. Open Ghidra and enable `KinGAidra` in `File -> Install Extensions`, then restart.
3. In `Window -> Script Manager`, open a chat script (for example `kingaidra_chat.py`) and set required values such as `URL`, `MODEL`, and `API_KEY`, then save the script.
4. In KinGAidra config (gear icon), enable one model for Chat.
5. Right-click a function and run `Explain using AI`.
6. Open History and confirm the conversation was saved for the current program.

## Core Features

### Chat

- Ask free-form reverse engineering questions in Ghidra, then reuse the saved conversation later from the History view.
- Placeholders in prompts are resolved against the current program:
  - `<code>`, `<code:address>`, `<code:address:recursive_count>`: decompiled code
  - `<asm>`, `<asm:address>`, `<asm:address:recursive_count>`: assembly code
  - `<aasm>`, `<aasm:address>`, `<aasm:address:recursive_count>`: assembly code with addresses
  - `<strings>`, `<strings:index>`, `<strings:index:count>`: list of strings
  - `<calltree>`, `<calltree:address>`, `<calltree:address:depth>`: call tree

**Chat Example**

![Chat Example](./img/test_chat.png)

**Explain Decompiled Code**

![Explain Decompiled Code](./img/explain.png)

**Decompile Assembly**

![Decompile Assembly](./img/decom_asm.png)

### Decom (Refactoring)

Generates rename/datatype proposals and can apply them to Ghidra.

![Refactoring Example](./img/refactor.png)

### DecomView

- Generates LLM-based C view per function.
- Stores generated views in conversation history and supports regeneration/refactor.

### Commenting

- Generates comment suggestions and applies them to the current function.

![Commenting Example](./img/comment.png)

### KeyFunc

- Prioritizes functions using chat-derived evidence.
- Can reload previously saved outputs from history.

![KeyFunc Example](./img/keyfunc.png)

### History

- History shows location, type, model, and timestamp.
- Selecting an entry restores the conversation in UI.

![History Example](./img/log.png)

## Custom Workflow JSON

Configure:

`KinGAidra -> Prompts -> Chat -> Workflows -> Action Workflows (JSON)`

```json
[
  {
    "name": "IoCs",
    "system_prompt": "You are a senior malware analyst. Facts only.",
    "tasks": [
      "Summarize high-level behavior for <code> and include evidence addresses.",
      "List only high-confidence IOCs from <strings> with reasons."
    ]
  }
]
```

Behavior:

- Appears in popup: `Custom Workflow using AI -> <name>`
- Tasks run sequentially in one conversation
- Result is stored in project conversation history
- Same `name` can be executed in headless mode (`--action`)

## Headless Example

```bash
analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
  -process <PROGRAM_NAME> \
  -postScript kingaidra_headless_chat.java \
  --action "Triage: Behavior + IOC" \
  --output workflow_result.md
```

## Installation

1. Download extension ZIP from [releases](https://github.com/mooncat-greenpy/KinGAidra/releases).
2. In Ghidra: `File -> Install Extensions`.
3. Add ZIP, enable `KinGAidra`, restart Ghidra.

### Export and analyze whole program (without API key)

1. Run `kingaidra_export.py`.

![](img/export_script.png)

2. Zip the generated export directory.

![](img/export_zip.png)

3. Upload the ZIP to your web UI and ask for analysis.

![ChatGPT example: attach ZIP and prompt](img/export_chat_1.png)

![ChatGPT example: response](img/export_chat_2.png)

## FAQ

### Where is conversation history stored?

KinGAidra stores conversation records in the current program database table `KinGAidra_Conversation`.
When you switch program files, you see that program's own history.

### Can we define our own team workflow?

Yes. Define workflows as JSON in `KinGAidra -> Prompts -> Chat -> Workflows -> Action Workflows (JSON)`.
Each workflow appears as a popup action and can also be executed in headless mode.

### Can the same workflow run in CI or batch mode?

Yes. Use `kingaidra_headless_chat.java --action "<workflow name>"` to execute the same named action/workflow without GUI.
