# Usage Guide

This guide explains daily usage for Chat, Decom, DecomView, KeyFunc, History, and headless automation.

- KinGAidra stores generated conversations in the current Ghidra program database.
- History is project-scoped: when you switch program files, you see the history for that program.

## Chat Tab

Use Chat for free-form prompts plus Ghidra-aware placeholders.

### Placeholder syntax

Placeholders in prompts are resolved against the current program:

- `<code>`, `<code:address>`, `<code:address:recursive_count>`: decompiled code
- `<asm>`, `<asm:address>`, `<asm:address:recursive_count>`: assembly code
- `<aasm>`, `<aasm:address>`, `<aasm:address:recursive_count>`: assembly code with addresses
- `<strings>`, `<strings:index>`, `<strings:index:count>`: list of strings
- `<calltree>`, `<calltree:address>`, `<calltree:address:depth>`: call tree

### Typical flow

1. Select an active model in KinGAidra configuration.
2. Open `Chat` tab.
3. Enter prompt (with placeholders if needed).
4. Click `Submit`.
5. Open `History` to revisit or reload past conversations.

## Popup Actions (Right Click)

KinGAidra adds actions directly from code locations:

- `Explain using AI`
- `Explain asm with AI`
- `Decompile using AI`
- `Explain strings (malware)`
- `Quick malware behavior overview with AI`
- `Add comments using AI`
- `Refactoring using AI`
- `Decompile using AI (view)`
- `Custom Workflow using AI -> <workflow name>` (if configured)

## Decom Tab (Refactoring)

`Decom` proposes function/parameter/variable rename and datatype improvements.

1. Move cursor to a function.
2. Run `Refactoring using AI` (popup), or open `Decom` and click `Guess`.
3. Review proposals.
4. Apply refactor in Ghidra.

## DecomView Tab

`DecomView` generates LLM-based C output per function and keeps per-function results.

1. Move cursor to a function.
2. Run `Decompile using AI (view)`.
3. Optionally provide additional instruction and click `Apply Instruction`.
4. Optionally click `Refactor Ghidra` to apply from generated view.
5. Use `Saved Function` selector to browse stored results.

## KeyFunc Tab

`KeyFunc` prioritizes functions for reverse engineering based on chat outputs.

1. Open `KeyFunc`.
2. Click `Guess` to generate function priorities.
3. Click `Load History` to reload previously saved KeyFunc outputs.

## History

- Open History from the Chat toolbar icon.
- Select a row to load a past conversation into Chat view.
- Some system-generated history views are read-only in Chat.

## Headless Usage

Script: `kingaidra_headless_chat.java`

### Action mode

```bash
analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
  -import <BINARY_PATH> \
  -postScript kingaidra_headless_chat.java \
  --action "Quick malware behavior overview with AI" \
  --output result.md
```

### Question mode

```bash
analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
  -process <PROGRAM_NAME> \
  -postScript kingaidra_headless_chat.java \
  --question "Summarize behavior and list evidence addresses." \
  --output answer.md
```

### Workflow mode

If `--action` matches a configured custom workflow name, that workflow is executed.

### Options

- `-a`, `--action`
- `-q`, `--question`
- `-o`, `--output`
- `--model-script`
- `-h`, `--help`

## Custom Workflow JSON

This scenario demonstrates the same workflow in GUI and headless mode.

1. Define workflow JSON in:
`KinGAidra -> Prompts -> Chat -> Workflows -> Action Workflows (JSON)`
2. Example workflow name: `IoCs`.
3. In Code Browser popup menu, run:
`Custom Workflow using AI -> IoCs`.
4. Open History and verify the workflow conversation was saved.
5. Run headless with the same action name:

```bash
analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
  -process <PROGRAM_NAME> \
  -postScript kingaidra_headless_chat.java \
  --action "IoCs" \
  --output workflow_result.md
```

6. Compare GUI output and `workflow_result.md` for consistency in workflow intent.

## Usage Without API Key

### Placeholder Copy Workflow (`kingaidra_gen_copy_text.py`)

If you cannot call APIs directly, use the copy-text workflow:

1. Enable only `CopyTextGen` (`kingaidra_gen_copy_text.py`).
2. Generate context text via placeholders in Chat.
3. Copy output into your external web UI prompt.

### Full Program Export Workflow (`kingaidra_export.py`)

For full-program context export, run:

```text
kingaidra_export.py <OUT_DIR> [--hexdump]
```

Export includes decompile/asm/strings/imports/exports/function metadata/call edges (and optional segment hexdumps).

1. Run `kingaidra_export.py`.

![](img/export_script.png)

2. Zip the generated export directory.

![](img/export_zip.png)

3. Upload the ZIP to your web UI and ask for analysis.

![ChatGPT example: attach ZIP and prompt](img/export_chat_1.png)

![ChatGPT example: response](img/export_chat_2.png)
