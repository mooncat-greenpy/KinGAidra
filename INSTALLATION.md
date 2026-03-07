# Installation Guide

This guide separates setup into:

- Core setup (required)
- Optional setup by model type
- Post-install configuration
- Optional add-ons

## Core Setup (required)

### Requirements

- Ghidra: 12.0+
- Java: version required by your Ghidra distribution
- OS: Windows / macOS / Linux

### Install Extension

1. Download the extension ZIP from:
   - <https://github.com/mooncat-greenpy/KinGAidra/releases>
2. Open Ghidra.
3. In Ghidra: `File -> Install Extensions...`
4. Add the ZIP, enable `KinGAidra`, then restart Ghidra.

### Verify Core Installation

Open any program and confirm:

- KinGAidra provider is visible.
- Tabs are available:
  - `Chat`
  - `Decom`
  - `DecomView`
  - `KeyFunc`
- Right-click actions such as `Explain using AI` appear in Code Browser.

### Configure Models in UI (required)

1. Open `Window -> Script Manager`.
2. Keep at least one chat script available (for example `kingaidra_chat.py`).
3. Open KinGAidra config (gear icon).
4. Add or select one model mapped to that script.
5. Enable it for Chat.
6. Test with: right-click a function -> `Explain using AI`.

In the same `Configure` screen, you can also:

- Add/remove model entries
- Map each model name to a script filename
- Toggle model active state per feature group

Notes:

- Chat model group allows one active model at a time.
- Decom group can keep multiple active models.

### Prepare PyGhidra pip Command (for PyGhidra-based Models)

For `kingaidra_chat_langchain.py` and `kingaidra_chat_codex.py`, install Python packages into the PyGhidra virtual environment.

First, run `pyghidraRun` once to confirm which Python executable is used:

```bash
<GHIDRA_INSTALL_DIR>/support/pyghidraRun beef
```

Check this line in the output:

`Using Python command: "/.../venv/bin/python3"`

Use that exact Python path for package installation.

Example:

```bash
"/.../venv/bin/python3" -m pip install <package>
```

In Ghidra 12.0 PUBLIC, this direct venv Python command is the reliable way to install dependencies.

## Optional Setup by Model Type

Choose the model path that matches your environment.

### OpenAI-Compatible API (`kingaidra_chat.py`, Jython)

Use this when you want a direct OpenAI-compatible endpoint with no extra pip packages.
This model does not require PyGhidra.

Set environment variable (recommended):

```bash
export OPENAI_API_KEY="YOUR_KEY"
```

Default behavior:

- `kingaidra_chat.py` is already configured for OpenAI API by default.
- In the default setup, setting `OPENAI_API_KEY` is enough to start using Chat.

If you need a non-default endpoint/model, configure these fields in `kingaidra_chat.py`:

- `URL`: OpenAI-compatible chat completions endpoint (`.../v1/chat/completions`).
- `MODEL`: Model ID sent in the request body.
- `API_KEY`: Bearer token. Default is `OPENAI_API_KEY` environment variable.
- `POST_MSG`: Text appended to selected KinGAidra tasks before sending.
- `TOOLS_FLAG`: Enables/disables tool-calling (including KinGAidra MCP tool exposure).
- `OPTIONAL_HEADERS`: Additional HTTP headers merged into the request.
- `OPTIONAL_DATA`: Additional JSON body fields merged into the request (for example `temperature`).

### LangChain Backend (`kingaidra_chat_langchain.py`, PyGhidra)

Use this when you want LangChain agent/tool integration.
This model requires PyGhidra runtime.

Install dependencies:

```bash
"/.../venv/bin/python3" -m pip install langchain langchain-mcp-adapters langchain-openai langgraph mcp
```

Default behavior:

- `kingaidra_chat_langchain.py` is already configured for OpenAI API by default.
- In the default setup, setting `OPENAI_API_KEY` is enough to start using Chat.

If you need a non-default endpoint/model, configure these fields in `kingaidra_chat_langchain.py`:

- `URL`: OpenAI-compatible API base URL (`.../v1`).
- `MODEL`: Model ID used by `ChatOpenAI`.
- `API_KEY`: API key. Default is `OPENAI_API_KEY` environment variable.
- `POST_MSG`: Text appended to selected KinGAidra tasks before sending.
- `TOOLS_FLAG`: Enables/disables MCP tool loading for the agent.
- `OPTIONAL_HEADERS`: Extra headers applied to HTTP clients used by the model.
- `OPTIONAL_DATA`: Reserved optional field in this script header (not applied in current `v1.1.0` logic).

Add external MCP servers in `kingaidra_chat_langchain.py`:

1. Open `Window -> Script Manager` and edit `kingaidra_chat_langchain.py`.
2. In `_init_mcp_tools(...)`, add your server in `connections`.
3. Keep `TOOLS_FLAG = True`.

Example (HTTP MCP server):

```python
def _init_mcp_tools(kingaidra_mcp_url):
    connections = {
        "my_external_mcp": {
            "transport": "http",
            "url": "http://127.0.0.1:9000/mcp",
        },
    }
    if kingaidra_mcp_url:
        connections[KINGAIDRA_MCP_NAME] = {
            "transport": KINGAIDRA_MCP_TRANSPORT,
            "url": kingaidra_mcp_url,
        }
    client = MultiServerMCPClient(connections, tool_name_prefix=True)
    return asyncio.run(client.get_tools())
```

This keeps KinGAidra MCP tools and external MCP tools available in the same model run.
Manual `kingaidra_mcp.py` setup is not required.

### Codex CLI Backend (`kingaidra_chat_codex.py`, PyGhidra)

Use this when you want Codex CLI-based operation.
This model requires PyGhidra runtime.

Prerequisites:

- `codex` CLI available in your environment (or specify `CODEX_BINARY`)
- Writable directory for Codex state (`.codex`) at your chosen location

Install dependencies:

```bash
"/.../venv/bin/python3" -m pip install git+https://github.com/mooncat-greenpy/codex-cli-helpers mcp
```

In `kingaidra_chat_codex.py`, configure these fields:

- `MODEL`: Model passed to Codex CLI (`--model` is added automatically).
- `MODEL_REASONING_EFFORT`: Adds `-c model_reasoning_effort=...` when set.
- `CODEX_BINARY`: Codex CLI executable name or full path. On Windows, set this to `codex.cmd`.
- `CODEX_WORKDIR`: Working directory used by Codex CLI; `.codex` state is expected under this path.
- `CODEX_EXTRA_ARGS`: Extra Codex CLI arguments appended to each run.
- `POST_MSG`: Text appended to selected KinGAidra tasks before sending.
- `TOOLS_FLAG`: Enables/disables passing KinGAidra MCP server config to Codex CLI.

Initial setup steps in KinGAidra:

1. Ensure Codex CLI is installed and accessible:
   - `codex --version`
2. Choose where to keep Codex state and initialize auth in that location:
   - KinGAidra Codex backend uses `.codex` under `CODEX_WORKDIR`, so initialize login for that same path.

```bash
# Example: set Codex working/state directory to any writable path
export CODEX_WORKDIR="<path>/codex_dir"
export CODEX_HOME="$CODEX_WORKDIR/.codex"

# Required: create CODEX_HOME before running codex login status/login
mkdir -p "$CODEX_HOME"

# Check login state for that CODEX_HOME
codex login status

# If not logged in, run authentication
codex login
```

3. In `kingaidra_chat_codex.py`, set at least:
   - `CODEX_BINARY` (if not `codex` in PATH; on Windows use `codex.cmd`)
   - `CODEX_WORKDIR` (same directory used above)
   - `MODEL`
4. Open KinGAidra config (gear icon), add/select a model mapped to `kingaidra_chat_codex.py`, and enable it for Chat.
5. Validate with:
   - right-click a function -> `Explain using AI`

Manual `kingaidra_mcp.py` setup is not required.

### No API Integration (Manual External UI Workflow)

Use this when API calls are not allowed.

- Enable `kingaidra_gen_copy_text.py` and copy resolved context text into your external UI.
- Or run `kingaidra_export.py` and analyze exported data outside KinGAidra.

### Script Editing Safety Rule

When customizing copied built-in scripts:

- Edit only the section above:
  - `Only modify the code above this comment.`
- Do not edit below the marker/update-managed block.

## Post-Install Configuration

Use this section for non-backend settings after model installation.

### Prompt Customization

Prompt options path:

- `KinGAidra -> Prompts`

You can customize:

- Default system prompt
- Task-specific user prompts (`Chat`, `Decom`, `DecomView`, `KeyFunc`, etc.)

### Custom Workflow JSON

Workflow options path:

- `KinGAidra -> Prompts -> Chat -> Workflows -> Action Workflows (JSON)`

Schema:

```json
[
  {
    "name": "Workflow menu name",
    "tasks": ["Prompt step 1", "Prompt step 2"],
    "system_prompt": "Optional override"
  }
]
```

Rules:

- `name` and non-empty `tasks` are required.
- `system_prompt` is optional.
- Invalid JSON or invalid items are ignored.

Execution behavior:

- Appears in popup: `Custom Workflow using AI -> <name>`
- Steps run sequentially in one conversation.
- The same workflow name can be used in headless `--action`.

### Security and Operational Notes

- Prefer environment variables for secrets (for example `OPENAI_API_KEY`) instead of hardcoding keys.
- Verify `URL` points to the intended endpoint before enabling a model.
- If you enable tool-calling behavior (`TOOLS_FLAG` in backend scripts), review what tools are exposed in your environment.
- Treat AI-generated refactor/comment outputs as proposals and review before applying.
- If your policy requires strict data control, use local endpoints or non-API workflows (`kingaidra_gen_copy_text.py` / `kingaidra_export.py`).

## Optional Add-ons

### `kingaidra_mcp.py` (When Needed)

- If dependencies are installed (including `mcp`) and tool usage is enabled, KinGAidra can start/use MCP on demand.
- You usually do not need separate setup or direct execution of `kingaidra_mcp.py`.
- Auto-start option path: `KinGAidra -> MCP -> Auto-start MCP server` (default: `true`)

Install dependencies:

```bash
"/.../venv/bin/python3" -m pip install mcp
```

Manual controls are available when needed:

- Use `MCP Control` toolbar action for manual start/stop/status.

### Headless Execution

Runner script:

- `ghidra_scripts/kingaidra_headless_chat.java`

Common flags:

- `--action "<action-or-workflow-name>"` or `--question "<prompt>"`
- `--output <path>`
- `--model-script <script.py>`
- `--help`

Example:

```bash
analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
  -process <PROGRAM_NAME> \
  -postScript kingaidra_headless_chat.java \
  --action "Explain using AI" \
  --output explain.md
```
