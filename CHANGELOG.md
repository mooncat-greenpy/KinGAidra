# Changelog


## [x.x.x]

### Added

- Added `kingaidra_headless_chat.java` for `--question`, predefined popup actions, and JSON-defined workflow execution with markdown output.
- Added new script integrations: `kingaidra_chat_codex.py`, `kingaidra_chat_langchain.py`, and `kingaidra_mcp.py`.
- Added MCP/Ghidra tools for `run_script`, byte dump/search, datatype definition lookup, and C-source struct generation.
- Added `ChatWorkflow` JSON workflows with per-workflow `system_prompt` support.
- Added `LlmDecompileGUI` with an LLM C-view tab, saved-function browsing, search/highlighting, double-click symbol navigation, instruction-based revision, and DecompileView-guided refactor application.
- Added PlantUML block rendering in chat markdown views.
- Added a `detail` toggle in Chat UI to show or hide system/tool messages and tool-call payloads.
- Added malware triage tasks for quick behavior overviews plus staged overview/additional/report prompts.
- Added a KeyFunc split between function-reason extraction and string extraction, with updated extractors and UI.
- Added structured conversation persistence for tool calls and tool results.

### Changed

- Reorganized prompt settings under `Prompts` option groups with task-level overrides.
- Refactored MCP server control into `McpServerController` and `McpControlGui`, including status display and auto-start on program open.
- Expanded Chat UI with address/function navigation, refresh/rebuild while preserving typed input, read-only system history conversations, improved message rendering, and parallel guess/workflow execution.
- Made conversation model assignment immutable and clarified stored message semantics.
- Updated script-updater handling for multiple source scripts.
- Headless runs now resolve KinGAidra options from user tool templates and can inject an MCP URL via `KINGAIDRA_MCP_URL`.
- Tuned default chat script behavior, including the default OpenAI endpoint/model.

### Fixed

- Fixed workflow action refreshes so popup actions apply without restarting Ghidra.
- Fixed MCP setup when a server URL is not preconfigured.
- Fixed tool-call serialization and display mismatches across chat backends.
- Improved local LLM stability by retrying when empty response content is returned.
- Reduced `History` dialog lag by using lightweight metadata loading, lazy conversation loading on selection, and a reusable modeless dialog.
- Fixed default system prompt handling.

## [1.2.2]

### Added

- Added `kingaidra_export.py` for full-program export with optional hexdump output.

### Changed

- Added a verifier/review stage before applying refactor rename and datatype changes.
- Improved `kingaidra_export.py` performance.

### Compatibility

- Added Ghidra 12.0 `#@runtime Jython` markers to bundled Python scripts.

## [1.2.1]

### Changed

- Raised the automatic-analysis function threshold and disabled comment/report generation by default in `kingaidra_auto.java` to make automated runs less aggressive.

### Fixed

- Fixed the refactor prompt so requested renames consistently use `snake_case`.

## [1.2.0]

### Added

- Added `kingaidra_auto.java` for recursive callee/caller analysis, optional refactor/comment/report generation, verbose output, and cancellation handling.
- Added headless-safe automation plumbing so analysis scripts can run without depending on GUI services.
- Added function-calling support to `kingaidra_chat.py`, including optional HTTP headers/body handling for model scripts.
- Added richer analysis context support with `Explain asm with AI`, address-aware asm dumping, placeholder expansion with function-name lookup/depth, and depth-limited call-tree generation.
- Added `PromptConf` so task prompts can be configured instead of remaining hardcoded.
- Added `kingaidra_gen_copy_text.py` for placeholder-text generation without an API key.
- Added automatic report generation from decompiled code and datatype resolution in the automation flow.

### Changed

- Refactored chat, decompile, refactor, and key-function tasks to consume configurable prompt/model settings.

### Fixed

- Fixed comment insertion to clear stale comments before applying regenerated output.
- Fixed prompt issues around datatype correction, refactoring, and report generation.

## [1.1.0]

### Added

- Added AI-assisted comment generation/apply flow (`Add comments using AI`) with structured comment extraction.
- Added model configuration framework (`ModelConf`, `ModelConfSingle`, `ModelConfMultiple`) and script updater support.
- Added unified/simplified configuration UI and conversation delete action from history.

### Changed

- Consolidated multiple configuration screens into a simpler flow.
- Refined comment formatting/placement and logging behavior.

### Fixed

- Fixed refactor/comment flow edge cases and GUI/log issues.
- Fixed concurrency guard behavior around multi-comment insertion.

### Compatibility

- Added support for Ghidra 11.0 and above.

## [1.0.0]

### Added

- Added `KeyFunc` analysis workflow with dedicated UI (`KeyFuncGUI`, `StringTableGUI`) and function typing/prioritization.
- Added call-tree, caller-depth, and string/reference resolvers for chat/context extraction.
- Added conversation metadata expansion (type support, created/updated timestamps) and related history handling.
- Added translation support path in analysis flow.

### Changed

- Refactored GUI/container plumbing to consistently use program-backed conversation containers.
- Expanded README and feature guidance around key-function and history workflows.

### Fixed

- Fixed filter/script naming/container wiring issues across key-function and conversation flows.

## [0.0.2]

### Added

- Established `KinGAidra/` extension layout and migrated project files into Ghidra extension structure.
- Added core chat + conversation foundation (`Ai`, conversation models, program-backed persistence container).
- Added Chat/Guess/Log GUI screens with markdown conversation rendering.
- Added decompile/refactor foundations (address resolution to source/asm, datatype extraction/parsing, refactor helpers).
- Added broad unit test coverage for AI/decompile/Ghidra utility paths.

### Changed

- Refined plugin UI/actions and prompt behavior across early chat/decompile workflows.

### Fixed

- Fixed early task-service, prompt, and GUI reliability issues during initial feature expansion.

## [0.0.1]

### Added

- Initial public baseline with datatype-change handling groundwork.
