# KinGAidra Plugin

KinGAidra is a Ghidra extension designed to enhance reverse engineering workflows by integrating AI capabilities. It helps analysts understand binaries more efficiently.

## Features
- [**AI Chat for Assembly and Decompilation**](#Chat): Interact with AI to discuss and analyze binaries.
- [**AI-Assisted Refactoring**](#Refactoring): Automatically refactor decompiled code using AI-generated suggestions.
- [**AI-Assisted Commenting**](#Commenting): Automatically add comments to decompiled code using AI-generated suggestions.
- [**Key Function Identification**](#KeyFunc): Utilize AI to identify important functions in a binary for analysis.
- [**Chat History**](#History): Save chat logs for future reference or analysis.
- [**Customizable Models**](#Configuration): Employ various AI models to meet your specific needs.


### Chat

The Chat feature in KinGAidra allows users to interact with an AI to discuss and analyze binaries.

- Inputs enclosed in `<code>`, `<code:address>`, or `<code:address:recursive_count>` tags will be converted into decompiled code.
- Inputs enclosed in `<asm>`, `<asm:address>`, or `<asm:address:recursive_count>` tags will be converted into assembly code.
- Inputs enclosed in `<aasm>`, `<aasm:address>`, or `<aasm:address:recursive_count>` tags will be converted into assembly code with addresses.
- Inputs enclosed in `<strings>`, `<strings:index>`, or `<strings:index:count>` tags will be converted into a list of strings.
- Inputs enclosed in `<calltree>`, `<calltree:address>`, or `<calltree:address:depth>` tags will be converted into a call tree.

**Chat Example**

![Chat Example](./img/test_chat.png)

**Explain Decompiled Code**

![Explain Decompiled Code](./img/explain.png)

**Decompile Assembly**

![Decompile Assembly](./img/decom_asm.png)

### Refactoring

The Refactoring feature in KinGAidra enables users to automatically refactor decompiled code using AI-generated suggestions.

![Refactoring Example](./img/refactor.png)

### Commenting

The Commenting feature in KinGAidra allows users to automatically add comments to decompiled code using AI-generated suggestions. This feature helps in understanding the code better by providing meaningful comments that explain the functionality of the code.

![Commenting Example](./img/comment.png)

### KeyFunc

The KeyFunc feature in KinGAidra assists users in identifying and prioritizing key functions within a binary for analysis. This feature leverages AI to highlight functions of interest, allowing analysts to focus on critical parts of the code.

![KeyFunc Example](./img/keyfunc.png)

### History

The History feature in KinGAidra allows users to save chat logs for future reference or analysis. This can be particularly useful for tracking the progress of reverse engineering tasks, sharing insights with team members, or revisiting previous conversations to extract valuable information.

![History Example](./img/log.png)

## Scripts

Default scripts.

- `kingaidra_gen_copy_text.py`: Displays prompts with placeholders resolved, ready to copy into a UI such as ChatGPT.
- `kingaidra_auto.py`: Automatically analyzes multiple functions.
- `kingaidra_chat.py`: Provides a customizable interface for sending and receiving queries to LLMs within KinGAidra.

## Installation

To install KinGAidra, follow these steps:

1. **Download the latest release**: Visit the [KinGAidra releases page](https://github.com/mooncat-greenpy/KinGAidra/releases) and download the latest release zip file.
2. **Launch Ghidra**: Open Ghidra on your system.
3. **Install the extension**:
   - Navigate to `File -> Install Extensions`
   - Click on `Add extension`
   - Select the downloaded zip file
4. **Enable KinGAidra**: Check the checkbox next to `KinGAidra` to enable the extension.
5. **Restart Ghidra**: Restart Ghidra to apply the changes.


## Configuration

Before using KinGAidra, set up the `kingaidra_chat.py` script with your LLM API information:

1. **Open Script Manager**: In Ghidra, navigate to `Window -> Script Manager`.
2. **Edit the script**: Locate the `kingaidra_chat.py` script in the list and open it for editing.
3. **Set LLM API details**: Configure the following variables in the script with the correct values for your LLM API:
   - `URL`
   - `MODEL`
   - `API_KEY`

You can use the OpenAI API or similar APIs as the LLM API. For example, services like Groq or local LLMs are also supported. To change the language of the LLM response, modify the `POST_MSG` variable.

![Configuration Script](./img/conf_script.png)

You can also copy `kingaidra_chat.py` and configure each copy with different API endpoints, models, or prompts. This allows you to switch between multiple LLMs or customize responses for different use cases. You can add scripts to KinGAidra through the settings screen shown in the image below. Additionally, you can select which scripts to use for whitch functions.

![Configuration Models](./img/conf_models.png)
