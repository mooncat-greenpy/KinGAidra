#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 

# TODO: Fix

import kingaidra

import urllib2
import json

URL = "" # "https://api.openai.com/v1/chat/completions"
MODEL = "" # "gpt-4o-mini"
API_KEY = ""


def extract_json(data, pre, post):
    start = data.find(pre)
    end = data.rfind(post)
    if start < 0:
        start = 0
    else:
        start += len(pre)
    if end < 0:
        end = len(data)
    try:
        return json.loads(data[start:end])
    except ValueError:
        return None

def extract_json_bf(data, must_key):
    if "{" not in data or "}" not in data or must_key not in data:
        return None

    length = len(data)
    for pre in range(length):
        for post in reversed(range(length + 1)):
            if post <= pre:
                break
            if "{" not in data[pre:post] or "}" not in data[pre:post] or must_key not in data[pre:post]:
                break
            try:
                return json.loads(data[pre:post])
            except ValueError:
                pass
    return None

def request_chatgptlike(data):
    req = urllib2.Request(
        URL,
        json.dumps(data),
        {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + API_KEY,
            "User-Agent": "Python",
        }
    )
    return json.loads(urllib2.urlopen(req).read())

def guess_func_name_var_name(diff):
    data = {
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content":"""Please improve the readability of the following code by renaming the functions, parameters, and variables with more descriptive and meaningful names. The new names should better reflect the purpose of the functions and the role of each variable in the code.
```
%s
```
Output should absolutely be JSON only.
No additional explanation is needed.
The format is as follows.
```json
{
    "new_func_name": "new function name",
    "orig_func_name": "original function name",
    "parameters": [
        {
            "new_param_name": "new parameter name",
            "orig_param_name": "original parameter name"
        },
    ],
    "variables": [
        {
            "new_var_name": "new variable name",
            "orig_var_name": "original variable name"
        }
    ]
}
```""" % diff.get_src_code()
            }
        ]
    }

    response = request_chatgptlike(data)

    if "error" in response:
        return json.dumps(response), {}, {}
    data = response["choices"][0]["message"]["content"]

    json_data = extract_json(data, "```json\n", "```")
    if not json_data:
        json_data = extract_json_bf(data, "new_func_name")
        if not json_data:
            return data, {}, {}

    new_func = json_data["new_func_name"]
    params = {}
    for i in json_data.get("parameters", []):
        if "orig_param_name" in i and "new_param_name" in i:
            params[i["orig_param_name"]] = i["new_param_name"]
    vars = {}
    for i in json_data.get("variables", []):
        if "orig_var_name" in i and "new_var_name" in i:
            vars[i["orig_var_name"]] = i["new_var_name"]
    return new_func, params, vars

def guess_datatype(diff):
    data = {
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content":"""I have decompiled C code that contains various data type issues due to the decompilation process. I need your help to review the code and make the necessary corrections to the data types. Please go over the code and make these adjustments to improve the accuracy of the data types.
```cpp
%s
```
The changes should be output in JSON format.
```json
[
    {
        "new_datatype": "new datatype name",
        "orig_datatype": "original datatype name",
        "var_name": "variable name"
    },
    ...
]
```""" % diff.get_src_code()
            }
        ]
    }

    response = request_chatgptlike(data)

    if "error" in response:
        return {}
    data = response["choices"][0]["message"]["content"]

    json_data = extract_json(data, "```json\n", "```")
    if not json_data:
        json_data = extract_json_bf(data, "[")
        if not json_data:
            return {}

    datatypes = {}
    for i in json_data:
        if "var_name" in i and "new_datatype" in i:
            datatypes[i["var_name"]] = i["new_datatype"]
    return datatypes

def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(kingaidra.decom.KinGAidraDecomTaskService)
    state = getState()
    key = state.getEnvironmentVar("KEY")

    diff = service.get_task(key)

    try:
        new_func, params, vars = guess_func_name_var_name(diff)
    except Exception as e:
        service.commit_task_error(key, str(e))
        return
    if new_func is "":
        service.commit_task_error(key, new_func)
        return

    try:
        datatypes = guess_datatype(diff)
    except Exception:
        datatypes = {}
    if not datatypes:
        service.commit_task(key, new_func, params, vars, {})

    service.commit_task(key, new_func, params, vars, datatypes)

if __name__ == "__main__":
    main()
