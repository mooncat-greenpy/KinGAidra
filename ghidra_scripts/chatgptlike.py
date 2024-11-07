#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


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

def extract_json_bf(data):
    if "{" not in data or "}" not in data or "new_func_name" not in data:
        return None

    length = len(data)
    for pre in range(length):
        for post in reversed(range(length + 1)):
            if post <= pre:
                break
            if "{" not in data[pre:post] or "}" not in data[pre:post] or "new_func_name" not in data[pre:post]:
                break
            try:
                return json.loads(data[pre:post])
            except ValueError:
                pass
    return None


def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(kingaidra.decom.KinGAidraDecomTaskService)
    state = getState()

    diff = service.get_task(state.getEnvironmentVar("KEY"))

    data = {
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content":"""Please modify the function and parameter, variable names to make the following code more readable.
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

    req = urllib2.Request(
        URL,
        json.dumps(data),
        {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + API_KEY,
            "User-Agent": "Python",
        }
    )
    response = json.loads(urllib2.urlopen(req).read())

    if "error" in response:
        return
    data = response["choices"][0]["message"]["content"]

    json_data = extract_json(data, "```json\n", "```")
    if not json_data:
        json_data = extract_json_bf(data)
        if not json_data:
            return

    params = {}
    for i in json_data.get("parameters", []):
        if "orig_param_name" in i and "new_param_name" in i:
            params[i["orig_param_name"]] = i["new_param_name"]
    vars = {}
    for i in json_data.get("variables", []):
        if "orig_var_name" in i and "new_var_name" in i:
            vars[i["orig_var_name"]] = i["new_var_name"]
    service.commit_task(state.getEnvironmentVar("KEY"), json_data["new_func_name"], params, vars)

if __name__ == "__main__":
    main()
