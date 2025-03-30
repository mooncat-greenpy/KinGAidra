#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


URL = "" # "https://api.openai.com/v1/chat/completions"
MODEL = "" # "gpt-4o-mini"
API_KEY = ""
POST_MSG = "" # "Please respond in XXXX."


# Only modify the code above this comment.
# Do not modify the code below this comment.
# The same applies when copying and using this script.


# <KinGAidra Marker For Update: v1.1.0>


import kingaidra

import urllib2
import json


def main():
    data = {
        "model": MODEL,
        "messages": [],
    }

    type = state.getEnvironmentVar("TYPE")
    data["messages"] = json.loads(state.getEnvironmentVar("MESSAGES"))

    if type == kingaidra.ai.task.TaskType.CHAT.toString() or type == kingaidra.ai.task.TaskType.ADD_COMMENTS.toString():
        data["messages"][-1]["content"] += POST_MSG

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

    data = response["choices"][0]["message"]["content"]

    state.addEnvironmentVar("RESPONSE", data)

if __name__ == "__main__":
    main()
