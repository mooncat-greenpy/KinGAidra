#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


import kingaidra

import urllib2
import json

URL = "" # "https://api.openai.com/v1/chat/completions"
MODEL = "" # "gpt-4o-mini"
API_KEY = ""


def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(kingaidra.chat.KinGAidraChatTaskService)

    convo = service.get_task(state.getEnvironmentVar("KEY"))

    data = {
        "model": MODEL,
        "messages": [],
    }

    for i in range(convo.get_msgs_len()):
        data["messages"].append({
            "role": convo.get_role(i),
            "content": convo.get_msg(i),
        })

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

    service.commit_task(state.getEnvironmentVar("KEY"), data)

if __name__ == "__main__":
    main()
