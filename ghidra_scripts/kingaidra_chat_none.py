#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


import kingaidra


def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(kingaidra.ai.task.KinGAidraChatTaskService)

    convo = service.get_task(state.getEnvironmentVar("KEY"))
    service.commit_task(state.getEnvironmentVar("KEY"), convo.get_msg(convo.get_msgs_len() - 1))


if __name__ == "__main__":
    main()
