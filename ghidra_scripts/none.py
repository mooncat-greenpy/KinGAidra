#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


import kingaidra


def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(kingaidra.decom.KinGAidraDecomTaskService)

    diff = service.get_task(state.getEnvironmentVar("KEY"))
    service.commit_task(state.getEnvironmentVar("KEY"), diff.get_name().get_old_name(), {}, {})


if __name__ == "__main__":
    main()
