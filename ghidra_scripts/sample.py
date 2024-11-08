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
    state = getState()

    diff = service.get_task(state.getEnvironmentVar("KEY"))
    params = {}
    for i in diff.get_params():
        params[i.get_old_name()] = i.get_old_name() + "_new"
    vars = {}
    for i in diff.get_vars():
        vars[i.get_old_name()] = i.get_old_name() + "_new"
    service.commit_task(state.getEnvironmentVar("KEY"), diff.get_name().get_old_name() + "_new", params, vars)


if __name__ == "__main__":
    main()
