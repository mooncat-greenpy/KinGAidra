#@author mooncat-greenpy
#@category KinGAidra
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
        params[i.get_var_name()] = i.get_var_name() + "_new"
    vars = {}
    for i in diff.get_vars():
        vars[i.get_var_name()] = i.get_var_name() + "_new"
    service.commit_task(state.getEnvironmentVar("KEY"), diff.get_name().get_var_name() + "_new", params, vars, {})


if __name__ == "__main__":
    main()
