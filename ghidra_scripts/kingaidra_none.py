#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 

# TODO: Fix

import kingaidra


def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(kingaidra.decom.KinGAidraDecomTaskService)

    diff = service.get_task(state.getEnvironmentVar("KEY"))
    service.commit_task(state.getEnvironmentVar("KEY"), diff.get_name().get_var_name(), {}, {}, {})


if __name__ == "__main__":
    main()
