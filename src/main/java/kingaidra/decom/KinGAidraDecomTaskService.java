package kingaidra.decom;

import java.util.Map;

import ghidra.framework.plugintool.ServiceInfo;
import kingaidra.KinGAidraPlugin;

//@formatter:off
@ServiceInfo (
	defaultProvider=KinGAidraPlugin.class,
	description="service"
)
//@formatter:on
public interface KinGAidraDecomTaskService {
    public void add_task(String key, DecomDiff diff);

    public void commit_task(String key, String func_name, Map<String, String> params,
            Map<String, String> vars);

    public DecomDiff get_task(String key);

    public DecomDiff pop_task(String key);
}
