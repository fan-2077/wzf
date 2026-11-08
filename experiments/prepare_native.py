"""AI-assisted feasibility setup; public dependencies only, no secret material.
This reproduces documented request-field repairs, not an alternative AIOS core.
"""
from pathlib import Path
import difflib, hashlib, json, os, shutil, subprocess, sys, sysconfig
import yaml, pybind11
ROOT=Path.cwd().resolve(); OUT=ROOT/'results'; OUT.mkdir(exist_ok=True)
UP=ROOT/'upstream'; UP.mkdir(exist_ok=True)
REPOS={'AIOS':('agiresearch/AIOS','292d98f78c835499df18cdb6de6325bba1895862'),
       'Cerebrum':('agiresearch/Cerebrum','ab7e434aa9cf3109ffd819779c06c08569218c71'),
       'CityFlow':('cityflow-project/CityFlow','81ee0f47659ca66177a71f81676691c58ee89184'),
       'CoLLMLight':('usail-hkust/CoLLMLight','ce204a90a238e206fa5673b6922aab3a6a9fc597')}
for name,(repo,sha) in REPOS.items():
    dest=UP/name; dest.mkdir(exist_ok=True)
    subprocess.run(['git','init',str(dest)],check=True,timeout=30)
    subprocess.run(['git','-C',str(dest),'remote','add','origin','https://github.com/'+repo+'.git'],check=True)
    subprocess.run(['git','-C',str(dest),'fetch','--depth','1','origin',sha],check=True,timeout=240)
    subprocess.run(['git','-C',str(dest),'checkout','--detach','FETCH_HEAD'],check=True,timeout=60)
    actual=subprocess.check_output(['git','-C',str(dest),'rev-parse','HEAD'],text=True).strip()
    assert actual==sha,(name,actual)
(OUT/'upstream_commits.json').write_text(json.dumps(REPOS,indent=2))
subprocess.run([sys.executable,'-m','pip','install','--no-deps','-e',str(UP/'Cerebrum')],check=True,timeout=180)
# Preserve pristine source, modify only the two confirmed request-forwarding sites.
compat=UP/'AIOS_compat'; shutil.copytree(UP/'AIOS',compat,ignore=shutil.ignore_patterns('.git'))
p=compat/'runtime/launch.py'; before=p.read_text()
old='''        elif request.query_type == "tool":
            query = ToolQuery(
                params=request.query_data.params,
                operation_type=request.query_data.operation_type
            )'''
new='''        elif request.query_type == "tool":
            query = ToolQuery(
                tool_calls=request.query_data.tool_calls
            )'''
old2='''                message_return_type=request.query_data.message_return_type,
            )'''
new2='''                message_return_type=request.query_data.message_return_type,
                temperature=request.query_data.temperature,
                max_new_tokens=request.query_data.max_new_tokens,
                response_format=request.query_data.response_format,
            )'''
assert before.count(old)==1 and before.count(old2)==1
p.write_text(before.replace(old,new).replace(old2,new2))
(OUT/'aios_request_compatibility.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True),p.read_text().splitlines(True),'a/runtime/launch.py','b/runtime/launch.py')))
config={'api_keys':{'openai':'','gemini':'','groq':'','anthropic':'','huggingface':{'auth_token':'','cache_dir':''}},
 'llms':{'models':[{'name':'qwen3-8b','backend':'vllm','hostname':'http://127.0.0.1:18080/v1','api_key':'local-only'}],'router':{'strategy':'sequential'},'log_mode':'console','use_context_manager':False},
 'memory':{'log_mode':'console','provider':'in-house','auto_extract':False,'auto_inject':False},
 'storage':{'root_dir':str(ROOT/'isolated/storage'),'use_vector_db':False,'vector_db_backend':'chroma'},
 'tool':{'mcp_server_script_path':str(ROOT/'unused-desktop-mcp-disabled.py')},
 'scheduler':{'log_mode':'console'},'agent_factory':{'log_mode':'console','max_workers':4},
 'server':{'host':'127.0.0.1','port':18082}}
(compat/'aios/config/config.yaml').write_text(yaml.safe_dump(config,sort_keys=False)); (OUT/'aios_config.yaml').write_text(yaml.safe_dump(config,sort_keys=False))
# Native preloaded tool manager stays intact; only register our own local tool.
os.environ['XDG_CACHE_HOME']=str(ROOT/'isolated/cache')
from cerebrum.manager.package import ToolPackage
from cerebrum.interface import AutoTool
source='''import json,urllib.request
class Tool:
    def run(self,params):
        if not isinstance(params,dict):raise TypeError("object required")
        req=urllib.request.Request("http://127.0.0.1:18083/tool",data=json.dumps(params).encode(),headers={"Content-Type":"application/json"})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req,timeout=180) as r:return json.dumps(json.load(r))
'''
path=AutoTool.TOOL_MANAGER._get_cache_path('competition_validation','traffic_regression','0.0.1')
assert path.is_relative_to(ROOT/'isolated/cache')
pkg=ToolPackage(path);pkg.metadata={'author':'competition_validation','name':'traffic_regression','version':'0.0.1','license':'AI-assisted local feasibility fixture','entry':'tool.py','module':'Tool'}
pkg.files={'tool.py':source.encode()};pkg.save();assert callable(AutoTool.from_preloaded('competition_validation/traffic_regression').run)
(OUT/'registered_tool.py').write_text(source)
# Native traffic simulator, with the same read-only diagnostic previously checked.
city=UP/'CityFlow'
subprocess.run(['git','-C',str(city),'submodule','update','--init','--depth','1','extern/rapidjson'],check=True,timeout=180)
mods={'src/engine/engine.h':[('#include <fstream>','#include <fstream>\n#include <stdexcept>'),('        // archive','''        int observeTrafficLightPhase(const std::string &id) const {
            Intersection *intersection = roadnet.getIntersectionById(id);
            if (intersection == nullptr) throw std::out_of_range("unknown intersection");
            return intersection->getTrafficLight().getCurrentPhaseIndex();
        }
        // archive''')],
'src/cityflow.cpp':[('        .def("set_tl_phase",','        .def("observe_tl_phase", &CityFlow::Engine::observeTrafficLightPhase, "intersection_id"_a)\n        .def("set_tl_phase",')]}
patch=[]
for rel,reps in mods.items():
    f=city/rel;a=f.read_text();b=a
    for x,y in reps:assert b.count(x)==1;(None);b=b.replace(x,y)
    f.write_text(b);patch.extend(difflib.unified_diff(a.splitlines(True),b.splitlines(True),'a/'+rel,'b/'+rel))
(OUT/'cityflow_readonly.patch').write_text(''.join(patch))
build=ROOT/'native_build';build.mkdir(exist_ok=True)
cpp=['utility/utility.cpp','utility/barrier.cpp','engine/archive.cpp','engine/engine.cpp','flow/flow.cpp','roadnet/roadnet.cpp','roadnet/trafficlight.cpp','vehicle/router.cpp','vehicle/vehicle.cpp','vehicle/lanechange.cpp','cityflow.cpp']
cmd=['g++','-O2','-shared','-std=c++11','-fPIC','-pthread','-DRAPIDJSON_HAS_STDSTRING=1','-I'+str(city/'src'),'-I'+str(city/'extern/rapidjson/include'),'-I'+str(city/'extern/milo'),'-I'+pybind11.get_include(),'-I'+sysconfig.get_paths()['include'],*[str(city/'src'/x) for x in cpp],'-o',str(build/('cityflow'+sysconfig.get_config_var('EXT_SUFFIX')))]
with (OUT/'cityflow_build.log').open('w') as log:subprocess.run(cmd,check=True,stdout=log,stderr=subprocess.STDOUT,timeout=240)
for file,expected in [('roadnet_4_4.json','11e2fe89f632e43e81f56ea87a308d544b66f9c5af8a410e16149668d6d376c1'),('anon_4_4_hangzhou_real.json','595a6140e6649efe5be1b274eb8b03e8c4029e517c9ac2ad53c9ea556a414213')]:
    q=UP/'CoLLMLight/data/Hangzhou/4_4'/file
    assert hashlib.sha256(q.read_bytes()).hexdigest()==expected,file
(OUT/'native_setup.json').write_text(json.dumps({'native_aios_source':REPOS['AIOS'][1],'native_sdk_source':REPOS['Cerebrum'][1],'model_backend_client':'AIOS vllm/OpenAI-compatible branch; actual server is llama.cpp CPU','aios_managers_replaced':False,'unused_desktop_mcp':'explicitly not launched; no MCP capability claim','cityflow_readonly_instrumentation':True,'research_scope':'known solved traffic regression, not multi-agent superiority'},indent=2))
print('Native dependencies prepared',flush=True)
