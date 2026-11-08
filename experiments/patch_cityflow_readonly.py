from pathlib import Path
import json

root=Path.cwd()
city=root/'upstream/CityFlow'
engine_h=city/'src/engine/engine.h'
source=engine_h.read_text()
if '#include <stdexcept>' not in source:
    source=source.replace('#include <fstream>','#include <fstream>\n#include <stdexcept>')
needle='        void setTrafficLightPhase(const std::string &id, int phaseIndex);'
method='''        int observeTrafficLightPhase(const std::string &id) const {
            Intersection *intersection = roadnet.getIntersectionById(id);
            if (intersection == nullptr) throw std::out_of_range("unknown intersection");
            return intersection->getTrafficLight().getCurrentPhaseIndex();
        }
'''
if 'observeTrafficLightPhase' not in source:
    assert source.count(needle)==1
    source=source.replace(needle,method+needle)
engine_h.write_text(source)

cpp=city/'src/cityflow.cpp'
source=cpp.read_text()
needle='        .def("set_tl_phase", &CityFlow::Engine::setTrafficLightPhase, "intersection_id"_a, "phase_id"_a)'
binding='        .def("observe_tl_phase", &CityFlow::Engine::observeTrafficLightPhase, "intersection_id"_a)\n'
if '"observe_tl_phase"' not in source:
    assert source.count(needle)==1
    source=source.replace(needle,binding+needle)
cpp.write_text(source)

out=root/'results'/'readonly_observation_patch.json'
out.write_text(json.dumps({
    'files':['src/engine/engine.h','src/cityflow.cpp'],
    'scope':'read-only signal phase observer; no traffic dynamics, routing or timing modified'
},indent=2))
print('Read-only CityFlow observer patch applied')
