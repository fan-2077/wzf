"""Register an explicit SDK source path inside this ephemeral Python environment.
Some editable-wheel installs report success without exposing cerebrum. This
adds only the pinned checkout path; no SDK source or manager is replaced.
"""
from pathlib import Path
import json, runpy, sysconfig
root=Path.cwd().resolve();out=root/'results';out.mkdir(exist_ok=True)
source=root/'upstream/Cerebrum'
pth=Path(sysconfig.get_paths()['purelib'])/'competition_cerebrum_source.pth'
pth.write_text(str(source)+'\n')
(out/'sdk_import_path.json').write_text(json.dumps({'pth_file':str(pth),'source_root':str(source),'source_commit':'ab7e434aa9cf3109ffd819779c06c08569218c71','scope':'ephemeral GitHub runner only; no user machine modified'},indent=2))
runpy.run_path(str(root/'experiments/prepare_native.py'),run_name='__main__')
