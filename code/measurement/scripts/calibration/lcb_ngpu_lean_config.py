"""Generation configuration of one panel cell for a lean GPU attempt (pilot subset: the 16 frozen tasks).

Shared fields (seed, system prompt, workload manifest, engine metrics schema, vLLM version, sequence limit, ...) come
from the Coder pilot configuration that already went through this path. What differs by stratum is set the way the
admission chain sets it: the native sampling/template settings, the frozen cap/context/deadline, the GPU memory
fraction and the text-only flag (only the multimodal Qwen3.8/Qwen3.5 architectures). The result is the same file
every validator of the attempt (prepare and runtime) checks again.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_isolation_batch_v2 as batch
import lcb_isolation_release_v2 as release
import lcb_native_generation as native
import lcb_seeds as seeds
import lcb_timeout_revision as timeout_revision

TEMPLATE = 'data/calibration/ngpu-pilot-draft-2026-10-22/generation-config.json'
CAPS = 'experiments/calibration/admission-cap-path-v3.json'
FROZEN = 'data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json'
MULTIMODAL_ARCHITECTURES = ('Qwen/Qwen3.8', 'Qwen/Qwen3.5')


def cap_key(stratum):
    """The off-mode control inherits the on-mode freeze, as lcb_ngpu_v3.validate_inputs expects."""
    return 'q38_thinking_freeze' if stratum == 'q38-nonthinking' else stratum.replace('-', '_') + '_freeze'


def roster(subset):
    release.check(subset in ('pilot', 'main'), 'Subset must be pilot or main')
    frozen = release.strict(release.read(release.ROOT / FROZEN))
    return frozen['pilot_task_ids'] if subset == 'pilot' else frozen['main_task_ids']


def stem(cell_id, subset, service=False, extended_timeout=False):
    return (cell_id.replace('|', '_') + ('' if subset == 'pilot' else '.' + subset) + ('.service' if service else '')
            + ('.t%d' % timeout_revision.EXTENDED_S if extended_timeout else ''))


def build(cell_id, subset='pilot', service=False, extended_timeout=False):
    """service=True asks for the service path: the weak4 selector runs online (first passing candidate is delivered), and
    only the delivered candidate is audited afterwards, outside the service window. The default is the evaluation pipeline.
    extended_timeout=True applies the owner-approved revision of lcb_timeout_revision (7,200 s per pooled call instead of the
    frozen 3,600 s, with its marker) and is refused for any cell outside its scope."""
    cell = batch.panel_cell(cell_id)
    name = cell['stratum_id']
    cap = release.strict(release.read(release.ROOT / CAPS))[cap_key(name)]
    effort = None if name == 'q38-nonthinking' else cap['effort']
    cfg = release.strict(release.read(release.ROOT / TEMPLATE))
    cfg.update(native.settings(name, effort))
    cfg.update(max_tokens=cap['max_tokens'], max_model_len=cap['max_model_len'],
               generation_timeout_s=cap['generation_timeout_s'],
               gpu_memory_utilization=0.85 if name == 'coder-nonthinking' else 0.90,
               inference_text_only=cell['model_id'].startswith(MULTIMODAL_ARCHITECTURES),
               k=cell['k'], replicate_id=cell['replicate_id'], pool_id=cell['pool_id'],
               concurrency=cell['concurrency'], arrival_offsets_s=[0] * len(roster(subset)), subset=subset)
    if name == 'q38-nonthinking':
        cfg['paired_on_effort'] = cap['effort']
    else:
        cfg.pop('paired_on_effort', None)
    if service:
        cfg['selection_mode'] = 'online'
        cfg['weak_size'] = 4  # the frozen weak selector
    if extended_timeout:
        release.check(timeout_revision.in_scope(cell), 'The 7200 s timeout revision covers only q38-thinking k=8 pooled cells: ' + cell_id)
        release.check(not service, 'The 7200 s timeout revision is approved for evaluation-pipeline cells, not for the service path: ' + cell_id)
        cfg['generation_timeout_s'] = timeout_revision.EXTENDED_S
        cfg['timeout_revision'] = timeout_revision.marker()
    native.validate(cfg)
    seeds.validate_policy(cfg)
    return cfg


def write(cell_id, directory, subset='pilot', service=False, extended_timeout=False):
    """Create <directory>/<cell>[.main][.service][.t7200].generation-config.json (never overwrites); return its path."""
    path = Path(directory) / (stem(cell_id, subset, service, extended_timeout) + '.generation-config.json')
    raw = release.encoded(build(cell_id, subset, service, extended_timeout))  # a refusal leaves no directory behind
    Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():  # a re-run after a failed request build; a different existing file is never replaced
        release.check(path.read_bytes() == raw, 'Existing generated configuration differs: ' + str(path))
        return path
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return path


def derive_workload(base, cell_id):
    """Jobs of one panel cell over the base workload's tasks: k candidates per task with the frozen hash seeds.

    The tasks (prompts, private tests, folds) are the base file's, untouched; only the candidate list depends on
    k and the replicate. A job keeps whatever other fields the base job has."""
    cell = batch.panel_cell(cell_id)
    release.check(type(base) is dict and set(base) == {'tasks', 'jobs'} and base['tasks'] and base['jobs'], 'Workload inputs')
    seed = release.strict(release.read(release.ROOT / TEMPLATE))['seed']
    first = {}
    for job in base['jobs']:
        first.setdefault(job['task_id'], job)
    jobs = []
    for task in base['tasks']:
        proto = first[task['task_id']]
        for index in range(cell['k']):
            jobs.append({**proto, 'candidate_id': index,
                         'seed': seeds.candidate_seed(seed, cell['replicate_id'], task['task_id'], index)})
    return {'tasks': base['tasks'], 'jobs': jobs}


def workload_for(cell_id, base_path, directory, subset='pilot'):
    """Path of the workload for this cell: the base file itself when it already is the cell's (k=1, replicate 0),
    otherwise a derived <directory>/<cell>[.main].workload.json (never replaced by different bytes)."""
    cell = batch.panel_cell(cell_id)
    base = release.strict(Path(base_path).read_bytes())
    derived = derive_workload(base, cell_id)
    if derived['jobs'] == base['jobs']:
        return Path(base_path)
    path = Path(directory) / (stem(cell_id, subset) + '.workload.json')
    Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = release.encoded(derived)
    if path.exists():
        release.check(path.read_bytes() == raw, 'Existing derived workload differs: ' + str(path))
        return path
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return path
