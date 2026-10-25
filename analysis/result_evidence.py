"""Read-only checks of anonymous paper inputs and derived count receipts.

The receipts commit to private source bytes without publishing generated text,
host identities or source archive paths. Checking the public counts is distinct
from repeating extraction from those private originals.
"""
from collections import Counter
from fractions import Fraction
from pathlib import Path
import csv
import hashlib
import json
import re
import sys


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
EVIDENCE = ROOT / 'evidence'
IDENTITIES = re.compile(r'/(?:scratch|Users|home)/|\bu\d{2}-[a-z0-9-]+|GPU-[0-9a-f-]{12,}', re.I)


def read(name):
    return json.loads((EVIDENCE / name).read_text())


def require(value, message):
    if not value:
        raise ValueError(message)


def restricted_h1():
    receipt = read('restricted-menu-counts.json')
    rows = {r['cell_alias']: r for r in receipt['rows']}
    require(set(rows) == {'serial_k1', 'serial_k8', 'pooled_k1', 'pooled_k8'}, 'Restricted menu slots')
    require(all(r['tasks'] == 106 for r in rows.values()), 'Restricted menu denominator')
    require(all(type(r['gpu_step_occupancy_ns']) is int for r in rows.values()), 'Integer original windows')
    v = {k: r['gpu_step_occupancy_ns'] for k, r in rows.items()}
    h1 = Fraction(v['serial_k8'] - v['serial_k1'] - v['pooled_k8'] + v['pooled_k1'], 106 * 10**9)
    require(h1 == Fraction(-35, 106), 'Restricted menu must use original precision')
    require(h1 == Fraction(receipt['h1_numerator'], receipt['h1_denominator']), 'Restricted receipt arithmetic')
    require(format(float(h1), '.1f') == receipt['rounded_one_decimal'] == '-0.3', 'Restricted menu rounding')
    return h1


def menu_windows():
    """Exact anonymous windows, cross-checked against the rounded public export."""
    rows = read('menu-window-counts.json')['rows']
    with (EVIDENCE / 'results/lean-main-resources-4-2026-10-23.tsv').open() as handle:
        exported = {}
        for row in csv.DictReader(handle, delimiter='\t'):
            stratum, _, config, k, rep = row['cell_id'].split('|')
            if (stratum == 'q38-thinking' and row['status'] == 'complete'
                    and row['hardware'] == 'NVIDIA H100 80GB HBM3'):
                exported[(config, int(k[1:]), rep)] = row
    require(len(rows) == len(exported) == 12, 'Menu window coverage')
    keys = [(r['configuration'], r['k'], r['replicate']) for r in rows]
    require(len(set(keys)) == len(keys) and set(keys) == set(exported), 'Menu window identities')
    for row, key in zip(rows, keys):
        require(row['tasks'] == 106 and type(row['gpu_step_occupancy_ns']) is int
                and row['gpu_step_occupancy_ns'] > 0, 'Menu integer window')
        require(row['gpu_model'] == 'NVIDIA H100 80GB HBM3', 'Menu hardware')
        seconds = row['gpu_step_occupancy_ns'] / 10**9
        require(float(format(seconds, '.4g')) == float(exported[key]['gpu_step_occupancy_s']),
                'Menu exact window differs from rounded export')
        require(type(row['extended_bound']) is bool
                and row['extended_bound'] == (exported[key]['timeout_revised'] == 'True'),
                'Menu extended-bound identity')
        for field in ('source_archive_sha256', 'source_member_sha256', 'source_cell_sha256'):
            require(re.fullmatch(r'[0-9a-f]{64}', row[field]) is not None, 'Menu source commitment')
    original = {r['cell_alias']: r['gpu_step_occupancy_ns'] for r in read('restricted-menu-counts.json')['rows']}
    mapping = {'serial_k1': ('serial', 1), 'serial_k8': ('serial', 8),
               'pooled_k1': ('batch64', 1), 'pooled_k8': ('batch16', 8)}
    for name, (config, k) in mapping.items():
        current = next(r for r in rows if (r['configuration'], r['k'], r['replicate']) == (config, k, 'r1'))
        require(current['gpu_step_occupancy_ns'] == original[name], 'Menu contradicts original restricted receipt')
    return rows


def menu_h1(include_extended=True, replicate=None):
    """Window contrast for the time-minimizing pooled menu, in exact arithmetic.

    The table generator separately checks that these choices minimize the
    declared resource cost, rather than presuming GPU time and cost coincide.
    """
    rows = [r for r in menu_windows() if (replicate is None or r['replicate'] == replicate)
            and (include_extended or not r['extended_bound'])]
    def mean(config, k):
        values = [Fraction(r['gpu_step_occupancy_ns'], r['tasks'] * 10**9)
                  for r in rows if (r['configuration'], r['k']) == (config, k)]
        return sum(values) / len(values) if values else None
    selected = {k: min((mean(config, k), config) for config in ('serial', 'batch16', 'batch64')
                       if mean(config, k) is not None) for k in (1, 8)}
    return {'h1': mean('serial', 8) - mean('serial', 1) - selected[8][0] + selected[1][0],
            'selected': {k: value[1] for k, value in selected.items()}}


def pilot_counts():
    receipt = read('pilot-format-counts.json')
    rows = receipt['rows']
    require(len(rows) == receipt['source_lines'] == 128, 'Pilot row count')
    require({r['source_line'] for r in rows} == set(range(1, 129)), 'Pilot line uniqueness')
    counts = Counter()
    for row in rows:
        require(re.fullmatch(r'[0-9a-f]{64}', row['source_line_sha256']) is not None, 'Pilot line commitment')
        if row['truncated']:
            expected = 'capped'
            require(not row['delivery_eligible'], 'Capped output never delivered')
        elif row['delivery_eligible']:
            expected = 'deliverable'
        elif row['extraction'] == 'unclosed_fence':
            expected = 'unclosed_fence'
        elif row['closed_fence_count'] == row['python_fence_count'] == 2:
            expected = 'two_python_blocks'
        elif 3 <= row['closed_fence_count'] <= 5:
            expected = 'three_to_five_blocks'
        elif row['closed_fence_count'] == row['unlabelled_fence_count'] == 1:
            expected = 'one_unlabelled_block'
        else:
            raise ValueError('Unclassified pilot row')
        require(row['category'] == expected, 'Pilot category differs from row evidence')
        counts[expected] += 1
    require(dict(counts) == receipt['summary'], 'Pilot aggregate differs from rows')
    require(counts == Counter(deliverable=101, capped=5, unclosed_fence=5,
                              two_python_blocks=11, three_to_five_blocks=5,
                              one_unlabelled_block=1), 'Pilot classification totals')
    return dict(counts)


def verify():
    manifest = read('results-manifest.json')
    expected = {row['file'] for row in manifest['files'] + manifest['derived_receipts']}
    allowed = expected | {'results-manifest.json', 'SHA256SUMS'}
    actual = {str(p.relative_to(EVIDENCE)) for p in EVIDENCE.rglob('*') if p.is_file()}
    require(actual <= allowed, 'Unexpected file in anonymous evidence bundle')
    for row in manifest['files'] + manifest['derived_receipts']:
        path = (EVIDENCE / row['file']).resolve()
        require(EVIDENCE.resolve() in path.parents, 'Evidence path escapes its directory')
        raw = path.read_bytes()
        require(len(raw) == row['bytes'], 'Evidence byte count: ' + row['file'])
        require(hashlib.sha256(raw).hexdigest() == row['sha256'], 'Evidence digest: ' + row['file'])
        require(IDENTITIES.search(raw.decode()) is None, 'Private identity in public evidence')
        if row['file'].endswith('.tsv'):
            require(len(raw.splitlines()) - 1 == row['rows'], 'Evidence row count')
    counts = pilot_counts()
    h1 = restricted_h1()
    menu = menu_h1(include_extended=False)
    require(menu['h1'] == Fraction(-255, 106), 'Restricted composite exact contrast')
    registered = read('registered-abstract.json')
    require(hashlib.sha256(registered['abstract_block'].encode()).hexdigest() == registered['sha256'], 'Registered abstract digest')
    approved = read('current-abstract.json')
    require(approved['registered_abstract_sha256'] == registered['sha256'], 'Registered abstract record binding')
    require(hashlib.sha256(approved['abstract_block'].encode()).hexdigest() == approved['sha256'], 'Current abstract digest')
    timeline = read('protocol-timeline.json')
    require([r['date'] for r in timeline['events']] == ['2026-10-09', '2026-10-10', '2026-10-14', '2026-10-21', '2026-10-23', '2026-10-24', '2026-10-25'], 'Protocol/amendment timeline')
    with (EVIDENCE / 'results/lean-main-theory-5-2026-10-24.tsv').open() as handle:
        rows = list(csv.DictReader(handle, delimiter='\t'))
    pre = [r for r in rows if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0']
    require(len(pre) == 1400 and all(r['adm_nonempty'] == 'no' for r in pre), 'Headline admission count')
    # Independently recompute band emptiness instead of only checking its label.
    require(all(max(float(r['C0L']) / float(r['B0L']), float(r['C1H']) / float(r['B1H']))
                >= min(float(r['C0H']) / float(r['B0H']), 1) for r in pre), 'Headline admission arithmetic')
    import bootstrap_tables
    bootstrap = bootstrap_tables.validate(EVIDENCE)
    import service_result_tables
    followup = service_result_tables.validate(EVIDENCE)
    import retail_result_tables
    retail = retail_result_tables.verify(EVIDENCE)
    return {'status': 'anonymous_paper_evidence_verified', 'input_tables': len(manifest['files']),
            'pilot_counts': counts, 'restricted_menu_h1': str(h1),
            'restricted_menu_display': format(float(h1), '.1f'),
            'restricted_composite_h1': str(menu['h1']),
            'headline_admission_rows': len(pre), 'headline_nonempty': 0,
            'registered_abstract_preserved': True,
            'current_abstract_matches_registered': approved['abstract_block'] == registered['abstract_block'],
            'current_abstract_approved': True, 'paired_prompt_bootstrap': bootstrap,
            'service_followup': followup, 'retail_pricing': retail, 'experiments_run': False}


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
