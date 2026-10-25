"""Q CaseRequest adapters: existing fixtures and separately gated N candidates."""
from dataclasses import asdict
import ast
import hashlib
import json

import lcb_isolation_release_v2 as release
import lcb_isolation_batch_v2 as batch
from lcb_isolation_control_v2 import _execution_slot
from lcb_pilot_quality_v1 import CaseRequest, CaseResult

FIXTURES = ('controls', 'cpu', 'reuse')


def request_digest(request):
    release.check(type(request) is CaseRequest, 'Exact Q CaseRequest required')
    fields = asdict(request)
    release.check(request.role in ('weak4', 'audit') and type(request.candidate_id) is int
                  and request.candidate_id >= 0 and type(request.seed) is int, 'Q request identity/role')
    release.check(hashlib.sha256(request.code.encode()).hexdigest() == request.code_sha256, 'Q code digest differs')
    # Q uses canonical JSON without the LF used by I durable objects.
    raw = json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def candidate_view(request):
    """No expected answer, audit state, control keys, owner/R, or host paths."""
    request_digest(request)
    return {'code': request.code, 'stdin': request.stdin, 'test_type': request.test_type,
            'entry_point': request.entry_point}


def fixture_request(authority, worker_id, case_id):
    release.check(worker_id in batch.WORKERS and case_id in FIXTURES, 'Fixed worker/fixture ID only')
    index = batch.WORKERS.index(worker_id) + 1
    release.require(authority, phase='runtime', role='W'+str(index))
    slot = batch.role_for(authority.manifest, 'E'+str(index))
    binding = release.object_sha({'batch': authority.manifest['batch_id'], 'worker': worker_id,
                                 'fixture': case_id, 'source': authority.snapshot['registration_sha256'],
                                 'execution_nonce': slot['nonce']})
    empty = hashlib.sha256(b'').hexdigest()
    return CaseRequest(binding, 'trusted-I-fixture', 'trusted/'+case_id, 0, 0,
                       binding, empty, binding, 'weak4', case_id, '', '', 'stdin', None)


class FixedFixtureAdapter:
    def __init__(self, authority, native_channel):
        _execution_slot(authority, native_channel.slot)
        release.check(native_channel.authority is authority, 'Native channel has a foreign authority')
        self.authority, self.native = authority, native_channel

    def _request(self, request):
        _execution_slot(self.authority, self.native.slot)
        request_digest(request)
        release.check(request == fixture_request(self.authority, self.native.slot['worker_id'], request.test_id),
                      'Only the exact I-v2 fixed Q fixture request is accepted')
        return request_digest(request)

    def prepare(self, request, deadline_ns):
        rid = self._request(request)
        release.check(request.stratum_id == 'trusted-I-fixture' and request.code == request.stdin == ''
                      and request.test_id in FIXTURES and request.task_id == 'trusted/'+request.test_id,
                      'Generated code cannot reach fixed native protocol')
        return self.native.start_case(request.test_id, rid, deadline_ns)

    def finish(self, request, deadline_ns):
        self._request(request)
        receipt = self.native.run_case(request.test_id, deadline_ns)
        release.check(receipt['request_sha256'] == request_digest(request), 'Request/result binding mismatch')
        # Native protocol fixtures yield resource/isolation receipts, not audit
        # correctness labels or stdout from an evaluated generated candidate.
        return receipt


class CandidateBackend:
    def evaluate(self, request):
        request_digest(request)
        # No flag, callback, fixture name or forged JSON can activate candidates.
        # A separately reviewed backend publication must supply N/I/F + Q and
        # independent owner admission. This implementation exposes no exec API.
        raise PermissionError('Candidate backend unpublished: N/I/F, Q release and independent owner admission required')


MAX_CODE_BYTES = 65536
MAX_TEST_INPUT_BYTES = 96*1024**2  # a property of the frozen tests; the largest private stdin seen so far is 2.7 MB


def prefilter(request):
    """Two rules: the code parses, and the code is not absurdly long. System calls are the C sandbox's job."""
    request_digest(request)
    if len(request.code.encode())>MAX_CODE_BYTES or len(request.stdin.encode())>MAX_TEST_INPUT_BYTES:
        return 'length'
    try:ast.parse(request.code)
    except (SyntaxError,ValueError,RecursionError,MemoryError):return 'syntax'
    return None


class CandidateAdapter:
    """Q request -> C-backed execution. The transport never receives answers."""
    def __init__(self,authority,transport):
        release.require_candidate(authority)
        self.authority,self.transport=authority,transport

    def evaluate(self,request):
        release.require_candidate(self.authority)
        digest=request_digest(request);reason=prefilter(request)
        if reason:return {'request_sha256':digest,'status':'candidate_rejected_prefilter',
                          'stdout':None,'error':reason,'cost_sample_eligible':False}
        result=self.transport(candidate_view(request))
        release.check(type(result) is dict and result.get('status') in ('ok','runtime_error','time_limit'),
                      'Incomplete candidate execution result')
        release.check(result['status']!='ok' or type(result.get('stdout')) is str,
                      'Successful candidate output missing')
        return {'request_sha256':digest,'status':result['status'],'stdout':result.get('stdout'),
                'error':result.get('error'),'execution':{k:result[k] for k in
                    ('returncode','wall_ns','stdout_hex','stderr_hex','output_truncated','stdout_total_bytes','stdout_sha256') if k in result}}
