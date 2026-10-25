"""CaseRequest boundary and real fixed-fixture dispatch; candidates stay closed."""
from dataclasses import asdict
import hashlib
import json

import lcb_isolation_release_v1 as release
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
    release.require(authority); release.check(case_id in FIXTURES, 'Fixed fixture ID only')
    binding = release.object_sha({'batch': authority.manifest['batch_id'], 'worker': worker_id,
                                 'fixture': case_id, 'source': authority.snapshot['registration_sha256']})
    empty = hashlib.sha256(b'').hexdigest()
    return CaseRequest(binding, 'trusted-I-fixture', 'trusted/'+case_id, 0, 0,
                       binding, empty, binding, 'weak4', case_id, '', '', 'stdin', None)


class FixedFixtureAdapter:
    def __init__(self, authority, native_channel):
        release.require(authority)
        self.authority, self.native = authority, native_channel

    def prepare(self, request, deadline_ns):
        release.require(self.authority)
        rid = request_digest(request)
        release.check(request.stratum_id == 'trusted-I-fixture' and request.code == request.stdin == ''
                      and request.test_id in FIXTURES and request.task_id == 'trusted/'+request.test_id,
                      'Generated code cannot reach fixed native protocol')
        return self.native.start_case(request.test_id, rid, deadline_ns)

    def finish(self, request, deadline_ns):
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
