"""One delivery rule shared by generation, selection, evaluation and reports."""
POLICY = 'completed-candidate-only-v1'


def eligible(row, *, strict=False):
    reason = row.get('finish_reason')
    if row.get('code') is not None and not isinstance(row['code'],str):raise ValueError('Invalid extracted code field')
    if strict and type(row.get('truncated')) is not bool:raise ValueError('Explicit truncated state required')
    if reason not in ('stop', 'length'):
        if strict: raise ValueError('Missing or unsupported candidate completion state')
        # Read-only compatibility for old reports without completion metadata.
        return bool(row.get('code')) and row.get('truncated') is not True
    flag = row.get('truncated', reason == 'length')
    if type(flag) is not bool or flag != (reason == 'length'):
        raise ValueError('Conflicting candidate completion fields')
    result = reason == 'stop' and bool(row.get('code'))
    if row.get('delivery_policy') is not None:
        if row['delivery_policy'] != POLICY or row.get('delivery_eligible') is not result:
            raise ValueError('Candidate delivery policy does not match completion state')
    return result


def stamp(row):
    result = eligible(row, strict=True)
    row.update(delivery_policy=POLICY, delivery_eligible=result,
               no_answer_reason=None if result else 'length_truncated' if row['finish_reason']=='length' else 'no_executable_final')
    return row
