"""Build an isolated ASL candidate from a supplied saved definition; no AWS calls."""

from copy import deepcopy
import argparse
import json
from pathlib import Path


def patch_definition(original, functions):
    value = deepcopy(original)
    states = value['States']
    parallel = states.pop('L0L1Parallel')
    for branch, role in zip(parallel['Branches'], ('l0', 'l1')):
        branch['States'][role.upper() + '_Invoke']['Parameters']['FunctionName'] = functions[role]

    l23_states = {name: states.pop(name) for name in
                  ('L23Task', 'L23_Shape', 'L23_Malformed', 'L23_Unavailable')}
    l23_task = l23_states.pop('L23Task')
    l23_task['Parameters']['FunctionName'] = functions['l23']
    l23_states['L23_Invoke'] = l23_task
    l23_states['L23_Shape']['Choices'][0]['Next'] = 'L23_Ok'
    for name in ('L23_Malformed', 'L23_Unavailable'):
        l23_states[name]['Next'] = 'L23_Ok'
    l23_states['L23_Ok'] = {'Type': 'Pass', 'Parameters': {'l23.$': '$.observe.l23'}, 'End': True}
    parallel['Branches'].append({'StartAt': 'L23_Invoke', 'States': l23_states})
    parallel['ResultSelector']['l23.$'] = '$[2].l23'
    parallel['Comment'] = ('L0, L1, and L23 start in parallel; L23 runs L2 and L3 concurrently. '
                           'L23 must preflight every target before network access.')
    states['L0L1L23Parallel'] = parallel
    states['AllocAttempt']['Next'] = 'L0L1L23Parallel'
    alloc = states['AllocAttempt']['Parameters']
    alloc['UpdateExpression'] = alloc['UpdateExpression'].replace(
        '#st = if_not_exists(#st, :pending)', '#st = :pending')
    alloc['UpdateExpression'] = alloc['UpdateExpression'].replace(
        ' ADD #att :one',
        ' REMOVE final_key, judgment_key, final_verdict, reach_state, '
        'l0_key, l1_key, l2_key, l3_key, url_activity_key, '
        'url_activity_sha256, url_activity_state, url_activity_valid_until, '
        'judgment_status, block_reason, #er ADD #att :one')
    alloc['ExpressionAttributeNames']['#er'] = 'error'
    parallel['Next'] = 'ParallelJoinShape'
    states['ParallelJoinShape'] = {'Type': 'Choice', 'Choices': [{
        'And': [{'Variable': path, 'IsPresent': True} for path in (
            '$.result.l0.s3_key', '$.result.l1.s3_key',
            '$.result.l23.l2.s3_key', '$.result.l23.l3.s3_key',
            '$.result.l23.network_preflight.state')],
        'Next': 'ParallelJoinKeys'}], 'Default': 'JoinMalformed'}
    states['ParallelJoinKeys'] = {'Type': 'Choice', 'Choices': [{
        'Or': [{'Variable': path, 'StringEquals': '-'} for path in (
            '$.result.l0.s3_key', '$.result.l1.s3_key',
            '$.result.l23.l2.s3_key', '$.result.l23.l3.s3_key')],
        'Next': 'JoinMalformed'}], 'Default': 'MarkL0L1'}
    states['JoinMalformed'] = {'Type': 'Pass',
        'Result': {'Error': 'JoinMalformed', 'Cause': 'layer invocation or shape failed'},
        'ResultPath': '$.error', 'Next': 'MarkFailed'}
    states['MarkL0L1']['Next'] = 'UnpackL23'
    states['UnpackL23'] = {'Type': 'Pass', 'Parameters': {'l23.$': '$.result.l23'},
                           'ResultPath': '$.observe', 'Next': 'SafetyDecision'}
    states.pop('GateDecision')
    states['SafetyDecision'] = {'Type': 'Choice', 'Choices': [
        {'And': [
            {'Variable': '$.result.l1.block_reason', 'StringEquals': 'BLOCKED_PRIVATE_TARGET'},
            {'Variable': '$.observe.l23.network_preflight.state', 'StringEquals': 'public_target_at_preflight'}],
         'Next': 'SafetyConflict'},
        {'Variable': '$.result.l1.block_reason', 'StringEquals': 'BLOCKED_PRIVATE_TARGET',
         'Next': 'MarkSafetyBlocked'}], 'Default': 'L23_Shape_AfterJoin'}
    states['SafetyConflict'] = {'Type': 'Pass', 'Result': {'Error': 'SafetyConflict',
        'Cause': 'L1 private target conflicts with L23 public preflight'},
        'ResultPath': '$.error', 'Next': 'MarkFailed'}
    states.pop('MarkGateBlocked')
    states['MarkSafetyBlocked'] = {'Type': 'Task',
        'Resource': 'arn:aws:states:::dynamodb:updateItem',
        'Parameters': {'TableName': states['MarkContext']['Parameters']['TableName'],
            'Key': {'job_id': {'S.$': '$.job_id'}},
            'UpdateExpression': 'SET #st = :st, #cl = :cl, block_reason = :reason, updatedAt = :t',
            'ExpressionAttributeNames': {'#st': 'status', '#cl': 'current_layer'},
            'ExpressionAttributeValues': {':st': {'S': 'TARGET_BLOCKED'}, ':cl': {'S': '-'},
                ':reason': {'S.$': '$.result.l1.block_reason'},
                ':t': {'S.$': '$$.State.EnteredTime'}}},
        'ResultPath': None,
        'Catch': [{'ErrorEquals': ['States.ALL'], 'ResultPath': '$.error', 'Next': 'MarkFailed'}],
        'End': True}
    states['L23_Shape_AfterJoin'] = {'Type': 'Choice', 'Choices': [
        {'And': [
            {'Variable': '$.observe.l23.l2.s3_key', 'IsPresent': True},
            {'Variable': '$.observe.l23.l3.s3_key', 'IsPresent': True},
            {'Variable': '$.observe.l23.reach_state', 'IsPresent': True},
            {'Variable': '$.observe.l23.network_preflight.state', 'IsPresent': True}],
         'Next': 'MarkObserved'}], 'Default': 'L23JoinMalformed'}
    states['L23JoinMalformed'] = {'Type': 'Pass', 'Result': {'Error': 'L23JoinMalformed',
        'Cause': 'L23 did not return record references and preflight state'},
        'ResultPath': '$.error', 'Next': 'MarkFailed'}
    states['ContextTask']['Parameters']['FunctionName'] = functions['context']
    states['JudgmentTask']['Parameters']['FunctionName'] = functions['judgment']
    states['MarkObserved']['Next'] = 'ActivityTask'
    states['ActivityTask'] = {'Type': 'Task', 'Resource': 'arn:aws:states:::lambda:invoke',
        'Parameters': {'FunctionName': functions['activity'], 'Payload': {
            'operation': 'activity', 'job_id.$': '$.job_id', 'url.$': '$.url',
            'attempt.$': '$.alloc.attempt',
            'layers': states['ContextTask']['Parameters']['Payload']['layers']}},
        'ResultSelector': {'decision.$': '$.Payload'}, 'ResultPath': '$.activity',
        'TimeoutSeconds': 60,
        'Catch': [{'ErrorEquals': ['States.ALL'], 'ResultPath': '$.error', 'Next': 'MarkFailed'}],
        'Next': 'ActivityShape'}
    states['ActivityShape'] = {'Type': 'Choice', 'Choices': [{
        'And': [{'Variable': path, 'IsPresent': True} for path in (
            '$.activity.decision.url_activity_key', '$.activity.decision.url_activity_sha256',
            '$.activity.decision.url_activity_state', '$.activity.decision.skip_judgment')],
        'Next': 'ContextTask'}], 'Default': 'ActivityMalformed'}
    states['ContextTask']['Parameters']['Payload']['url_activity.$'] = '$.activity.decision'
    states['MarkContext']['Next'] = 'URLActivityDecision'
    states['URLActivityDecision'] = {'Type': 'Choice', 'Choices': [
        {'And': [
            {'Variable': '$.activity.decision.skip_judgment', 'BooleanEquals': True},
            {'Variable': '$.activity.decision.url_activity_state',
             'StringEquals': 'DNS_NAME_NONEXISTENT_AT_SCAN'},
            {'Variable': '$.context.ctx.skip_judgment', 'BooleanEquals': True}],
         'Next': 'MarkDnsInactive'},
        {'And': [
            {'Variable': '$.activity.decision.skip_judgment', 'BooleanEquals': True},
            {'Variable': '$.activity.decision.url_activity_state',
             'StringEquals': 'URL_UNREACHABLE_AT_SCAN'},
            {'Variable': '$.context.ctx.skip_judgment', 'BooleanEquals': True}],
         'Next': 'MarkUrlUnreachable'},
        {'And': [
            {'Variable': '$.activity.decision.skip_judgment', 'BooleanEquals': False},
            {'Variable': '$.context.ctx.skip_judgment', 'BooleanEquals': False}],
         'Next': 'JudgmentTask'}], 'Default': 'ActivityMalformed'}
    states['ActivityMalformed'] = {'Type': 'Pass', 'Result': {'Error': 'ActivityMalformed',
        'Cause': 'Builder did not return an explicit skip_judgment boolean'},
        'ResultPath': '$.error', 'Next': 'MarkFailed'}
    states['MarkDnsInactive'] = {'Type': 'Task',
        'Resource': 'arn:aws:states:::dynamodb:updateItem',
        'Parameters': {'TableName': states['MarkContext']['Parameters']['TableName'],
            'Key': {'job_id': {'S.$': '$.job_id'}},
            'UpdateExpression': 'SET #st = :st, #cl = :cl, judgment_status = :js, url_activity_key = :key, url_activity_sha256 = :hash, url_activity_state = :state, url_activity_valid_until = :until, updatedAt = :t',
            'ExpressionAttributeNames': {'#st': 'status', '#cl': 'current_layer'},
            'ExpressionAttributeValues': {
                ':st': {'S': 'DNS_NAME_NONEXISTENT_AT_SCAN'}, ':cl': {'S': '-'},
                ':js': {'S': 'not_requested_dns_name_nonexistent_at_scan'},
                ':key': {'S.$': '$.activity.decision.url_activity_key'},
                ':hash': {'S.$': '$.activity.decision.url_activity_sha256'},
                ':state': {'S.$': '$.activity.decision.url_activity_state'},
                ':until': {'S.$': '$.activity.decision.valid_until'},
                ':t': {'S.$': '$$.State.EnteredTime'}}},
        'ResultPath': None,
        'Catch': [{'ErrorEquals': ['States.ALL'], 'ResultPath': '$.error', 'Next': 'MarkFailed'}],
        'End': True}
    unreachable = deepcopy(states['MarkDnsInactive'])
    params = unreachable['Parameters']
    params['UpdateExpression'] = params['UpdateExpression'].replace(
        ', url_activity_valid_until = :until', '')
    params['ExpressionAttributeValues'].pop(':until')
    params['ExpressionAttributeValues'][':st'] = {'S': 'URL_UNREACHABLE_AT_SCAN'}
    params['ExpressionAttributeValues'][':js'] = {'S': 'not_requested_url_unreachable_at_scan'}
    states['MarkUrlUnreachable'] = unreachable
    # The parallel branches have completed here. Write shared progress once
    # after the join, rather than using the old L0/L1 then L23 updates.
    old_l0l1 = states.pop('MarkL0L1')['Parameters']
    states['ParallelJoinKeys']['Default'] = 'UnpackL23'
    joined = states['MarkObserved']['Parameters']
    joined['UpdateExpression'] = joined['UpdateExpression'].replace(
        'reach_state = :rs,', 'l0_key = :k0, l1_key = :k1, reach_state = :rs,')
    joined['UpdateExpression'] = joined['UpdateExpression'].replace(
        '#fr.#g = :fg,', '#fr.#l0 = :f0, #fr.#l1 = :f1, #fr.#g = :fg,')
    for name in ('#l0', '#l1'):
        joined['ExpressionAttributeNames'][name] = old_l0l1['ExpressionAttributeNames'][name]
    for name in (':k0', ':k1', ':f0', ':f1'):
        joined['ExpressionAttributeValues'][name] = old_l0l1['ExpressionAttributeValues'][name]
    blocked = states['MarkSafetyBlocked']['Parameters']
    blocked['UpdateExpression'] = blocked['UpdateExpression'].replace(
        'block_reason = :reason,',
        'l0_key = :k0, l1_key = :k1, l2_key = :k2, l3_key = :k3, block_reason = :reason,')
    blocked['ExpressionAttributeValues'].update({
        ':k0': {'S.$': '$.result.l0.s3_key'}, ':k1': {'S.$': '$.result.l1.s3_key'},
        ':k2': {'S.$': '$.observe.l23.l2.s3_key'},
        ':k3': {'S.$': '$.observe.l23.l3.s3_key'}})
    return value


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--functions', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    baseline = json.loads(args.baseline.read_text(encoding='utf-8'))
    functions = json.loads(args.functions.read_text(encoding='utf-8'))
    result = patch_definition(baseline, functions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
