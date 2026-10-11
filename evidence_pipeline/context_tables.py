"""Named columns for repeated evidence rows; no fact selection or interpretation.

Each group has one kind and exactly the same supplied fact keys. Shared values
are printed once. Row zero is the evidence ID; subsequent cells follow columns.
Unlike padding heterogeneous records, this cannot turn missing data into null.
"""
from copy import deepcopy
from collections import defaultdict
import json


def size(value):
    return len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode())


def same(left,right):
    return json.dumps(left,sort_keys=True,ensure_ascii=False)==json.dumps(right,sort_keys=True,ensure_ascii=False)


def common_fields(values):
    shared={}
    for key in values[0]:
        if not all(key in v for v in values):continue
        cells=[v[key] for v in values]
        if all(same(cells[0],v) for v in cells):shared[key]=deepcopy(cells[0])
        elif all(isinstance(v,dict) for v in cells):
            child=common_fields(cells)
            if child:shared[key]=child
    return shared


def subtract(value,shared):
    result=deepcopy(value)
    for key,item in shared.items():
        if same(result[key],item):result.pop(key)
        else:result[key]=subtract(result[key],item)
    return result


def merge(shared,delta):
    result=deepcopy(shared)
    for key,value in delta.items():
        if key in result:
            if not isinstance(value,dict) or not isinstance(result[key],dict):
                raise ValueError('conflicting_evidence_table_fact')
            result[key]=merge(result[key],value)
        else:result[key]=deepcopy(value)
    return result


def present(view):
    if 'evidence_table_encoding' in view:
        return deepcopy(view)
    evidence = view.get('evidence')
    if not isinstance(evidence, list) or not evidence:
        return deepcopy(view)
    groups = defaultdict(list)
    for index, row in enumerate(evidence):
        if set(row) != {'id', 'kind', 'facts'} or not isinstance(row['facts'], dict):
            return deepcopy(view)
        groups[(row['kind'], tuple(sorted(row['facts'])))].append((index, row))
    tables=[]
    for (kind, keys), rows in groups.items():
        common=common_fields([r['facts'] for _,r in rows]) if len(rows)>1 else {}
        deltas=[subtract(r['facts'],common) for _,r in rows]
        columns=[k for k in keys if any(k in delta for delta in deltas)]
        # A column is present for every row in this shape group. The nested
        # common-field subtraction leaves the same key set across these rows.
        if not all(set(delta)==set(columns) for delta in deltas):
            common={k:v for k,v in common.items() if all(same(r['facts'][k],v) for _,r in rows)}
            deltas=[subtract(r['facts'],common) for _,r in rows]
            columns=[k for k in keys if k not in common]
        tables.append({'kind':kind, 'columns':['id',*columns], 'shared_facts':common,
            'positions':[i for i,_ in rows],
            'rows':[[r['id'],*[delta[k] for k in columns]] for (_,r),delta in zip(rows,deltas,strict=True)]})
    result=deepcopy(view)
    result['evidence']=tables
    result['evidence_table_encoding']={
        'version':1,
        'read':'Each group defines evidence of one kind. A row follows columns, starting with its E citation ID. Recursively combine remaining columns with shared_facts to read its full facts; shared values are printed once. Every supplied fact and row is retained; positions restore original order. Missing keys are not inferred.'}
    return result if size(result)<size(view) else deepcopy(view)


def restore(view):
    result=deepcopy(view)
    encoding=result.pop('evidence_table_encoding', None)
    if encoding is None:
        return result
    if encoding.get('version') != 1:
        raise ValueError('invalid_evidence_table_encoding')
    located={}
    for group in result['evidence']:
        if not group['columns'] or group['columns'][0]!='id':
            raise ValueError('invalid_evidence_table_columns')
        columns=group['columns'][1:]
        if len(columns)!=len(set(columns)):
            raise ValueError('conflicting_evidence_table_columns')
        for index,row in zip(group['positions'],group['rows'],strict=True):
            if type(index) is not int or index in located:
                raise ValueError('invalid_evidence_table_position')
            facts=merge(group['shared_facts'],dict(zip(columns,row[1:],strict=True)))
            located[index]={'id':row[0],'kind':group['kind'],'facts':facts}
    if set(located)!=set(range(len(located))):
        raise ValueError('missing_evidence_table_position')
    result['evidence']=[located[i] for i in range(len(located))]
    return result
