"""L1-only evidence selection, shared by standalone and combined documents.

Stored source data remains in the audit. This module selects observations and
recorded relationships, without parsing a URL or deciding maliciousness.
"""
from copy import deepcopy

from .records import canonical

KINDS = {'dns_a_ip_asn', 'dns_a', 'dns_ns_host', 'dns_ns_registration',
         'dns_rdap_ns_comparison', 'rdap', 'ip_asn', 'infrastructure_observation'}
ADDRESS_SELECTION = 'DNS A 응답에서 중복을 뺀 첫 IPv4 두 개'
DNS_CHECKS = {'DNS A', 'DNS AAAA', 'DNS NS', 'DNS NS (등록 단위)'}


def _cname_without_ttl(value):
    """Old L1 records stored CNAME lines as owner TTL IN CNAME target."""
    lines=[]
    for line in value.splitlines():
        owner_and_ttl, separator, target=line.partition(' IN CNAME ')
        owner, space, ttl=owner_and_ttl.rpartition(' ')
        lines.append(f'{owner} IN CNAME {target}' if separator and space and ttl.isdecimal() else line)
    return '\n'.join(lines)


def _cname_relations(lines):
    relations=[]
    for item in lines:
        if not isinstance(item,str):return None
        for line in item.splitlines():
            source, separator, target=line.partition(' IN CNAME ')
            if not separator or not source or not target:return None
            relations.append({'from_domain':source,'to_domain':target})
    return relations


def _without_l1_dns_ttl(value):
    """Keep stored records intact while omitting DNS TTL from the model view."""
    if value.get('layer')!='l1' or value.get('name') not in DNS_CHECKS:return value
    evidence=value.get('evidence')
    if not isinstance(evidence,dict):return value
    result=evidence.get('result')
    if isinstance(result,dict):result.pop('ttl',None)
    detail=evidence.get('detail')
    if isinstance(detail,dict) and isinstance(detail.get('cname_chain'),list):
        chain=[_cname_without_ttl(item) if isinstance(item,str) else item
               for item in detail['cname_chain']]
        relations=_cname_relations(chain)
        if relations is not None:
            detail.pop('cname_chain')
            if relations:detail['cname_relations']=relations
        else:
            detail['cname_chain']=chain
    return value


def _l1_address_with_asn(value, ip_asn):
    """Group the selected A addresses by the IP·ASN facts shown to the model."""
    if value.get('layer')!='l1' or value.get('name')!='DNS A' or not isinstance(ip_asn,dict):
        return value
    a_result=(value.get('evidence') or {}).get('result')
    asn_evidence=ip_asn.get('evidence') or {}
    detail=asn_evidence.get('detail') or {}
    targets=detail.get('query_targets')
    query_target=(value.get('observation') or {}).get('query_target')
    if not (isinstance(query_target,str) and query_target
            and (value.get('evidence') or {}).get('status')=='응답 수신'
            and isinstance(a_result,dict) and isinstance(a_result.get('records'),list)
            and isinstance(targets,list) and targets and len(targets)<=2):
        return value
    selected=list(dict.fromkeys(a_result['records']))[:2]
    if targets!=selected:
        return value
    observed=asn_evidence.get('result')
    observed=observed if isinstance(observed,dict) else {}
    networks=[]
    by_facts={}
    for ip in targets:
        data=observed.get(ip)
        if not isinstance(data,dict) or not data.get('asn') or 'lookup_failure' in data:
            facts={'ip_asn':'not_observed'}
        else:
            facts={key:data[key] for key in ('asn','prefix','org') if data.get(key) is not None}
            if 'org' not in facts:facts['org']='not_observed'
        # Only complete, observed network facts establish a grouping relation.
        complete=all(isinstance(facts.get(key),str) and facts[key]!='not_observed'
                     for key in ('asn','prefix','org'))
        signature=tuple(sorted(facts.items())) if complete else (ip,)
        if signature not in by_facts:
            group={'queried_ipv4':[],**facts}
            by_facts[signature]=group
            networks.append(group)
        by_facts[signature]['queried_ipv4'].append(ip)
    value['_ip_asn_networks']=networks
    return value


def _target(item):
    return (item.get('observation') or (item.get('evidence') or {}).get('observation') or {}).get('query_target')


def _result(item):
    return (item.get('evidence') or {}).get('result')


def _networks(targets, observed):
    groups=[]
    for ip in targets:
        data=observed.get(ip)
        if not isinstance(data,dict) or not data.get('asn') or 'lookup_failure' in data:
            groups.append({'ipv4':[ip], 'ip_asn':'not_observed'})
            continue
        facts={key:deepcopy(data[key]) for key in ('asn','prefix','org') if data.get(key) is not None}
        facts.setdefault('org','not_observed')
        complete=all(isinstance(facts.get(key),str) and facts[key]!='not_observed' for key in ('asn','prefix','org'))
        previous=next((group for group in groups if {k:v for k,v in group.items() if k!='ipv4'}==facts),None) if complete else None
        if previous is not None:previous['ipv4'].append(ip)
        else:groups.append({'ipv4':[ip],**facts})
    return groups


class L1Projection:
    def __init__(self, source):
        self.source=source
        self.layers=[(i,x) for i,x in enumerate(source.get('layers',[])) if x.get('layer')=='l1']
        self.items=[(i,x) for i,x in enumerate(source.get('observations',[])) if x.get('layer')=='l1']
        self.present=bool(self.layers or self.items)
        self.projected={}
        layer=self.layers[0][1] if self.layers else {}
        host=(layer.get('target') or {}).get('lookup_host')
        if not host:
            host=next((_target(x) for _,x in self.items if x.get('name') in ('DNS A','DNS NS') and _target(x)),None)
        domain=((layer.get('coverage') or {}).get('domain_units') or {}).get('등록 단위')
        self.subject={k:v for k,v in [('lookup_host',host),('registered_domain',domain)] if isinstance(v,str) and v}

    def register(self, document):
        if not self.present:return
        by_name={x.get('name'):(i,x) for i,x in self.items}
        by_id={x.get('id'):(i,x) for i,x in self.items}
        used=set()

        def emit(kind, facts, original, pointers):
            eid=document.add(kind,original,pointers[0])
            document.definitions[-1]['source_pointers']=list(dict.fromkeys(pointers))
            self.projected[eid]=facts
            return eid

        def omit(i, reason):
            used.add(i)
            document.model_omissions.append({'source':f'/observations/{i}','reason':reason})

        def scoped(item, facts, field):
            target=_target(item)
            if target and target!=self.subject.get(field):facts['query_target']=target
            return facts

        def limit(item, facts):
            evidence=item.get('evidence') or {}
            observation=item.get('observation') or evidence.get('observation') or {}
            if evidence.get('status')!='응답 수신' or observation.get('state') in ('partial','unavailable','not_attempted','interrupted'):
                facts['status']='partial' if facts else 'not_observed'
                if evidence.get('reason'):facts['reason']=evidence['reason']
            return facts

        a=by_name.get('DNS A'); ip_asn=by_name.get('IP·ASN')
        if a:
            i,item=a
            cleaned=_without_l1_dns_ttl(deepcopy(item))
            paired=_l1_address_with_asn(cleaned,ip_asn[1]) if ip_asn else cleaned
            networks=paired.get('_ip_asn_networks')
            if networks:
                facts={'address_selection':ADDRESS_SELECTION,'networks':[
                    {'ipv4':group['queried_ipv4'],**{k:v for k,v in group.items() if k!='queried_ipv4'}} for group in networks]}
                detail=(cleaned.get('evidence') or {}).get('detail') or {}
                if detail.get('cname_relations'):facts['cname_relations']=detail['cname_relations']
                elif detail.get('cname_chain'):facts['cname_chain']=detail['cname_chain']
                emit('dns_a_ip_asn',scoped(item,facts,'lookup_host'),item,[f'/observations/{i}',f'/observations/{ip_asn[0]}'])
                used.add(i);omit(ip_asn[0],'ip_asn_represented_with_dns_a')

        comparison=None
        for index,fact in enumerate(self.source.get('analysis_facts',[])):
            if fact.get('layer')!='l1' or fact.get('kind')!='dns_rdap_nameserver_set_comparison':continue
            linked=[by_id[x] for x in fact.get('source_evidence_ids',[]) if x in by_id]
            ns=next((x for _,x in linked if x.get('name') in ('DNS NS','DNS NS (등록 단위)')),None)
            rdap=next((x for _,x in linked if x.get('name')=='RDAP'),None)
            domain=fact.get('domain')
            if not domain or ns is None or rdap is None or _target(ns)!=domain or _target(rdap)!=domain:continue
            ns_result=_result(ns);rdap_result=_result(rdap)
            dns=ns_result.get('records') if isinstance(ns_result,dict) else None
            registered=rdap_result.get('nameservers') if isinstance(rdap_result,dict) else None
            if not all((x.get('evidence') or {}).get('status')=='응답 수신' for x in (ns,rdap)):continue
            if not all(isinstance(v,list) and v and all(isinstance(n,str) and n for n in v) for v in (dns,registered)):continue
            normalize=lambda values:{n.rstrip('.').casefold() for n in values}
            left,right=normalize(dns),normalize(registered)
            if type(fact.get('same_set')) is not bool or fact['same_set']!=(left==right):continue
            comparison={'status':'matched' if fact['same_set'] else 'different'}
            if domain!=self.subject.get('registered_domain'):comparison['query_target']=domain
            if not fact['same_set']:comparison.update(dns_only=sorted(left-right),rdap_only=sorted(right-left))
            emit('dns_rdap_ns_comparison',comparison,fact,[f'/analysis_facts/{index}',*[f'/observations/{i}' for i,_ in linked]])
            break

        for i,item in self.items:
            if i in used:continue
            name=item.get('name');evidence=item.get('evidence') or {};result=_result(item)
            if name=='DNS AAAA':omit(i,'dns_aaaa_excluded_from_model_context');continue
            if item.get('state')=='not_applicable':omit(i,'query_not_applicable');continue
            if name=='IP·ASN' and a and evidence.get('status')=='Not Queried' and (
                    _result(a[1])=='NXDOMAIN' or isinstance(_result(a[1]),dict) and _result(a[1]).get('records')==[]):
                omit(i,'ip_asn_has_no_dns_a_target');continue
            facts={};kind='infrastructure_observation';scope='lookup_host'
            if name in DNS_CHECKS:
                cleaned=_without_l1_dns_ttl(deepcopy(item));evidence=cleaned.get('evidence') or {};result=evidence.get('result')
                detail=evidence.get('detail') or {}
                if name!='DNS A':
                    registration=name=='DNS NS (등록 단위)' or bool(self.subject.get('registered_domain') and _target(item)==self.subject['registered_domain'])
                    # Receiving a DNS reply does not mean NS names were obtained.
                    # Keep negative/error replies; only lists are reserved for comparison.
                    if (registration and evidence.get('status')=='응답 수신'
                            and isinstance(result,dict) and isinstance(result.get('records'),list)):
                        omit(i,'registration_ns_reserved_for_comparison_not_model_lookup');continue
                    if result=={'records':[]} and not item.get('cause_ids') and not detail.get('cname_relations'):
                        omit(i,'routine_host_ns_nodata_excluded_from_model_context');continue
                    kind='dns_ns_registration' if registration else 'dns_ns_host'
                    scope='registered_domain' if registration else 'lookup_host'
                    if isinstance(result,dict) and result.get('records'):facts['nameservers']=deepcopy(result['records'])
                else:
                    kind='dns_a'
                    if isinstance(result,dict) and isinstance(result.get('records'),list):
                        facts['ipv4']=list(dict.fromkeys(result['records']))[:2]
                        if facts['ipv4']:facts['address_selection']=ADDRESS_SELECTION
                if isinstance(result,str):facts['response']=result
                if isinstance(result,dict) and result.get('response_codes'):facts['response_codes']=deepcopy(result['response_codes'])
                if detail.get('cname_relations'):facts['cname_relations']=detail['cname_relations']
                elif detail.get('cname_chain'):facts['cname_chain']=detail['cname_chain']
                limit(item,facts)
            elif name=='RDAP':
                kind='rdap';scope='registered_domain'
                if isinstance(result,str):facts={'status':'not_observed','response':result}
                if isinstance(result,dict):
                    for key in ('registration','expiration','last_changed'):
                        if isinstance(result.get(key),str) and result[key]:facts[key]=result[key]
                    if result.get('status'):facts['domain_status']=deepcopy(result['status'])
                    registrar=result.get('registrar')
                    if isinstance(registrar,dict):
                        chosen={k:v for k,v in registrar.items() if k in ('name','iana_id') and isinstance(v,str) and v}
                        if chosen:facts['registrar']=chosen
                    elif isinstance(registrar,str) and registrar:facts['registrar']=registrar
                    if comparison is None and result.get('nameservers'):facts['nameservers']=deepcopy(result['nameservers'])
                    if isinstance(result.get('registered'),bool):facts['registered']=result['registered']
                limit(item,facts)
                if not facts and comparison is not None:
                    omit(i,'rdap_only_ns_represented_by_comparison');continue
                document.model_omissions.append({'source':f'/observations/{i}','reason':'rdap_record_wrapper_excluded_from_model_context'})
            elif name=='IP·ASN':
                kind='ip_asn'
                observed=result if isinstance(result,dict) else {}
                detail=evidence.get('detail') or {}
                targets=detail.get('query_targets') or list(dict.fromkeys([*observed,*(detail.get('dropped') or {})]))
                if targets:
                    groups=_networks(targets,observed)
                    # Literal IP queries may be IPv6; do not label them as DNS A IPv4.
                    facts['networks']=[{'ip':g.pop('ipv4'),**g} for g in groups]
                else:limit(item,facts)
            else:
                facts={'lookup':name or 'not_recorded'}
                limit(item,facts)
            if not facts:facts={'status':'not_observed'}
            emit(kind,scoped(item,facts,scope),item,[f'/observations/{i}'])

        for layer_index,layer in self.layers:
            lifecycle=(layer.get('coverage') or {}).get('query_lifecycle') or []
            for index,query in enumerate(lifecycle):
                name=query.get('name')
                if name=='DNS AAAA' or name in by_name:continue
                facts={'lookup':name or 'not_recorded','status':'not_observed'}
                if query.get('run_stop_reason'):facts['reason']=query['run_stop_reason']
                emit('infrastructure_observation',facts,query,[f'/layers/{layer_index}/coverage/query_lifecycle/{index}'])
            if not self.projected:
                facts={'status':'not_observed'}
                reason=(layer.get('execution') or {}).get('reason')
                if isinstance(reason,str) and reason:facts['reason']=reason
                emit('infrastructure_observation',facts,layer,[f'/layers/{layer_index}'])
            document.model_omissions.append({'source':f'/layers/{layer_index}',
                'reason':'l1_subject_selected_execution_and_storage_metadata_are_audit_only'})


def validate_l1_selection(context):
    rows=context.get('evidence',[])
    selected=[r for r in rows if r.get('kind') in KINDS]
    # Previously persisted model documents retain their historical contract.
    # New projections always carry the L1 subject, even if it is unknown/empty.
    if not selected and 'l1' not in (context.get('layer_subjects') or {}):return
    for row in rows:
        facts=row.get('facts',{})
        if facts.get('layer')=='l1':raise ValueError('l1_record_wrapper_leaked_to_model_context')
    if not selected:return
    subject=(context.get('layer_subjects') or {}).get('l1')
    if not isinstance(subject,dict) or set(subject)-{'lookup_host','registered_domain'} or any(not isinstance(v,str) or not v for v in subject.values()):
        raise ValueError('invalid_l1_subject')
    if all(row.get('kind') in KINDS|{'url_subject','url_observation'} for row in rows):
        if set(context.get('reading_guide') or {})-{'l0'}:
            raise ValueError('unrelated_guide_in_l01_context')
    allowed={
        'dns_a_ip_asn':{'address_selection','networks','cname_relations','cname_chain','query_target'},
        'dns_a':{'ipv4','address_selection','response','response_codes','cname_relations','cname_chain','query_target','status','reason'},
        'dns_ns_host':{'nameservers','response','response_codes','cname_relations','cname_chain','query_target','status','reason'},
        'dns_ns_registration':{'response','response_codes','query_target','status','reason'},
        'dns_rdap_ns_comparison':{'status','dns_only','rdap_only','query_target'},
        'rdap':{'registration','expiration','last_changed','domain_status','registrar','nameservers','registered','query_target','status','reason','response'},
        'ip_asn':{'networks','query_target','status','reason'},
        'infrastructure_observation':{'lookup','status','reason','query_target'},
    }
    comparison=any(r['kind']=='dns_rdap_ns_comparison' for r in selected)
    if any(r['kind']=='dns_a_ip_asn' for r in selected) and any(r['kind'] in ('dns_a','ip_asn') for r in selected):
        raise ValueError('paired_ip_asn_duplicated_in_model_context')
    for row in selected:
        kind=row['kind'];facts=row.get('facts')
        if not isinstance(facts,dict) or not facts or set(facts)-allowed[kind]:raise ValueError('invalid_l1_model_selection')
        if kind=='rdap':
            if comparison and 'nameservers' in facts:raise ValueError('rdap_nameservers_duplicated_in_model_context')
            registrar=facts.get('registrar')
            if isinstance(registrar,dict) and (not registrar or set(registrar)-{'name','iana_id'}):raise ValueError('invalid_l1_registrar')
            if any(key in facts and (not isinstance(facts[key],str) or not facts[key])
                   for key in ('registration','expiration','last_changed')):raise ValueError('invalid_l1_rdap_date')
            if 'registered' in facts and type(facts['registered']) is not bool:raise ValueError('invalid_l1_registered')
        for key in ('nameservers','domain_status','response_codes','dns_only','rdap_only'):
            if key in facts and (not isinstance(facts[key],list) or any(not isinstance(v,str) or not v for v in facts[key])):
                raise ValueError('invalid_l1_observed_list')
        if 'cname_relations' in facts and (not isinstance(facts['cname_relations'],list) or any(
                not isinstance(relation,dict) or set(relation)!={'from_domain','to_domain'}
                or any(not isinstance(v,str) or not v for v in relation.values()) for relation in facts['cname_relations'])):
            raise ValueError('invalid_l1_cname_relation')
        if kind=='dns_rdap_ns_comparison':
            if facts.get('status') not in ('matched','different'):raise ValueError('invalid_ns_comparison_model_status')
            if facts['status']=='matched' and set(facts)&{'dns_only','rdap_only'}:raise ValueError('matched_ns_comparison_contains_duplicate_lists')
            if facts['status']=='different' and not (facts.get('dns_only') or facts.get('rdap_only')):raise ValueError('ns_difference_without_differences')
        if kind in ('dns_a_ip_asn','ip_asn') and 'networks' in facts:
            groups=facts['networks'];members=[];signatures=[];ip_key='ipv4' if kind=='dns_a_ip_asn' else 'ip'
            if not isinstance(groups,list) or not groups:raise ValueError('invalid_l1_networks')
            for group in groups:
                if not isinstance(group,dict) or set(group)-{ip_key,'asn','prefix','org','ip_asn'}:raise ValueError('invalid_l1_networks')
                ips=group.get(ip_key)
                if not isinstance(ips,list) or not ips or any(not isinstance(ip,str) or not ip for ip in ips):raise ValueError('invalid_l1_networks')
                members.extend(ips)
                if 'ip_asn' in group:
                    if group['ip_asn']!='not_observed' or set(group)!={ip_key,'ip_asn'} or len(ips)!=1:raise ValueError('invalid_l1_networks')
                elif not isinstance(group.get('asn'),str):raise ValueError('invalid_l1_networks')
                complete=all(isinstance(group.get(k),str) and group[k]!='not_observed' for k in ('asn','prefix','org'))
                if len(ips)>1 and not complete:raise ValueError('invalid_l1_networks')
                signature=canonical({k:v for k,v in group.items() if k!=ip_key}) if complete else canonical(group)
                if signature in signatures:raise ValueError('duplicated_l1_network_group')
                signatures.append(signature)
            if len(members)!=len(set(members)):raise ValueError('duplicated_l1_address')
            if kind=='dns_a_ip_asn' and (len(members)>2 or facts.get('address_selection')!=ADDRESS_SELECTION):raise ValueError('invalid_l1_address_selection')


def present_l1(context):
    """Expose the approved layer document from the same selected combined facts."""
    from .context_inventory import restore
    source=restore(context)
    validate_l1_selection(source)
    if 'l1' not in source.get('layer_subjects',{}):raise ValueError('l1_context_missing')
    return {'layer':'L1','subject':deepcopy(source['layer_subjects']['l1']),
            'evidence':[{'id':r['id'],'kind':r['kind'],**deepcopy(r['facts'])}
                        for r in source['evidence'] if r['kind'] in KINDS]}


def build_l1_context(record, raw, *, audit=None):
    from .context import build_context
    if record.get('layer')!='l1':raise ValueError('expected_l1_record')
    return present_l1(build_context([record],{'l1':raw},audit=audit))
