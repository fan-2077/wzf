pages, rows, seen, path, snapshot, total = [], [], set(), '/messages', None, None
while path is not None:
    if not isinstance(path,str) or path in seen:
        raise RuntimeError('invalid_or_repeated_audit_cursor')
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.path != '/messages' or parsed.fragment:
        raise RuntimeError('audit_cursor_outside_allowlist')
    query = parse_qs(parsed.query, strict_parsing=True)
    if any(k not in ('after','through') for k in query) or any(len(v)!=1 or not v[0].isdigit() for v in query.values()):
        raise RuntimeError('invalid_audit_cursor_parameters')
    seen.add(path)
    if len(seen)>4096: raise RuntimeError('audit_page_budget')
    res = request('GET', path)
    if res['status'] != 200: raise RuntimeError('audit_http_error')
    page = res['body']
    if type(page.get('snapshot')) is not int or type(page.get('total')) is not int or page['total']<0:
        raise RuntimeError('audit_schema_error')
    if snapshot is None: snapshot,total=page['snapshot'],page['total']
    if page['snapshot']!=snapshot or page['total']!=total:
        raise RuntimeError('audit_snapshot_changed')
    if not isinstance(page.get('items'),list): raise RuntimeError('audit_items_invalid')
    rows.extend(page['items']); pages.append(res); path=page['next']
    if len(rows)>100000: raise RuntimeError('audit_item_budget')
ids=[r['id'] for r in rows]
if len(rows)!=total or len(set(ids))!=total or ids!=sorted(ids) or any(type(i)is not int or i<1 or i>snapshot for i in ids):
    raise RuntimeError('incomplete_or_ambiguous_audit')
emit({'kind':'public_audit','snapshot':snapshot,'total':total,'items':rows,'pages':pages,'source_complete':True,'fresh_begin':True})
