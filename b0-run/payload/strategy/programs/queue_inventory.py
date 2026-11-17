try:
    role=conn.call('ROLE')
    server_info=txt(conn.call('INFO','server'))
    info={line.split(':',1)[0]:line.split(':',1)[1] for line in server_info.splitlines() if ':' in line and not line.startswith('#')}
    before=inspect_queue(conn)
    after=inspect_queue(conn)
    result={'kind':'queue_inventory','redis_db':cfg['redis_db'],'peer':conn.peer,
            'redis_role':txt(role[0]),'redis_run_id':info.get('run_id'),'redis_version':info.get('redis_version'),
            'before':before,'after':after,'stable_payloads':before['inventory_token']==after['inventory_token'],
            'commands':commands,'source_complete':True,
            'read_only_commands':True,'writer_barrier_claimed':False}
    emit(result)
finally:
    conn.close()
