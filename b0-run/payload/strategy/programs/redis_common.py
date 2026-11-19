import base64
import hashlib
import json
import lzma
import socket
import sys
import time
import zlib
from collections import Counter

cfg = json.loads(sys.argv[1])
MAX_BULK = 16 * 1024 * 1024
MAX_ITEMS = 200000
commands = []

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def emit(obj):
    raw=json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    compressed=zlib.compress(raw)
    marker,encoding='B0_RESULT_ZLIB:','zlib+base64'
    if len(compressed)>4096:
        candidate=lzma.compress(raw,format=lzma.FORMAT_XZ,preset=3)
        if len(candidate)<len(compressed):
            compressed=candidate
            marker,encoding='B0_RESULT_XZ:','xz+base64'
    envelope={'encoding':encoding,'uncompressed_bytes':len(raw),
              'uncompressed_sha256':hashlib.sha256(raw).hexdigest(),
              'data_base64':base64.b64encode(compressed).decode()}
    print(marker+json.dumps(envelope,sort_keys=True,separators=(',',':')))

class Redis:
    def __init__(self):
        self.sock = socket.create_connection(('gitlab-redis',6379),timeout=30)
        self.sock.settimeout(30)
        self.peer = list(self.sock.getpeername())
        self.stream = self.sock.makefile('rb')
        self.call('SELECT',cfg['redis_db'])
    def close(self):
        self.stream.close(); self.sock.close()
    def read(self, depth=0):
        if depth>32: raise RuntimeError('RESP_depth')
        line=self.stream.readline(65537)
        if not line or len(line)>65536 or not line.endswith(b'\r\n'): raise RuntimeError('RESP_incomplete_line')
        kind,content=line[:1],line[1:-2]
        if kind==b'+':return content
        if kind==b'-':raise RuntimeError('Redis_error_'+content[:100].decode('ascii','replace'))
        if kind==b':':return int(content)
        if kind==b'$':
            size=int(content)
            if size==-1:return None
            if not 0<=size<=MAX_BULK:raise RuntimeError('RESP_bulk_bound')
            raw=self.stream.read(size+2)
            if len(raw)!=size+2 or not raw.endswith(b'\r\n'):raise RuntimeError('RESP_incomplete_bulk')
            return raw[:-2]
        if kind==b'*':
            size=int(content)
            if size==-1:return None
            if not 0<=size<=MAX_ITEMS:raise RuntimeError('RESP_array_bound')
            return [self.read(depth+1) for _ in range(size)]
        raise RuntimeError('RESP_unknown_type')
    def call(self,*values):
        raw=[v if isinstance(v,bytes) else str(v).encode() for v in values]
        encoded=b'*'+str(len(raw)).encode()+b'\r\n'+b''.join(b'$'+str(len(v)).encode()+b'\r\n'+v+b'\r\n' for v in raw)
        entry={'seq':len(commands)+1,'command':raw[0].decode(),'arguments_sha256':hashlib.sha256(encoded).hexdigest(),'start':time.monotonic()}
        commands.append(entry)
        try:
            self.sock.sendall(encoded)
            result=self.read()
            entry.update(end=time.monotonic(),response_received=True)
            return result
        except BaseException as exc:
            entry.update(end=time.monotonic(),response_received=False,error_type=type(exc).__name__)
            raise

def txt(value):
    if not isinstance(value,bytes):raise RuntimeError('RESP_expected_text')
    return value.decode('utf-8','strict')

def scan(conn,pattern):
    cursor=b'0';seen=set();found=set();pages=[]
    while True:
        cursor,keys=conn.call('SCAN',cursor,'MATCH',pattern,'COUNT',1000)
        pages.append({'cursor':txt(cursor),'count':len(keys)})
        found.update(keys)
        if cursor==b'0':break
        if cursor in seen or len(pages)>4096:raise RuntimeError('Redis_scan_not_complete')
        seen.add(cursor)
    return sorted(found),pages

def inspect_queue(conn):
    patterns={}
    for pat in ('queue:*','working:queue:*','*:work','reliable-fetcher-heartbeat-*'):
        keys,pages=scan(conn,pat);patterns[pat]={'keys':[txt(k) for k in keys],'scan':pages}
    names=conn.call('SMEMBERS','queues')
    queue_keys=set(k.encode() for k in patterns['queue:*']['keys'])|{b'queue:'+x for x in names}
    working_keys={k.encode() for k in patterns['working:queue:*']['keys']}
    sets=[];jobs=[]
    for key in sorted(queue_keys|working_keys|{b'retry',b'schedule',b'dead',b'interrupted'}):
        kind=txt(conn.call('TYPE',key))
        expected='list' if key.startswith((b'queue:',b'working:queue:')) else 'zset'
        if kind not in ('none',expected):raise RuntimeError('unexpected_queue_redis_type')
        if expected=='list':
            length=conn.call('LLEN',key);members=conn.call('LRANGE',key,0,-1)
            if len(members)!=length:raise RuntimeError('list_length_changed')
            entries=[(m,None) for m in members]
        else:
            length=conn.call('ZCARD',key);raw=conn.call('ZRANGE',key,0,-1,'WITHSCORES')
            if len(raw)!=length*2:raise RuntimeError('zset_length_changed')
            entries=list(zip(raw[0::2],map(txt,raw[1::2])))
        sets.append({'key':txt(key),'type':kind,'expected_type':expected,'length':length})
        for index,(raw,score) in enumerate(entries):
            item=json.loads(raw)
            if not isinstance(item,dict) or not isinstance(item.get('jid'),str):raise RuntimeError('queue_payload_schema')
            jobs.append({'key':txt(key),'type':expected,'index':index,'score':score,'jid':item['jid'],
                         'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_base64':base64.b64encode(raw).decode(),'item':item})
    process_names=conn.call('SMEMBERS','processes')
    processes=[]
    for key in sorted(process_names):
        raw=conn.call('HGETALL',key)
        if len(raw)%2:raise RuntimeError('process_hash_odd')
        processes.append({'identity':txt(key),'fields':{txt(k):txt(v) for k,v in zip(raw[0::2],raw[1::2])}})
    work_keys={k.encode() for k in patterns['*:work']['keys']}|{p+b':work' for p in process_names}
    work=[]
    for key in sorted(work_keys):
        kind=txt(conn.call('TYPE',key))
        if kind not in ('none','hash'):raise RuntimeError('work_hash_type')
        length=conn.call('HLEN',key);raw=conn.call('HGETALL',key)
        if len(raw)!=length*2:raise RuntimeError('work_hash_length_changed')
        for field,value in zip(raw[0::2],raw[1::2]):
            row=json.loads(value)
            work.append({'key':txt(key),'thread_id':txt(field),'raw_base64':base64.b64encode(value).decode(),
                         'raw_sha256':hashlib.sha256(value).hexdigest(),'value':row,
                         'process_indexed':key[:-5] in process_names})
    heartbeats=[]
    for key in patterns['reliable-fetcher-heartbeat-*']['keys']:
        raw=conn.call('GET',key)
        heartbeats.append({'key':key,'value_base64':base64.b64encode(raw).decode() if raw is not None else None})
    token_content={'jobs':[{k:j[k] for k in ('key','type','index','score','jid','raw_sha256')} for j in jobs],
                   'work':[{k:w[k] for k in ('key','thread_id','raw_sha256')} for w in work]}
    return {'sets':sets,'jobs':jobs,'work':work,'processes':processes,'heartbeats':heartbeats,
            'patterns':patterns,'registered_queues':sorted(txt(x) for x in names),
            'inventory_token':digest(token_content),'source_complete':True}

conn=Redis()
