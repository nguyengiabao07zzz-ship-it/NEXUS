"""Opt-in bounded polling; collects locally, never invokes AI."""
import copy
from datetime import datetime,timezone
import hashlib
import threading
from collections import OrderedDict
from .core import Invalid
from . import indexer


class Monitor:
    def __init__(self,config_path,analyses):
        self.config_path=config_path;self.analyses=analyses
        self.lock=threading.Lock();self.stop_event=threading.Event();self.thread=None
        self.current=None;self.seen=OrderedDict()
        self.state={'running':False,'cycles':0,'new_documents':0,'error_code':None,'automatic_ai':False}

    def start(self,query,interval=60):
        if not isinstance(query,dict) or set(query)-{'source','minutes','limit','agent_id'}:raise Invalid('Polling query không hợp lệ')
        if type(interval) is not int or not 30<=interval<=3600:raise Invalid('Chu kỳ polling từ 30–3600 giây')
        indexer.build_query(**query)
        with self.lock:
            if self.thread and self.thread.is_alive():raise Invalid('Polling đã chạy; dừng trước khi đổi truy vấn')
            self.seen.clear();self.current=None;self.stop_event.clear()
            self.state={'running':True,'cycles':0,'new_documents':0,'error_code':None,'interval':interval,
                        'query':copy.deepcopy(query),'automatic_ai':False,'max_session_hours':8}
            self.thread=threading.Thread(target=self._loop,args=(copy.deepcopy(query),interval),daemon=True)
            self.thread.start()
        return self.status()

    def cycle(self,query):
        try:
            result=indexer.collect(self.config_path,**query)
            result['snapshot_id']=self.analyses.remember(result)
            new=0
            with self.lock:
                for document in result['documents']:
                    identity=hashlib.sha256((document['index']+'\0'+document['id']).encode()).hexdigest()
                    if identity not in self.seen:new+=1
                    self.seen[identity]=None;self.seen.move_to_end(identity)
                while len(self.seen)>5000:self.seen.popitem(last=False)
                self.current=result
                self.state.update(last_read=datetime.now(timezone.utc).isoformat(),error_code=None,
                                  returned=result['returned'],total_matching=result['total_matching'],truncated=result['truncated'])
                self.state['cycles']+=1;self.state['new_documents']+=new
        except indexer.CollectionError as exc:
            with self.lock:self.state['error_code']=exc.code
        except Exception:
            with self.lock:self.state['error_code']='monitor_internal_error'

    def _loop(self,query,interval):
        import time
        end=time.monotonic()+8*3600
        try:
            while not self.stop_event.is_set() and time.monotonic()<end:
                self.cycle(query)
                if self.stop_event.wait(interval):break
        finally:
            with self.lock:self.state['running']=False

    def status(self):
        with self.lock:return copy.deepcopy(self.state)

    def latest(self):
        with self.lock:
            if self.current is None:raise Invalid('Polling chưa có lượt đọc thành công')
            return copy.deepcopy(self.current)

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=20)
        return self.status()
