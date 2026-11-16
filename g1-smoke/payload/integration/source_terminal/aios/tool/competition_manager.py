"""Trusted access declarations for the two local validation services."""
import re
from aios.scheduler.competition_extension import SafeToolManager,ToolPolicyRegistry,ToolAccess

TRAFFIC_READS={'get_snapshot','assess_incident','assess_network_impact','evaluate_signal_options','evaluate_route_options','rollout_joint_plan','verify'}

def traffic_access(params):
    op=params.get('operation')
    if not isinstance(params.get('arguments',{}),dict):raise ValueError('arguments must be object')
    if op in TRAFFIC_READS:return ToolAccess(reads=('snapshot:traffic-fixed-case',))
    if op=='submit_plan':return ToolAccess(writes=('world:traffic-fixed-case',))
    raise ValueError('Unregistered traffic operation')

def warehouse_access(params):
    session=params.get('case_session')
    if not isinstance(session,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',session):raise ValueError('Invalid case_session')
    op=params.get('operation')
    if op in {'snapshot','verify'}:return ToolAccess(reads=('world:warehouse:'+session,))
    if op=='evaluate_schedule':return ToolAccess(reads=('snapshot:warehouse:'+session,))
    if op=='submit':return ToolAccess(writes=('world:warehouse:'+session,))
    raise ValueError('Unregistered warehouse operation')

class CompetitionToolManager(SafeToolManager):
    def __init__(self,log_mode='console'):
        super().__init__(log_mode=log_mode,policy_registry=ToolPolicyRegistry({'competition_round3/traffic_ops':traffic_access,'competition_round3/warehouse_ops':warehouse_access}))
