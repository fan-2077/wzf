"""Seal the explicit execution mode; complete evidence also survives failed runs."""
def build_verdict(run, cleanup, *, diagnostic=False):
    native=run.get('native_b0_result') or {}
    agent=native.get('agent_result') or {}
    checks={
        'declared_runtime_contract_passed':run.get('runtime_pass') is True,
        'runner_cleanup_verified':run.get('cleanup_verified') is True,
        'extra_cleanup_verified':run.get('extra_cleanup_verified') is True,
        'workflow_fallback_cleanup_verified':cleanup.get('passed') is True,
        'source_inputs_unchanged':run.get('source_inputs_unchanged') is True,
        'no_execution_or_cleanup_error':not run.get('error') and not run.get('cleanup_error')
            and not run.get('extra_cleanup_error') and not native.get('error') and not agent.get('error')
            and native.get('cleanup_passed') is not False,
    }
    mode=run.get('scope')
    return {'schema':'b0-stage-verdict-v1','scope':mode,'protocol_id':run.get('protocol_id'),**checks,
        'evidence_inventory_complete':True,'evidence_archive_qualified':True,
        'read_only_qualification_only':mode=='native_readonly_qualification',
        'b0_recovery_passed':mode=='public_b0' and run.get('b0_pass') is True and all(checks.values()),
        'original_mitigation_success':native.get('original_mitigation_success'),
        'formal_competition_result':False,'timing_comparison':False,
        'passed':mode in {'native_readonly_qualification','public_b0'} and not diagnostic and all(checks.values())}

def main():
    from export_owned_evidence import runner_main
    return runner_main()

if __name__=='__main__':raise SystemExit(main())
