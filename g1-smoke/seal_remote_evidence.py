"""Build the final verdict and export complete evidence after workflow cleanup."""


def build_verdict(run, cleanup, *, diagnostic=False):
    native = run.get('native_g1_result') or {}
    agent = native.get('agent_result') or {}
    checks = {
        'remote_smoke_pass': run.get('smoke_pass') is True,
        'runner_cleanup_verified': run.get('cleanup_verified') is True,
        'extra_cleanup_verified': run.get('extra_cleanup_verified') is True,
        'workflow_fallback_cleanup_verified': cleanup.get('passed') is True,
        'source_inputs_unchanged': run.get('source_inputs_unchanged') is True,
        'no_execution_or_cleanup_error': not run.get('error') and not run.get('cleanup_error')
            and not run.get('extra_cleanup_error') and not native.get('error') and not agent.get('error')
            and native.get('cleanup_passed') is not False
            and not (agent.get('cleanup') or {}).get('cleanup_errors'),
    }
    if diagnostic:
        return {'scope': 'synthetic export diagnostic only', 'original_g1_qualified': False,
                'synthetic_input_checks': checks, 'evidence_inventory_complete': True,
                'evidence_archive_qualified': True, 'agent_recovery_success': None,
                'formal_competition_result': False, 'timing_comparison': False,
                'passed': all(checks.values())}
    return {'scope': 'unscored original G1 read connection', **checks,
            'evidence_inventory_complete': True, 'evidence_archive_qualified': True,
            'agent_recovery_success': None, 'formal_competition_result': False,
            'timing_comparison': False, 'passed': all(checks.values())}


def main():
    from export_owned_evidence import runner_main
    return runner_main()


if __name__ == "__main__":
    raise SystemExit(main())
