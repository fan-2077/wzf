contracts=['puma','sidekiq'].map { |service| [service,B0.service_source_contract(service)] }.to_h
snapshots=['puma','sidekiq'].map { |service| B0.supervision_snapshot(service) }
statuses=snapshots.map { |snapshot|snapshot['status'] }
snapshot=B0.process_snapshot
processes=snapshot['processes']
B0.emit({'kind'=>'service_inventory','statuses'=>statuses,
  'processes'=>processes,'process_snapshot'=>snapshot,'supervision_snapshots'=>snapshots,
  'source_contracts'=>contracts,'smtp_sockets'=>B0.smtp_sockets,
  'writers_stopped'=>statuses.all? { |row|row['qualified'] && row['state_code']==0 && row['pid']==0 && row['desired_not_up'] } &&
    processes.none? { |row|row['service'] && row['state']!='Z' },
  'source_complete'=>snapshot['source_complete'] && snapshots.all? { |entry|entry['status']['qualified'] },
  'prior_stop_session_certificate_required_by_common_facade'=>true,'historical_smtp_terminal_claimed'=>false})
