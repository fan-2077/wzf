service, verb = cfg.fetch('service'), cfg.fetch('verb')
raise 'service_not_allowed' unless ['sidekiq','puma'].include?(service)
raise 'verb_not_allowed' unless ['stop','start'].include?(verb)
action_started=B0.monotonic
clock=B0.clock_identity
deadline=nil
if verb=='stop'
  deadline=cfg.fetch('deadline_monotonic')
  raise 'stop_deadline_invalid' unless deadline.is_a?(Numeric) && deadline.finite? &&
    deadline>action_started && deadline<=action_started+120.0
  raise 'target_monotonic_clock_not_bound' unless cfg.fetch('clock_identity')==clock
end
source_contract=B0.service_source_contract(service)
pre_control_observations=[]
scope_for=lambda do |snapshot|
  status=snapshot['status'];rows=snapshot['process_snapshot']['processes'];main=status['main_process']
  next nil unless status['qualified'] && status['state']=='run' && main &&
    main['pid']==main['session'] && main['session']!=status['supervisor']['session'] && main['session']!=Process.getsid(0)
  sid=main['session']
  selected=rows.select { |row|row['session']==sid || row['service']==service || B0.same_process(row,main) }
  loop do
    parents=selected.map { |row|row['pid'] }
    extra=rows.select { |row|parents.include?(row['ppid']) && !selected.any? { |old|B0.same_process(old,row) } }
    break if extra.empty?
    selected+=extra
  end
  next nil unless selected.all? { |row|row['state']=='Z' || row['session']==sid }
  {'root'=>main,'session'=>sid,'owned'=>selected}
end
initial=nil;scope=nil
if verb=='stop'
  previous_candidate=nil
  loop do
    break if B0.monotonic>=deadline
    raise 'target_monotonic_clock_changed_before_stop' unless B0.clock_identity==clock
    sampled_started=B0.monotonic
    candidate=B0.supervision_snapshot(service);candidate_scope=scope_for.call(candidate)
    pre_control_observations << {'started_monotonic'=>sampled_started,'completed_monotonic'=>B0.monotonic,
      'supervision'=>candidate,'running_session_scope_qualified'=>!candidate_scope.nil?}
    if candidate_scope && previous_candidate &&
        B0.same_supervision(previous_candidate['status'],candidate['status']) &&
        B0.same_process(previous_candidate['status']['main_process'],candidate['status']['main_process'])
      initial=candidate;scope=candidate_scope;break
    end
    previous_candidate=candidate_scope ? candidate : nil
    remaining=deadline-B0.monotonic
    sleep [0.25,remaining].min if remaining>0
  end
  unless initial && B0.monotonic<deadline
    B0.emit({'kind'=>'service_control','service'=>service,'verb'=>verb,'service_effect_verified'=>false,
      'command_dispatch_count'=>0,'pre_control_observations'=>pre_control_observations,
      'source_contract'=>source_contract,'clock_identity'=>clock,'deadline_monotonic'=>deadline,
      'stopping_reason'=>'no_stable_running_session_scope_within_original_budget',
      'historical_smtp_terminal_claimed'=>false})
    exit 0
  end
else
  initial=B0.supervision_snapshot(service)
  raise 'initial_service_supervision_unqualified' unless initial['status']['qualified']
end
before_status=initial['status'];before=initial['process_snapshot']['processes']
root=scope && scope['root'];session=scope && scope['session'];owned=scope ? scope['owned'] : []
sockets_before=B0.smtp_sockets
log_paths=service=='sidekiq' ? ['/var/log/gitlab/sidekiq/current','/var/log/gitlab/sidekiq/sidekiq.log'] : []
log_before=log_paths.filter_map do |path|
  next unless File.file?(path)
  stat=File.stat(path);{'path'=>path,'inode'=>stat.ino,'size'=>stat.size}
end
command_started=B0.monotonic
out=err=nil;status=nil;command_pid=nil;command_starttime=nil
# Exactly one control invocation. wait_thread.value reaps this original child;
# the fixed omnibus-ctl synchronously waits for its one per-service sv child.
Open3.popen3('/opt/gitlab/bin/gitlab-ctl',verb,service) do |stdin,stdout,stderr,wait_thread|
  stdin.close
  command_pid=wait_thread.pid
  begin
    command_starttime=B0.read_proc(command_pid)['starttime']
  rescue Errno::ENOENT,Errno::ESRCH
    command_starttime=nil
  end
  output_reader=Thread.new { stdout.binmode.read }
  error_reader=Thread.new { stderr.binmode.read }
  status=wait_thread.value
  out=output_reader.value;err=error_reader.value
end
command_completed=B0.monotonic
command={'dispatch_count'=>1,'pid'=>command_pid,'starttime'=>command_starttime,
  'started_monotonic'=>command_started,'completed_monotonic'=>command_completed,'wait_reaped'=>true,
  'exit_code'=>status.exitstatus,'termsig'=>status.termsig,
  'stdout_bytes'=>out.bytesize,'stdout_sha256'=>B0.sha(out),'stdout_base64'=>Base64.strict_encode64(out),
  'stderr_bytes'=>err.bytesize,'stderr_sha256'=>B0.sha(err),'stderr_base64'=>Base64.strict_encode64(err)}
observations=[];tracked=owned.dup;sticky_gaps=[];verified=false;final=nil;observation_error=nil
begin
loop do
  # Reaching this loop never issues another stop, signal, or state-changing call.
  sample_started=B0.monotonic
  break if verb=='stop' && sample_started>=deadline
  snapshot=B0.supervision_snapshot(service)
  after_status=snapshot['status'];process_snapshot=snapshot['process_snapshot'];rows=process_snapshot['processes']
  same_supervisor=B0.same_supervision(before_status,after_status)
  same_clock=B0.clock_identity==clock
  sticky_gaps << 'supervisor_replaced_or_directory_changed' unless same_supervisor
  sticky_gaps << 'clock_identity_changed' unless same_clock
  if verb=='stop'
    if after_status['pid']>0 && after_status['pid']!=root['pid']
      sticky_gaps << 'new_service_root_outside_initial_session_scope'
    end
    loop do
      parents=rows.select { |row|tracked.any? { |old|B0.same_process(old,row) } }.map { |row|row['pid'] }
      extra=rows.select do |row|
        (parents.include?(row['ppid']) || row['session']==session) && !tracked.any? { |old|B0.same_process(old,row) }
      end
      break if extra.empty?
      tracked+=extra
    end
    escaped=rows.select { |row|row['state']!='Z' && row['session']!=session && tracked.any? { |old|B0.same_process(old,row) } }
    sticky_gaps << 'observed_owned_process_escaped_session' unless escaped.empty?
  end
  same_owned=rows.select { |row|row['state']!='Z' && tracked.any? { |old|B0.same_process(old,row) } }
  live=rows.select { |row|row['service']==service && row['state']!='Z' }
  session_live=verb=='stop' ? rows.select { |row|row['session']==session && row['state']!='Z' } : []
  sample_completed=B0.monotonic
  verified=if verb=='stop'
    after_status['qualified'] && after_status['pid']==0 && after_status['state_code']==0 &&
      after_status['desired_not_up'] && process_snapshot['source_complete'] &&
      same_owned.empty? && live.empty? && session_live.empty? && sticky_gaps.empty? && sample_completed<=deadline
  else
    status.success? && after_status['qualified'] && after_status['state']=='run' && after_status['pid']>0 &&
      after_status['main_process'] && process_snapshot['source_complete'] && same_supervisor && same_clock
  end
  final={'started_monotonic'=>sample_started,'completed_monotonic'=>sample_completed,
    'status'=>after_status,'process_snapshot'=>process_snapshot,'same_supervisor'=>same_supervisor,
    'same_clock_identity'=>same_clock,'same_owned_live'=>same_owned,'service_live'=>live,
    'session_live'=>session_live,'postcondition_satisfied'=>!!verified}
  observations << final
  break if verified || verb=='start' || !sticky_gaps.empty?
  remaining=deadline-B0.monotonic
  break if remaining<=0
  sleep [1.0,remaining].min
end
rescue StandardError=>error
  observation_error={'class'=>error.class.name,'message'=>error.message}
  sticky_gaps << 'readonly_observation_failed'
  verified=false
end
source_unchanged=false
begin
  final_source=B0.service_source_contract(service)
  source_unchanged=final_source==source_contract
rescue StandardError=>error
  observation_error={'class'=>error.class.name,'message'=>error.message}
  sticky_gaps << 'final_source_contract_unavailable'
end
verified=false unless source_unchanged
log_after=log_before.map do |entry|
  begin
    stat=File.stat(entry['path']);same=stat.ino==entry['inode'] && stat.size>=entry['size'];raw=''
    File.open(entry['path'],'rb') { |file|file.seek(entry['size']);raw=file.read(1048577) || '' } if same
    {'path'=>entry['path'],'inode'=>stat.ino,'before_size'=>entry['size'],'after_size'=>stat.size,
     'same_file'=>same,'complete'=>same && raw.bytesize<=1048576,
     'data_base64'=>Base64.strict_encode64(raw),'sha256'=>B0.sha(raw)}
  rescue Errno::ENOENT,Errno::ESRCH
    {'path'=>entry['path'],'same_file'=>false,'complete'=>false,'missing_after'=>true}
  end
end
B0.emit({'kind'=>'service_control','service'=>service,'verb'=>verb,'command_exit'=>status.exitstatus,
  'command'=>command,'before_status'=>before_status,'after_status'=>final && final['status'],
  'initial_process_snapshot'=>initial['process_snapshot'],'owned_processes_before'=>owned,
  'pre_control_observations'=>pre_control_observations,
  'same_owned_live_after'=>final && final['same_owned_live'],'service_live_after'=>final && final['service_live'],
  'session_live_after'=>final && final['session_live'],'tracked_processes'=>tracked,
  'session_scope'=>session,'session_scope_qualified'=>verb=='stop' && !!session,
  'source_contract'=>source_contract,'source_contract_unchanged'=>source_unchanged,
  'clock_identity'=>clock,'deadline_monotonic'=>deadline,'fixed_observation_budget_seconds'=>120,
  'observations'=>observations,'sticky_gaps'=>sticky_gaps.uniq,'observation_error'=>observation_error,
  'action_started_monotonic'=>action_started,'action_completed_monotonic'=>B0.monotonic,
  'smtp_sockets_before'=>sockets_before,'smtp_sockets_after'=>B0.smtp_sockets,'shutdown_logs'=>log_after,
  'service_effect_verified'=>!!verified,'historical_smtp_terminal_claimed'=>false,
  'effect_basis'=>verb=='stop' ? 'one_control_dispatch_then_complete_finite_supervision_and_process_postcondition' : 'successful_start_and_live_actual_supervised_process'})
