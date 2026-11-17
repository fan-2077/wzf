require 'json'
require 'digest'
require 'base64'
require 'open3'
require 'socket'
require 'zlib'

module B0
  def self.emit(value)
    raw=JSON.generate(value, ascii_only: true)
    puts 'B0_RESULT_ZLIB:' + JSON.generate({'encoding'=>'zlib+base64','uncompressed_bytes'=>raw.bytesize,
      'uncompressed_sha256'=>Digest::SHA256.hexdigest(raw),
      'data_base64'=>Base64.strict_encode64(Zlib::Deflate.deflate(raw))},ascii_only:true)
  end

  def self.sha(value)
    Digest::SHA256.hexdigest(value)
  end

  def self.processes
    rows = []
    Dir.glob('/proc/[0-9]*/stat').sort.each do |path|
      begin
        pid = path.split('/')[2].to_i
        raw = File.binread(path)
        right = raw.rindex(')')
        fields = raw[(right + 2)..].split
        argv = File.binread("/proc/#{pid}/cmdline").split("\x00")
        # Never echo full argv: other application processes may contain credentials.
        first = argv.first.to_s
        executable = File.basename(first.split(' ').first.to_s)
        service = if first.match?(/\Asidekiq(?:\s|:|\z)/) || executable == 'sidekiq'
                    'sidekiq'
                  elsif first.match?(/\Apuma(?:\s|:|\z)/) || executable == 'puma'
                    'puma'
                  end
        if service.nil? && ['ruby', 'ruby3.2', 'ruby3.3', 'bundle'].include?(executable)
          candidate = argv[1].to_s
          service = 'sidekiq' if candidate.match?(%r{/(?:bin|exe)/sidekiq\z})
          service = 'puma' if candidate.match?(%r{/(?:bin|exe)/puma\z})
        end
        rows << {'pid'=>pid,'ppid'=>fields[1].to_i,'state'=>fields[0],
                 'starttime'=>fields[19],'cmdline_sha256'=>sha(argv.join("\x00")), 'service'=>service}
      rescue Errno::ENOENT, Errno::ESRCH
        # An enumerated process can exit before inspection; it is not fabricated as live.
        next
      end
    end
    rows
  end

  def self.service_status(service)
    out, err, status = Open3.capture3('/opt/gitlab/bin/gitlab-ctl', 'status', service)
    state = if out.match?(/\Arun: #{Regexp.escape(service)}:/)
              'run'
            elsif out.match?(/\Adown: #{Regexp.escape(service)}:/)
              'down'
            else
              'unknown'
            end
    pid = out[/\(pid ([0-9]+)\)/,1]
    {'service'=>service,'state'=>state,'pid'=>pid&.to_i,'exit_code'=>status.exitstatus,
     'stdout'=>out,'stderr'=>err}
  end

  def self.smtp_sockets
    rows = []
    ['/proc/net/tcp','/proc/net/tcp6'].each do |path|
      File.readlines(path).drop(1).each do |line|
        f = line.split
        remote = f[2].to_s
        next unless remote.split(':').last.to_s.to_i(16) == 1025
        rows << {'table'=>path,'local'=>f[1],'remote'=>remote,'state'=>f[3],'inode'=>f[9]}
      end
    end
    rows.sort_by { |r| [r['table'],r['local'],r['remote'],r['inode']] }
  end

  def self.stopped_services!
    statuses = ['puma','sidekiq'].map { |s| service_status(s) }
    live = processes.select { |p| p['service'] && p['state'] != 'Z' }
    raise 'writer_barrier_not_current' unless statuses.all? { |s| s['state']=='down' } && live.empty?
    {'statuses'=>statuses,'live_service_processes'=>live,'smtp_sockets'=>smtp_sockets}
  end

  def self.identity(r)
    issue = Issue.find_by(project_id: r.fetch('project'), iid: r.fetch('iid'))
    recipient = User.find_by(email: r.fetch('recipient'))
    result = {'project'=>r['project'],'iid'=>r['iid'],'recipient'=>r['recipient'],
              'issue_exists'=>!issue.nil?, 'recipient_exists'=>!recipient.nil?}
    if issue
      result.merge!('issue_id'=>issue.id,'title'=>issue.title,'description'=>issue.description.to_s,
                    'confidential'=>issue.confidential,'project_id'=>issue.project_id)
    end
    if recipient
      result.merge!('recipient_id'=>recipient.id,'recipient_active'=>recipient.active?)
    end
    result['allowed_read_issue'] = !!(issue && recipient && Ability.allowed?(recipient, :read_issue, issue))
    result['matches'] = !!(issue && recipient && recipient.active? && result['allowed_read_issue'] &&
      issue.title==r.fetch('title') && issue.description.to_s==r.fetch('description') &&
      issue.confidential==r.fetch('confidential'))
    result
  end
end

cfg = JSON.parse(ENV.fetch('B0_ARGUMENTS'))

# Fixed public supervision evidence. Loaded only by service-related bodies.
# No control command, signal, Redis request or application mail construction.
module B0
  SERVICE_SOURCE_FILES = {
    '/opt/gitlab/embedded/service/gitlab-rails/sidekiq_cluster/cli.rb'=>'67fe92f3596fbe0cbfd9b82a4150ac1443bc885316087aa87388097e43f09697',
    '/opt/gitlab/embedded/service/gitlab-rails/sidekiq_cluster/sidekiq_cluster.rb'=>'14236db6614fe36b179f5eac86b57457feca9e1e2344316763d23de52bb3e9a2',
    '/opt/gitlab/embedded/service/gitlab-rails/lib/gitlab/process_supervisor.rb'=>'12f2ca711d6093446f34712a15a278428bd70f4eb2dc299092745a3eb9bd7d40',
    '/opt/gitlab/embedded/service/gitlab-rails/lib/gitlab/process_management.rb'=>'9e0c860e6b95578ae087c13fe38ef3243472fbb8b74075261a47d8131bd0785e',
    '/opt/gitlab/embedded/service/gitlab-rails/metrics_server/metrics_server.rb'=>'024e8c21b4e4201794cc040244ced2295da22e7152caa2ab66b3b6d9d1284eeb'
  }.freeze

  def self.monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def self.clock_identity
    time_namespace=File.readlink('/proc/self/ns/time')
    raise 'active_and_children_time_namespaces_differ' unless time_namespace==File.readlink('/proc/self/ns/time_for_children')
    {'schema'=>'b0-monotonic-clock-identity-v1',
     'boot_id'=>File.read('/proc/sys/kernel/random/boot_id').strip,
     'time_namespace'=>time_namespace,
     'timens_offsets_sha256'=>sha(File.binread('/proc/self/timens_offsets'))}
  end

  def self.fs_identity(path)
    stat=File.stat(path)
    {'device'=>stat.dev,'inode'=>stat.ino}
  end

  def self.read_proc(pid)
    raw=File.binread("/proc/#{pid}/stat")
    right=raw.rindex(')')
    raise 'invalid_proc_stat' unless right && raw.start_with?("#{pid} (")
    fields=raw[(right+2)..].split
    raise 'short_proc_stat' unless fields.length>=20
    argv=File.binread("/proc/#{pid}/cmdline").split("\x00")
    first=argv.first.to_s
    executable=File.basename(first.split(' ').first.to_s)
    service=if first.match?(/\Asidekiq(?:\s|:|\z)/) || executable=='sidekiq'
      'sidekiq'
    elsif first.match?(/\Apuma(?:\s|:|\z)/) || executable=='puma'
      'puma'
    end
    if service.nil? && ['ruby','ruby3.2','ruby3.3','bundle'].include?(executable)
      candidate=argv[1].to_s
      service='sidekiq' if candidate.match?(%r{/(?:bin|exe)/sidekiq\z})
      service='puma' if candidate.match?(%r{/(?:bin|exe)/puma\z})
    end
    row={'pid'=>pid,'ppid'=>Integer(fields[1]),'pgrp'=>Integer(fields[2]),'session'=>Integer(fields[3]),
         'state'=>fields[0],'starttime'=>fields[19],'cmdline_sha256'=>sha(argv.join("\x00")),
         'service'=>service,'is_runsv'=>executable=='runsv'}
    if row['is_runsv']
      row['supervisor_cwd_identity']=fs_identity("/proc/#{pid}/cwd")
      row['supervisor_exe_identity']=fs_identity("/proc/#{pid}/exe")
      row['supervisor_exe_path']=File.readlink("/proc/#{pid}/exe")
    end
    after=File.binread("/proc/#{pid}/stat");last=after[(after.rindex(')')+2)..].split
    raise 'proc_identity_changed_during_read' unless last[19]==row['starttime']
    row
  end

  def self.process_snapshot
    attempts=[];result=nil
    3.times do
      start=monotonic
      before=Dir.children('/proc').select { |name|name.match?(/\A[0-9]+\z/) }.map(&:to_i).sort
      rows=[];vanished=[];errors=[]
      before.each do |pid|
        begin
          rows << read_proc(pid)
        rescue Errno::ENOENT,Errno::ESRCH
          vanished << pid
        rescue StandardError=>error
          errors << {'pid'=>pid,'class'=>error.class.name,'message'=>error.message}
        end
      end
      after=Dir.children('/proc').select { |name|name.match?(/\A[0-9]+\z/) }.map(&:to_i).sort
      missing=after-rows.map { |row|row['pid'] }
      result={'started_monotonic'=>start,'completed_monotonic'=>monotonic,
        'listed_before'=>before,'listed_after'=>after,'vanished_during_read'=>vanished,
        'unread_live_pids'=>missing,'errors'=>errors,'processes'=>rows,
        'source_complete'=>errors.empty? && missing.empty?}
      attempts << result.reject { |key,_|key=='processes' }
      break if result['source_complete']
    end
    result.merge('enumeration_attempts'=>attempts)
  end

  def self.processes
    result=process_snapshot
    raise 'complete_proc_snapshot_unavailable' unless result['source_complete']
    result['processes']
  end

  def self.service_source_contract(service)
    raise 'service_not_allowed' unless ['puma','sidekiq'].include?(service)
    manifest_raw=File.binread('/opt/gitlab/version-manifest.json')
    raise 'version_manifest_over_limit' if manifest_raw.bytesize>2097152
    manifest=JSON.parse(manifest_raw)
    raise 'actual_manifest_format_unqualified' unless manifest['manifest_format']==2
    runit_entry=manifest.fetch('software').fetch('runit')
    raise 'actual_runit_manifest_entry_not_object' unless runit_entry.is_a?(Hash)
    runit_versions=['locked_version','described_version','display_version'].to_h { |key|[key,runit_entry.fetch(key)] }
    raise 'actual_runit_version_unqualified' unless runit_versions.values.all? { |value|value=='2.1.2' }
    source_sha=runit_entry.fetch('locked_source').fetch('sha256')
    raise 'actual_runit_source_pin_unqualified' unless runit_entry['source_type']=='url' &&
      source_sha=='6fd0160cb0cf1207de4e66754b6d39750cff14bb0aa66ab49490992c0c47ba18'
    runit='2.1.2'
    sources=SERVICE_SOURCE_FILES.map do |path,expected|
      raw=File.binread(path);actual=sha(raw)
      raise 'actual_service_model_source_changed' unless actual==expected
      {'path'=>path,'bytes'=>raw.bytesize,'sha256'=>actual}
    end
    {
      '/opt/gitlab/embedded/lib/ruby/gems/*/gems/puma-7.2.0/lib/puma/cluster.rb'=>'e4beaf3fc6894583ead8bd4e42dde1cec525037c872511b76dad76e933e4076d',
      '/opt/gitlab/embedded/lib/ruby/gems/*/gems/omnibus-ctl-0.6.12/lib/omnibus-ctl.rb'=>'50d421e29a29c0671217772556cc542b91b95f0dfe365015e05ce008b96e2bfc'
    }.each do |pattern,expected|
      paths=Dir.glob(pattern)
      raise 'actual_service_model_source_not_unique' unless paths.length==1
      raw=File.binread(paths.first)
      raise 'actual_service_model_source_changed' unless sha(raw)==expected
      sources << {'path'=>paths.first,'bytes'=>raw.bytesize,'sha256'=>sha(raw)}
    end
    template='/opt/gitlab/embedded/cookbooks/gitlab/templates/default/sv-'+service+'-run.erb'
    expected_template={'puma'=>'a414f5b6c2709e0ca8ee4faffb9117de41ed9d35aa4967873f04c2382475c235',
      'sidekiq'=>'861fc54c66d6333a1f69693868d5e0dcaf65d5588a66cf73f6c956b8ffb070d4'}.fetch(service)
    template_raw=File.binread(template)
    raise 'actual_service_run_template_changed' unless sha(template_raw)==expected_template
    run=File.binread('/opt/gitlab/service/'+service+'/run')
    raise 'generated_service_run_over_limit' if run.bytesize>131072
    commands=run.gsub(/\\\r?\n/,' ').lines.reject { |line|line.lstrip.start_with?('#') }
    launch=commands.select { |line|line.match?(/\Aexec chpst\s/) }
    expected_exec=service=='sidekiq' ? '/opt/gitlab/embedded/service/gitlab-rails/bin/sidekiq-cluster' : '/opt/gitlab/embedded/bin/bundle exec puma -C '
    raise 'actual_chpst_session_launch_not_present' unless launch.length==1 && launch.first.split.include?('-P') && launch.first.include?(expected_exec)
    service_dir='/opt/gitlab/service/'+service
    raise 'unexpected_service_finish_or_up_hook' if File.exist?(service_dir+'/finish') || File.exist?(service_dir+'/control/u')
    control_t=nil
    if service=='puma'
      expected_control="#!/bin/sh\necho \"Received TERM from runit, sending to process group (-PID)\"\nkill -- -$(cat /opt/gitlab/service/puma/supervise/pid)\n"
      control_t=File.binread(service_dir+'/control/t')
      raise 'actual_puma_TERM_hook_changed' unless control_t==expected_control
    else
      raise 'unexpected_sidekiq_TERM_hook' if File.exist?(service_dir+'/control/t')
    end
    init=File.realpath('/opt/gitlab/init/'+service)
    raise 'actual_init_not_fixed_sv' unless init==File.realpath('/opt/gitlab/embedded/bin/sv')
    binaries=['sv','runsv','chpst'].map do |name|
      path='/opt/gitlab/embedded/bin/'+name
      {'path'=>path,'sha256'=>sha(File.binread(path)),'identity'=>fs_identity(path)}
    end
    {'schema'=>'b0-fixed-service-source-contract-v1','qualified'=>true,'runit_version'=>runit,
      'version_manifest_sha256'=>sha(manifest_raw),'actual_manifest_format'=>2,
      'actual_runit_manifest_version_fields'=>runit_versions,'runit_locked_source_sha256'=>source_sha,'source_files'=>sources,
      'template'=>{'path'=>template,'sha256'=>sha(template_raw)},
      'generated_run'=>{'bytes'=>run.bytesize,'sha256'=>sha(run),'data_base64'=>Base64.strict_encode64(run)},
      'finish_and_up_hooks_absent'=>true,'TERM_hook_sha256'=>control_t && sha(control_t),
      'init_realpath'=>init,'binaries'=>binaries,
      'generated_run_check_scope'=>'fixed package template and single chpst -P launch anchor; actual SID checked separately',
      'finite_model'=>'fresh pinned application; no other controller; fixed child spawn sources; no arbitrary escaping daemon'}
  end

  def self.supervision_snapshot(service)
    path='/opt/gitlab/service/'+service
    actual=File.realpath(path)
    raise 'unexpected_service_directory' unless actual=='/opt/gitlab/sv/'+service
    directory=fs_identity(path);supervise=fs_identity(path+'/supervise')
    raw=File.binread(path+'/supervise/status')
    raise 'runit_status_not_twenty_bytes' unless raw.bytesize==20
    snapshot=process_snapshot
    after=File.binread(path+'/supervise/status')
    supervisors=snapshot['processes'].select do |row|
      row['is_runsv'] && row['state']!='Z' && row['supervisor_cwd_identity']==directory &&
        row['supervisor_exe_identity']==fs_identity('/opt/gitlab/embedded/bin/runsv')
    end
    pid=raw.byteslice(12,4).unpack1('V');desired=raw.getbyte(17);code=raw.getbyte(19)
    state={0=>'down',1=>'run',2=>'finish'}[code] || 'unknown'
    supervisor=supervisors.length==1 ? supervisors.first : nil
    stable=raw==after && directory==fs_identity(path) && supervise==fs_identity(path+'/supervise')
    main=snapshot['processes'].find { |row|row['pid']==pid && row['state']!='Z' } if pid>0
    qualified=stable && snapshot['source_complete'] && supervisor && [100,117].include?(desired) &&
      [0,1,2].include?(code) && (pid==0 || (main && main['ppid']==supervisor['pid']))
    row={'service'=>service,'state'=>state,'pid'=>pid,'state_code'=>code,
      'desired_byte'=>desired,'desired_not_up'=>desired==100,'raw_status_base64'=>Base64.strict_encode64(raw),
      'raw_status_sha256'=>sha(raw),'status_stable_during_snapshot'=>stable,
      'directory'=>{'path'=>actual,'identity'=>directory,'supervise_identity'=>supervise},
      'supervisor'=>supervisor,'main_process'=>main,'qualified'=>!!qualified,
      'status_semantics'=>'runit 2.1.2; byte17 d represents not-W_UP, not a unique W_DOWN claim'}
    {'status'=>row,'process_snapshot'=>snapshot}
  end

  def self.service_status(service)
    supervision_snapshot(service).fetch('status')
  end

  def self.same_process(a,b)
    a && b && a['pid']==b['pid'] && a['starttime']==b['starttime']
  end

  def self.same_supervision(a,b)
    a['directory']==b['directory'] && same_process(a['supervisor'],b['supervisor']) &&
      a['supervisor']['supervisor_exe_identity']==b['supervisor']['supervisor_exe_identity']
  end

  def self.stopped_services!
    snapshots=['puma','sidekiq'].map { |service|supervision_snapshot(service) }
    statuses=snapshots.map { |entry|entry['status'] }
    snapshot=process_snapshot
    live=snapshot['processes'].select { |row|row['service'] && row['state']!='Z' }
    stopped=statuses.all? { |row|row['qualified'] && row['state']=='down' && row['pid']==0 && row['state_code']==0 && row['desired_not_up'] }
    raise 'writer_barrier_not_current' unless snapshot['source_complete'] && live.empty? && stopped
    {'statuses'=>statuses,'process_snapshot'=>snapshot,'live_service_processes'=>live,
     'smtp_sockets'=>smtp_sockets,'historical_smtp_terminal_claimed'=>false,
     'prior_stop_session_certificate_required_by_common_facade'=>true}
  end
end

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
