require 'json'
require 'digest'
require 'base64'
require 'open3'
require 'socket'

module B0
  def self.emit(value)
    puts 'B0_RESULT:' + JSON.generate(value, ascii_only: true)
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

service, verb = cfg.fetch('service'), cfg.fetch('verb')
raise 'service_not_allowed' unless ['sidekiq','puma'].include?(service)
raise 'verb_not_allowed' unless ['stop','start'].include?(verb)
before_status=B0.service_status(service)
before=B0.processes
root_pids=before.select { |p| p['service']==service }.map { |p| p['pid'] }
root_pids << before_status['pid'] if before_status['pid']
loop do
  found=before.select { |p| root_pids.include?(p['ppid']) }.map { |p| p['pid'] }
  expanded=(root_pids+found).uniq
  break if expanded==root_pids
  root_pids=expanded
end
owned=before.select { |p| root_pids.include?(p['pid']) }
sockets_before=B0.smtp_sockets
log_paths = service=='sidekiq' ? ['/var/log/gitlab/sidekiq/current','/var/log/gitlab/sidekiq/sidekiq.log'] : []
log_before=log_paths.filter_map do |path|
  next unless File.file?(path)
  stat=File.stat(path)
  {'path'=>path,'inode'=>stat.ino,'size'=>stat.size}
end
out,err,status=Open3.capture3('/opt/gitlab/bin/gitlab-ctl',verb,service)
after_status=B0.service_status(service)
after=B0.processes
same_owned=after.select { |p| owned.any? { |old| old['pid']==p['pid'] && old['starttime']==p['starttime'] } && p['state']!='Z' }
live=after.select { |p| p['service']==service && p['state']!='Z' }
log_after=log_before.map do |entry|
  stat=File.stat(entry['path'])
  same=stat.ino==entry['inode'] && stat.size>=entry['size']
  raw=''
  if same
    File.open(entry['path'],'rb') { |f| f.seek(entry['size']);raw=f.read(1048577) || '' }
  end
  {'path'=>entry['path'],'inode'=>stat.ino,'before_size'=>entry['size'],'after_size'=>stat.size,
   'same_file'=>same,'complete'=>same && raw.bytesize<=1048576,
   'data_base64'=>Base64.strict_encode64(raw),'sha256'=>B0.sha(raw)}
end
ok=status.success? && if verb=='stop'
  after_status['state']=='down' && same_owned.empty? && live.empty?
else
  after_status['state']=='run' && after_status['pid'] && after.any? { |p|p['pid']==after_status['pid'] && p['state']!='Z'}
end
B0.emit({'kind'=>'service_control','service'=>service,'verb'=>verb,'command_exit'=>status.exitstatus,
         'stdout'=>out,'stderr'=>err,'before_status'=>before_status,'after_status'=>after_status,
         'owned_processes_before'=>owned,'same_owned_live_after'=>same_owned,'service_live_after'=>live,
         'smtp_sockets_before'=>sockets_before,'smtp_sockets_after'=>B0.smtp_sockets,
         'shutdown_logs'=>log_after,'service_effect_verified'=>!!ok})
