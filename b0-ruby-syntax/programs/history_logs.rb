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

require 'zlib'
require 'stringio'
ids=cfg.fetch('job_ids')
raise 'invalid_job_ids' unless ids.is_a?(Array) && ids.all? { |x|x.is_a?(String) && x.match?(/\A[A-Za-z0-9_-]{1,128}\z/) }
files=[];matched=[];unparsed=[];total=0
log_names = lambda do
  Dir.children('/var/log/gitlab/sidekiq').select { |name| name=='current' || name.match?(/\A(?:sidekiq\.log(?:\.[0-9]+)?(?:\.gz)?|@[a-fA-F0-9]+\.[su])\z/) }.sort
end
names_before=log_names.call
names_before.each do |name|
  path='/var/log/gitlab/sidekiq/'+name
  next unless File.file?(path)
  raise 'log_symlink' if File.symlink?(path)
  stat=File.stat(path)
  raise 'log_file_over_limit' if stat.size>33554432
  blob=File.binread(path)
  total+=blob.bytesize
  raise 'logs_total_over_limit' if total>134217728
  raw=name.end_with?('.gz') ? Zlib::GzipReader.wrap(StringIO.new(blob), &:read) : blob
  raise 'log_expanded_over_limit' if raw.bytesize>67108864
  count=0
  raw.each_line do |line|
    count+=1
    selected=ids.any? { |id| line.include?(id) }
    lifecycle=line.match?(/(?:Starting processing|Booting Sidekiq|Sidekiq.*version|Pausing to allow|Terminating busy|hard.shutdown|All threads stopped|Bye!|Shutting down|Stopping quiet|job_status)/)
    next unless selected || lifecycle
    pos=line.index('{')
    begin
      row=pos ? JSON.parse(line[pos..]) : nil
    rescue JSON::ParserError
      row=nil
    end
    item={'file'=>name,'line'=>count,'line_sha256'=>B0.sha(line),'selected_job'=>selected,'lifecycle'=>lifecycle,'row'=>row}
    if row
      # Fields are public application job/lifecycle logs. No credentials are read.
      matched << item
    else
      item['raw_base64']=Base64.strict_encode64(line)
      unparsed << item
    end
  end
  after=File.stat(path)
  files << {'name'=>name,'inode'=>stat.ino,'bytes'=>stat.size,'mtime_ns'=>stat.mtime.nsec,
            'sha256'=>B0.sha(blob),'capture_encoding'=>'zlib+base64',
            'capture_zlib_base64'=>Base64.strict_encode64(Zlib::Deflate.deflate(blob)),
            'lines'=>count,'unchanged_during_read'=>after.ino==stat.ino && after.size==stat.size && after.mtime==stat.mtime}
end
names_after=log_names.call
B0.emit({'kind'=>'history_logs','names_before'=>names_before,'names_after'=>names_after,'files'=>files,'matching_records'=>matched,'unparsed_selected'=>unparsed,
         'source_complete'=>!files.empty? && names_before==names_after && files.map { |f|f['name'] }==names_before && files.all? { |f|f['unchanged_during_read'] },'requested_job_ids'=>ids,
         'total_bytes'=>total,'historical_terminal_claimed'=>false})
