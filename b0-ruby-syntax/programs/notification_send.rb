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

require 'net/smtp'
require 'mail'

# A common instrumentation guard is installed around the actual loaded stack.
# It records every SMTP session and refuses a second DATA body within one
# application invocation before that body can be submitted. This same rule is
# available to every comparison arm, not a B0-only transport replacement.
module B0SMTP
  class ImplicitDataRetryForbidden < StandardError; end
  class ContractMismatch < StandardError; end
  class << self
    attr_accessor :events, :sessions, :owner, :intent, :data_entries, :allowed_data_entries, :io_map
  end
  self.events=[]
  self.sessions=[]
  self.owner=Thread.current.object_id
  self.data_entries=0
  self.allowed_data_entries=0
  self.io_map={}

  def self.event(kind, details={})
    raise ContractMismatch,'unexpected_smtp_thread' unless Thread.current.object_id==owner
    raise ContractMismatch,'smtp_trace_bound' if events.length>=4096
    events << {'sequence'=>events.length+1,'event'=>kind,'monotonic'=>Process.clock_gettime(Process::CLOCK_MONOTONIC),**details}
  end

  def self.verify_message(message)
    r=intent
    raise ContractMismatch,'notification_envelope_recipient' unless message.to==[r.fetch('recipient')]
    checks={
      'X-GitLab-NotificationReason'=>r.fetch('reason'),
      'X-GitLab-Project-Id'=>r.fetch('project').to_s,
      'X-GitLab-Issue-Iid'=>r.fetch('iid').to_s
    }
    checks.each do |key,value|
      raise ContractMismatch,'notification_header_mismatch' unless message[key]&.value.to_s==value
    end
    raise ContractMismatch,'notification_subject_mismatch' unless message.subject.to_s.include?(r.fetch('title'))
  end

  def self.session(smtp)
    value=smtp.instance_variable_get(:@b0_session)
    return value if value
    value={'session_id'=>sessions.length+1,'object_id'=>smtp.object_id,'sockets'=>[]}
    sessions << value
    smtp.instance_variable_set(:@b0_session,value)
    value
  end
end

module B0SMTPObserver
  def tcp_socket(address,port)
    session=B0SMTP.session(self)
    raise B0SMTP::ContractMismatch,'smtp_destination_mismatch' unless address=='notification-mailbox' && port==1025
    B0SMTP.event('tcp_connect_start',{'session_id'=>session['session_id'],'address'=>address,'port'=>port})
    sock=super
    session['sockets'] << sock
    B0SMTP.event('tcp_connected',{'session_id'=>session['session_id'],
      'peer'=>sock.peeraddr,'local'=>sock.addr,'socket_inode'=>File.readlink("/proc/self/fd/#{sock.fileno}")})
    sock
  rescue StandardError => e
    B0SMTP.event('tcp_connect_error',{'session_id'=>session && session['session_id'],'error_type'=>e.class.name})
    raise
  end

  def new_internet_message_io(socket)
    io=super
    session=B0SMTP.session(self)
    B0SMTP.io_map[io.object_id]=self
    B0SMTP.event('message_io_bound',{'session_id'=>session['session_id'],'io_object_id'=>io.object_id})
    io
  end

  def do_start(*args,**kwargs)
    session=B0SMTP.session(self)
    B0SMTP.event('smtp_start',{'session_id'=>session['session_id']})
    super
  rescue StandardError => e
    B0SMTP.event('smtp_start_error',{'session_id'=>session['session_id'],'error_type'=>e.class.name})
    raise
  end

  def data(msgstr=nil,&block)
    session=B0SMTP.session(self)
    B0SMTP.data_entries+=1
    B0SMTP.event('data_method_entry',{'session_id'=>session['session_id'],'entry_number'=>B0SMTP.data_entries})
    if B0SMTP.allowed_data_entries>=1
      B0SMTP.event('implicit_data_retry_refused',{'session_id'=>session['session_id']})
      raise B0SMTP::ImplicitDataRetryForbidden,'one_data_submission_per_registered_action'
    end
    raise B0SMTP::ContractMismatch,'only_encoded_message_data_is_qualified' unless msgstr.is_a?(String) && !block
    B0SMTP.verify_message(Mail.read_from_string(msgstr))
    qualified_io=@socket.instance_of?(Net::InternetMessageIO) && B0SMTP.io_map[@socket.object_id].equal?(self) &&
      @socket.method(:write_message).owner==B0MessageIOObserver && @socket.method(:writeline).owner==B0MessageIOObserver
    raise B0SMTP::ContractMismatch,'actual_DATA_io_not_covered_by_fixed_observer' unless qualified_io
    B0SMTP.event('qualified_data_io',{'session_id'=>session['session_id'],'io_object_id'=>@socket.object_id,
      'io_class'=>@socket.class.to_s,'write_message_owner'=>@socket.method(:write_message).owner.to_s,
      'writeline_owner'=>@socket.method(:writeline).owner.to_s})
    B0SMTP.allowed_data_entries+=1
    @b0_data_active=true
    @b0_message_written=false
    @b0_data_continue=false
    B0SMTP.event('data_allowed',{'session_id'=>session['session_id'],'message_sha256'=>B0.sha(msgstr),'message_bytes'=>msgstr.bytesize})
    result=super
    B0SMTP.event('data_method_return',{'session_id'=>session['session_id'],'status'=>result.respond_to?(:status) ? result.status : nil})
    result
  rescue StandardError => e
    B0SMTP.event('data_method_error',{'session_id'=>session && session['session_id'],'error_type'=>e.class.name,'cause_type'=>e.cause&.class&.name})
    raise
  ensure
    @b0_data_active=false
  end

  def get_response(line)
    session=B0SMTP.session(self)
    command=line.to_s.split(' ',2).first
    B0SMTP.event('get_response_method',{'session_id'=>session['session_id'],'command'=>command})
    super
  end

  def recv_response
    session=B0SMTP.session(self)
    phase = @b0_data_active ? (@b0_message_written ? 'data_final' : 'data_continue') : 'other'
    B0SMTP.event('response_read_start',{'session_id'=>session['session_id'],'phase'=>phase})
    result=super
    @b0_data_continue=true if phase=='data_continue' && result.status=='354'
    B0SMTP.event('response_read_complete',{'session_id'=>session['session_id'],'phase'=>phase,'status'=>result.status,'response'=>result.string})
    result
  rescue StandardError => e
    B0SMTP.event('response_read_error',{'session_id'=>session && session['session_id'],'phase'=>phase,
      'error_type'=>e.class.name,'cause_type'=>e.cause&.class&.name,
      'client_socket_already_closed'=>@socket ? @socket.closed? : true,
      'message_writer_returned'=>!!@b0_message_written,'data_continue_received'=>!!@b0_data_continue})
    raise
  end

  def do_finish
    session=B0SMTP.session(self)
    B0SMTP.event('smtp_finish_start',{'session_id'=>session['session_id']})
    super
  rescue StandardError => e
    B0SMTP.event('smtp_finish_error',{'session_id'=>session['session_id'],'error_type'=>e.class.name})
    raise
  ensure
    B0SMTP.event('smtp_finish_end',{'session_id'=>session && session['session_id'],
      'socket_nil'=>@socket.nil?,'all_sockets_closed'=>session && session['sockets'].all?(&:closed?)})
  end
end

module B0MessageIOObserver
  def writeline(line)
    smtp=B0SMTP.io_map[object_id]
    return super unless smtp
    session=B0SMTP.session(smtp)
    command=line.to_s.split(' ',2).first
    if command=='AUTH'
      B0SMTP.event('unexpected_auth_refused',{'session_id'=>session['session_id']})
      raise B0SMTP::ContractMismatch,'SMTP_authentication_not_in_fixed_contract'
    end
    if command=='RCPT'
      address=line[/\ARCPT TO:<([^>]+)>/i,1]
      raise B0SMTP::ContractMismatch,'actual_smtp_recipient_mismatch' unless address==B0SMTP.intent.fetch('recipient')
    end
    B0SMTP.event('wire_command_start',{'session_id'=>session['session_id'],'command'=>command,'command_sha256'=>B0.sha(line)})
    result=super
    B0SMTP.event('wire_command_return',{'session_id'=>session['session_id'],'command'=>command,'returned_bytes'=>result})
    result
  rescue StandardError => e
    B0SMTP.event('wire_command_error',{'session_id'=>session && session['session_id'],'command'=>command,'error_type'=>e.class.name})
    raise
  end

  def write_message(message)
    smtp=B0SMTP.io_map[object_id]
    return super unless smtp
    session=B0SMTP.session(smtp)
    B0SMTP.event('message_writer_start',{'session_id'=>session['session_id'],'message_sha256'=>B0.sha(message)})
    result=super
    smtp.instance_variable_set(:@b0_message_written,true)
    B0SMTP.event('message_writer_return',{'session_id'=>session['session_id'],'returned_bytes'=>result,
      'qualified_source_includes_end_of_data_marker'=>true})
    result
  rescue StandardError => e
    B0SMTP.event('message_writer_error',{'session_id'=>session && session['session_id'],'error_type'=>e.class.name})
    raise
  end
end

barrier=B0.stopped_services!
active_old_sockets=barrier['smtp_sockets'].reject { |row| ['06','07'].include?(row['state']) }
raise 'old_smtp_socket_still_present' unless active_old_sockets.empty?
r=cfg.fetch('intent')
identity=B0.identity(r)
raise 'send_time_authorization_or_content_mismatch' unless identity['matches']
B0SMTP.intent=r
expected={
  'smtp_tcp_socket'=>[Net::SMTP,:tcp_socket,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'smtp_message_io'=>[Net::SMTP,:new_internet_message_io,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'smtp_start'=>[Net::SMTP,:do_start,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'smtp_get_response'=>[Net::SMTP,:get_response,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'smtp_data'=>[Net::SMTP,:data,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'smtp_recv'=>[Net::SMTP,:recv_response,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'smtp_sendmail'=>[Net::SMTP,:sendmail,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'smtp_finish'=>[Net::SMTP,:do_finish,'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517'],
  'message_writer'=>[Net::InternetMessageIO,:write_message,'3d011dfa382fa5cc90e3619f2dc56c47e2a29e25081d90515bfc1da80771ba88'],
  'wire_writer'=>[Net::BufferedIO,:writeline,'3d011dfa382fa5cc90e3619f2dc56c47e2a29e25081d90515bfc1da80771ba88'],
  'smtp_delivery'=>[Mail::SMTP,:deliver!,'14596f84aee964e30fb262caf65730cdb5f926956a3612c78f7cff28484f7459'],
  'smtp_connection'=>[Mail::SMTPConnection,:deliver!,'26a2ea105b2f3c00f05d31d8848e94346f8d2a963d22326d3a74e5dfbc2d61a5'],
  'mail_deliver'=>[Mail::Message,:deliver,'62aec80d17112b198cd3cc9f7820e95e043c41fb279ce3edd3d6fb15da721dba'],
  'action_mailer_deliver_now'=>[ActionMailer::MessageDelivery,:deliver_now,'599657ce3dddf8fd22665aea50ee299d4df5e2c566b22566ae114ac2806131af']
}
bindings={}
expected.each do |key,(klass,method,sha)|
  actual=klass.instance_method(method);loc=actual.source_location
  bindings[key]={'owner'=>actual.owner.to_s,'source_location'=>loc,'sha256'=>loc && Digest::SHA256.file(loc[0]).hexdigest,
                 'ancestors'=>klass.ancestors.map(&:to_s)}
  raise 'loaded_mail_stack_contract_changed' unless actual.owner==klass && loc && bindings[key]['sha256']==sha
end
notify_method=Notify.instance_method(:new_issue_email)
notify_loc=notify_method.source_location
raise 'actual_Notify_method_changed' unless notify_method.owner.to_s=='Emails::Issues' && notify_loc &&
  Digest::SHA256.file(notify_loc[0]).hexdigest=='22960e4879f28927011fa01784be95cdafde16658fe9dbdb14d88434a27b591e'
bindings['actual_notify_new_issue_email']={'owner'=>notify_method.owner.to_s,'source_location'=>notify_loc,
  'sha256'=>Digest::SHA256.file(notify_loc[0]).hexdigest,'ancestors'=>Notify.ancestors.map(&:to_s)}
Net::SMTP.prepend(B0SMTPObserver)
Net::InternetMessageIO.prepend(B0MessageIOObserver)
delivery=Notify.new_issue_email(identity['recipient_id'],identity['issue_id'],r.fetch('reason'))
message=delivery.message
B0SMTP.verify_message(message)
raise 'delivery_method_not_qualified_smtp' unless message.delivery_method.instance_of?(Mail::SMTP)
settings=message.delivery_method.settings
raise 'delivery_target_not_qualified' unless settings[:address]=='notification-mailbox' && settings[:port].to_i==1025
raise 'smtp_authentication_not_qualified' if settings[:user_name] || settings[:password] || settings[:authentication]
raise 'smtp_tls_not_qualified' if settings[:tls] || settings[:ssl] || settings[:enable_starttls] || settings[:enable_starttls_auto]
raise 'mail_delivery_disabled' unless message.perform_deliveries
application_error=nil
B0SMTP.event('application_deliver_now_start')
begin
  delivery.deliver_now
  B0SMTP.event('application_deliver_now_return')
rescue StandardError => e
  application_error={'type'=>e.class.name,'cause_type'=>e.cause&.class&.name}
  B0SMTP.event('application_deliver_now_error',application_error)
end
sessions=B0SMTP.sessions.map do |session|
  {'session_id'=>session['session_id'],'object_id'=>session['object_id'],
   'socket_count'=>session['sockets'].length,'all_sockets_closed'=>session['sockets'].all?(&:closed?)}
end
B0.emit({'kind'=>'notification_send','identity'=>identity,'intent'=>r,'writer_barrier'=>barrier,
 'real_application'=>'Notify.new_issue_email(...).deliver_now','runtime_bindings'=>bindings,
 'installed_observers'=>{'smtp_first_ancestor'=>Net::SMTP.ancestors.first.to_s,'message_io_first_ancestor'=>Net::InternetMessageIO.ancestors.first.to_s},
 'application_error'=>application_error,'smtp_events'=>B0SMTP.events,'smtp_sessions'=>sessions,
 'data_method_entries'=>B0SMTP.data_entries,'allowed_data_entries'=>B0SMTP.allowed_data_entries,
 'smtp_internal_retries_counted'=>true,'automatic_outer_retries'=>0,
 'business_effect_claimed'=>false,'server_terminal_claimed'=>false})
