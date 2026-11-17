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

# Ordinary API replay enqueues normal GitLab workers. They must be preserved.
# Bind the actual loaded CE methods that choose their ordinary notification
# reasons before using that finite source contract to restart the background.
barrier=B0.stopped_services!
expected={
  'app/workers/new_issue_worker.rb'=>'1bc96a75425b4155ff8afe1fdb2df6ca50537b7437bb63c41fb21d2ce4e8fb9c',
  'app/services/notification_service.rb'=>'f90f0bec8e02fe93f3609ce6e01cb927a7bf1cdbed753e15ac7f84c515a1a0aa',
  'app/services/notification_recipients/build_service.rb'=>'775785c478b90038ec61e9eb603657c8d5eb5f198735c78b17dda8439d56ede5',
  'app/models/notification_recipient.rb'=>'75ead4f72b7376e0670737b322f1c1e075921e857154dc2d39a07474e4b1e233',
  'app/services/notification_recipients/builder/default.rb'=>'868a84a5fe9234a9962176d7d621a2d8389101614a72e5dc22ed6b1945220d82',
  'app/services/notification_recipients/builder/base.rb'=>'0f2703569ce77a5bad911a19ea4b9915e9816fa33e8c2ed2198f35fc71a7b696',
  'app/models/notification_reason.rb'=>'7527589447b5eb3dcd0acc17e945046d02a99a316d1ae884716ef631bec81918'
}
root='/opt/gitlab/embedded/service/gitlab-rails/'
sources=expected.to_h { |path,sha| [path,{'expected_sha256'=>sha,'actual_sha256'=>Digest::SHA256.file(root+path).hexdigest}] }
requests=[
  [NewIssueWorker,:perform,'app/workers/new_issue_worker.rb',false],
  [NotificationService,:new_issue,'app/services/notification_service.rb',false],
  [NotificationService,:new_resource_email,'app/services/notification_service.rb',false],
  [NotificationRecipients::BuildService,:build_recipients,'app/services/notification_recipients/build_service.rb',true],
  [NotificationRecipients::Builder::Default,:build!,'app/services/notification_recipients/builder/default.rb',false],
  [NotificationRecipients::Builder::Default,:initialize,'app/services/notification_recipients/builder/default.rb',false],
  [NotificationRecipients::Builder::Default,:add_watchers,'app/services/notification_recipients/builder/default.rb',false],
  [NotificationRecipients::Builder::Default,:acting_user,'app/services/notification_recipients/builder/default.rb',false],
  [NotificationRecipients::Builder::Default,:custom_action,'app/services/notification_recipients/builder/default.rb',false],
  [NotificationRecipients::Builder::Default,:mention_type_actions,'app/services/notification_recipients/builder/default.rb',true],
  [NotificationRecipient,:initialize,'app/models/notification_recipient.rb',false],
  [NotificationRecipient,:own_activity?,'app/models/notification_recipient.rb',false],
  [NotificationRecipient,:reason,'app/models/notification_recipient.rb',false],
  [NotificationReason,:priority,'app/models/notification_reason.rb',true]
]
[:add_recipients,:make_recipient,:notification_recipients,:add_participants,:add_mentions,:add_custom_notifications,
 :add_project_watchers,:add_group_watchers,:add_subscribed_users,:add_labels_subscribers].each do |method|
  requests << [NotificationRecipients::Builder::Default,method,'app/services/notification_recipients/builder/base.rb',false,
               NotificationRecipients::Builder::Base]
end
bindings=requests.map do |klass,method,path,singleton,expected_owner|
  bound=singleton ? klass.method(method) : klass.instance_method(method)
  location=bound.source_location
  wanted_owner=expected_owner || (singleton ? klass.singleton_class : klass)
  actual_sha=location && Digest::SHA256.file(location[0]).hexdigest
  {'class'=>klass.to_s,'method'=>method.to_s,'singleton'=>singleton,'owner'=>bound.owner.to_s,
   'ancestors'=>(singleton ? klass.singleton_class : klass).ancestors.map(&:to_s),
   'source_location'=>location,'source_sha256'=>actual_sha,
   'qualified'=>bound.owner==wanted_owner && actual_sha==expected[path]}
end
reasons=NotificationReason::REASON_PRIORITY
qualified=sources.values.all? { |row|row['expected_sha256']==row['actual_sha256'] } &&
  bindings.all? { |row|row['qualified'] } && reasons==['own_activity','assigned','review_requested','mentioned','subscribed']
B0.emit({'kind'=>'background_contract','qualified'=>qualified,'writer_barrier'=>barrier,
  'sources'=>sources,'actual_method_bindings'=>bindings,'normal_reason_domain'=>[nil]+reasons,
  'excluded_custom_reason'=>'issue-update','source_complete'=>true,
  'claim_scope'=>'ordinary_NewIssueWorker_notification_reason_choice_only',
  'normal_background_has_run'=>false,'original_oracle_still_required'=>true})
