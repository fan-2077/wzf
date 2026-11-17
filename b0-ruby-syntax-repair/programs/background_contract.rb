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
require 'uri'
expected={
  'app/workers/new_issue_worker.rb'=>'1bc96a75425b4155ff8afe1fdb2df6ca50537b7437bb63c41fb21d2ce4e8fb9c',
  'app/services/notification_service.rb'=>'f90f0bec8e02fe93f3609ce6e01cb927a7bf1cdbed753e15ac7f84c515a1a0aa',
  'app/services/notification_recipients/build_service.rb'=>'775785c478b90038ec61e9eb603657c8d5eb5f198735c78b17dda8439d56ede5',
  'app/models/notification_recipient.rb'=>'75ead4f72b7376e0670737b322f1c1e075921e857154dc2d39a07474e4b1e233',
  'app/services/notification_recipients/builder/default.rb'=>'868a84a5fe9234a9962176d7d621a2d8389101614a72e5dc22ed6b1945220d82',
  'app/services/notification_recipients/builder/base.rb'=>'0f2703569ce77a5bad911a19ea4b9915e9816fa33e8c2ed2198f35fc71a7b696',
  'app/models/notification_reason.rb'=>'7527589447b5eb3dcd0acc17e945046d02a99a316d1ae884716ef631bec81918',
  'lib/gitlab/redis/wrapper.rb'=>'d36e2cdca8aeac64d89b3c3105f098b9903b03c64e87eac40ad993786e95450b',
  'lib/gitlab/redis/queues.rb'=>'c9c27177a0626302d083acb4320cf14be73bf8e95040408f12cf6eb1e6b76a4a'
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
  [NotificationReason,:priority,'app/models/notification_reason.rb',true],
  [Gitlab::Redis::Queues,:params,'lib/gitlab/redis/wrapper.rb',true,Gitlab::Redis::Wrapper.singleton_class],
  [Gitlab::Redis::Queues,:instances,'lib/gitlab/redis/queues.rb',true],
  [Gitlab::Redis::Queues,:params,'lib/gitlab/redis/wrapper.rb',false,Gitlab::Redis::Wrapper],
  [Gitlab::Redis::Queues,:fetch_config,'lib/gitlab/redis/wrapper.rb',false,Gitlab::Redis::Wrapper],
  [Gitlab::Redis::Queues,:redis_store_options,'lib/gitlab/redis/wrapper.rb',false,Gitlab::Redis::Wrapper],
  [Gitlab::Redis::Queues,:parse_redis_url,'lib/gitlab/redis/wrapper.rb',false,Gitlab::Redis::Wrapper]
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
# Read the actual post-initialization Rails configuration without creating a
# Redis connection, a ProcessSet, or invoking queue cleanup. No raw URL,
# password, certificate, or other credential value is emitted.
params=Gitlab::Redis::Queues.params.transform_keys(&:to_s)
begin
  uri=params['url'].is_a?(String) ? URI.parse(params['url']) : nil
rescue URI::InvalidURIError
  raise 'Actual_Rails_queue_URL_unparseable'
end
url_db=uri && uri.path.to_s.match?(%r{\A/[0-9]+\z}) ? uri.path.delete_prefix('/').to_i : nil
database=params.key?('db') ? params['db'] : url_db
database=database.to_i if database.is_a?(String) && database.match?(/\A[0-9]+\z/)
host=params['host'] || uri&.host
port=params['port'] || uri&.port
port=port.to_i if port.is_a?(String) && port.match?(/\A[0-9]+\z/)
present=->(value) { !value.nil? && value!=false && (!value.respond_to?(:empty?) || !value.empty?) }
shards=Gitlab::Redis::Queues.instances.keys.map(&:to_s).sort
configuration={
  'schema'=>'b0-actual-Rails-queue-configuration-v1',
  'source'=>'Gitlab::Redis::Queues.params_after_Rails_initialization',
  'host'=>host,'port'=>port,'database'=>database,'database_present'=>!database.nil?,
  'database_basis'=>params.key?('db') ? 'actual_params_db' : (url_db.nil? ? 'missing' : 'actual_params_URL_path'),
  'url_present'=>!uri.nil?,'url_scheme'=>uri&.scheme,
  'authentication_present'=>present.call(params['username']) || present.call(params['password']) ||
    present.call(uri&.user) || present.call(uri&.password) || present.call(params['sentinel_password']),
  'tls_present'=>present.call(params['ssl']) || present.call(params['ssl_params']) || uri&.scheme=='rediss',
  'cluster_present'=>present.call(params['nodes']) || present.call(params['cluster']),
  'sentinels_present'=>present.call(params['sentinels']),
  'unix_socket_present'=>present.call(params['path']) || uri&.scheme=='unix',
  'namespace_present'=>present.call(params['namespace']),
  'shards'=>shards,'connections_created_by_observer'=>false,
  'actual_method_binding_keys'=>bindings.select { |row|row['class']=='Gitlab::Redis::Queues' }.map { |row|
    [row['method'],row['singleton'],row['source_sha256']] }
}
# redis-store intentionally omits :db for a URL without a database path. Ask
# the actual loaded redis-client configuration class to normalize that ordinary
# form. Config.new is separate from new_client/new_pool; no connection is made.
client_config_sha='d8cfbfc07954663fd1ec2eb11fca38b825c17b9aaf1c0e55ca5d138ecf1a6e60'
client_main_sha='c9779c773dd0370e207dc8c5db19a4c03cce731a69b78c7e7febff9ac027573e'
client_url_sha='70796489afdc9baa113f0481e65da687716400ab0a7b3a2998f426ec20f93af3'
client_requests=[
  [RedisClient::Config,:initialize,false,RedisClient::Config,client_config_sha],
  [RedisClient::Config::Common,:initialize,false,RedisClient::Config::Common,client_config_sha],
  [RedisClient::Config,:db,false,RedisClient::Config::Common,client_config_sha],
  [RedisClient::Config,:host,false,RedisClient::Config,client_config_sha],
  [RedisClient::Config,:port,false,RedisClient::Config,client_config_sha],
  [RedisClient,:driver,true,RedisClient.singleton_class,client_main_sha]
]
[:initialize,:db,:host,:port,:path,:username,:password,:ssl?].each do |method|
  client_requests << [RedisClient::URLConfig,method,false,RedisClient::URLConfig,client_url_sha]
end
client_bindings=client_requests.map do |klass,method,singleton,owner,sha|
  bound=singleton ? klass.method(method) : klass.instance_method(method)
  location=bound.source_location;actual_sha=location && Digest::SHA256.file(location[0]).hexdigest
  {'class'=>klass.to_s,'method'=>method.to_s,'singleton'=>singleton,'owner'=>bound.owner.to_s,
   'source_location'=>location,'source_sha256'=>actual_sha,
   'qualified'=>bound.owner==owner && actual_sha==sha}
end
driver_class=RedisClient.instance_variable_get(:@default_driver)
client_qualified=Gem.loaded_specs['redis-client']&.version&.to_s=='0.26.4' &&
  client_bindings.all? { |row|row['qualified'] } && RedisClient::Config.method(:new).owner==Class &&
  RedisClient::URLConfig.method(:new).owner==Class && driver_class.is_a?(Class)
normalization={'qualified'=>false,'scope'=>'actual_client_configuration_only_no_client_or_pool',
  'version'=>Gem.loaded_specs['redis-client']&.version&.to_s,'actual_method_bindings'=>client_bindings,
  'already_loaded_driver_class'=>driver_class.is_a?(Class) ? driver_class.to_s : nil,
  'actual_input_keys'=>%w[url host port db path].select { |key|params.key?(key) },
  'configuration_constructor_owner'=>RedisClient::Config.method(:new).owner.to_s,
  'new_client_called'=>false,'new_pool_called'=>false,'redis_commands_issued'=>0}
supported_shape=%w[authentication_present tls_present cluster_present sentinels_present unix_socket_present namespace_present].all? { |key|configuration[key]==false }
if qualified && client_qualified && supported_shape && shards==['main']
  # params has string keys here: explicitly rebuild symbols, preserving a
  # caller-independent actual nonzero database instead of dropping that value.
  options=%w[url host port db path].each_with_object({}) do |key,out|
    out[key.to_sym]=params[key] if params.key?(key)
  end
  normalized=RedisClient::Config.new(**options,driver:driver_class)
  host=normalized.host;port=normalized.port;database=normalized.db
  normalization.merge!('qualified'=>true,'host'=>host,'port'=>port,'database'=>database,
    'input_database_present'=>params.key?('db'),'input_URL_database_present'=>!url_db.nil?)
  configuration.merge!('host'=>host,'port'=>port,'database'=>database,'database_present'=>true,
    'database_basis'=>'actual_client_config_normalization')
end
configuration['client_configuration_normalization']=normalization
url_agrees=uri.nil? || ((uri.host.nil? || uri.host==host) && (uri.port.nil? || uri.port==port) &&
  (url_db.nil? || url_db==database) && uri.scheme=='redis')
configuration['qualified']=qualified && host=='gitlab-redis' && port==6379 &&
  database.is_a?(Integer) && database.between?(0,15) && shards==['main'] && url_agrees &&
  %w[authentication_present tls_present cluster_present sentinels_present unix_socket_present namespace_present].all? { |key|configuration[key]==false }
B0.emit({'kind'=>'background_contract','qualified'=>qualified,'writer_barrier'=>barrier,
  'sources'=>sources,'actual_method_bindings'=>bindings,'normal_reason_domain'=>[nil]+reasons,
  'excluded_custom_reason'=>'issue-update','source_complete'=>true,
  'actual_queue_configuration'=>configuration,
  'claim_scope'=>'ordinary_NewIssueWorker_reason_choice_and_actual_Rails_queue_configuration',
  'normal_background_has_run'=>false,'original_oracle_still_required'=>true})
