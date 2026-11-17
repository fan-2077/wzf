require "json"
B0_EXPECTED_APPLICATION_SOURCES = JSON.parse("{\"app/mailers/emails/issues.rb\":\"22960e4879f28927011fa01784be95cdafde16658fe9dbdb14d88434a27b591e\",\"app/mailers/notify.rb\":\"cb2f63bab9042a36ff9bac9eb93ce83689d30238f80ce55ca322bd80d2711029\",\"app/services/issuable_base_service.rb\":\"379fe82293adb1988de0db0dd8ef44895d6459b018b70cb7c28efbd77ea309bc\",\"app/services/issues/base_service.rb\":\"c3f44b3c6b61d089e174f4a183227a2c8e2516cf4e756408002806037b3ba12b\",\"app/services/issues/create_service.rb\":\"8cc0fa10b9db97a57c9e150bdca18bd752a24c636feb5e1704ab577ce35ff0fc\",\"config/initializers/sidekiq.rb\":\"ae4a73d4447c2ac8a1998a8baceea9d0c55965742f682b5fed823428eb37a3d6\",\"lib/api/issues.rb\":\"06cb42f4cdde9a0ac1cf7cc11dfeb089de52da7e3b954709f27311b7e2e4571a\",\"lib/gitlab/sidekiq_logging/json_formatter.rb\":\"600d58650098aea2b28b7224f8ca98e78a7d5b3f6590fb5db8bc0674867f6e9f\",\"lib/gitlab/sidekiq_logging/structured_logger.rb\":\"f1db323070029462e7c7cba56dd7abb7ff83b2e6bd21e71b798bf162a7dea68a\",\"vendor/gems/sidekiq-reliable-fetch/lib/sidekiq/base_reliable_fetch.rb\":\"05042b331bda2bdbc8e14d2462f357416da51cbbcca77ff9b57d54f5ff264bd8\",\"vendor/gems/sidekiq-reliable-fetch/lib/sidekiq/interrupted_set.rb\":\"ed328fbf75308acbb33ee25b865f333b320fde94aecc869e01a3117b7e1064f2\",\"vendor/gems/sidekiq-reliable-fetch/lib/sidekiq/semi_reliable_fetch.rb\":\"f7bee9ee0dc6ca90acaf5270315b0389d0f72a4909475c0debed5d392fcbd8b1\",\"vendor/gems/sidekiq/lib/sidekiq/api.rb\":\"0370bde2d73f166c53633804a54027bf1d448bd6cc2038a5cdc287bdb8bb4f8b\",\"vendor/gems/sidekiq/lib/sidekiq/manager.rb\":\"d987a7b23a44472e47c010f02630e9d06c03a85dd10fa2c9968ca43ee60722d4\",\"vendor/gems/sidekiq/lib/sidekiq/processor.rb\":\"94821033c323767de1518ab34f7083ccd64dac761922f3132771d24bba4073d7\"}")
# Fixed, non-executing view of the documented main-queue configuration sources.
# This is diagnostic evidence only; business guards bind actual Rails params.
require 'yaml'
require 'uri'

def b0_redis_config_diagnostics
  root='/opt/gitlab/embedded/service/gitlab-rails/config/'
  etc='/var/opt/gitlab/gitlab-rails/etc/'
  selected=false
  %w[redis.yml redis.queues.yml resque.yml].map do |name|
    path=etc+name
    row={'path'=>path,'rails_path'=>root+name,'present'=>File.file?(path),
         'selected_by_fixed_main_queue_precedence'=>false,'qualified_for_business'=>false}
    next row unless row['present']
    begin
      before=File.stat(path); raw=File.binread(path); after=File.stat(path)
      row.merge!('bytes'=>raw.bytesize,'sha256'=>Digest::SHA256.hexdigest(raw),
        'unchanged_during_read'=>[before.ino,before.size,before.mtime]==[after.ino,after.size,after.mtime],
        'resolved_path'=>File.realpath(path),
        'rails_link_matches'=>File.file?(root+name) && File.realpath(root+name)==File.realpath(path))
      raise 'Redis_config_diagnostic_size_bound' if raw.bytesize>1048576
      # The actual application may evaluate ERB. This fixed observer does not.
      raise 'Redis_config_contains_ERB_not_evaluated' if raw.include?('<%')
      data=YAML.safe_load(raw,permitted_classes:[Symbol],aliases:true)
      production=data.is_a?(Hash) ? data['production'] : nil
      config=name=='redis.yml' && production.is_a?(Hash) ? production['queues'] :
             (name=='redis.yml' ? nil : production)
      row['configuration_present']=!config.nil?
      row['queue_shards_present']=name=='redis.yml' && production.is_a?(Hash) &&
        production.keys.any? { |key|key.to_s.include?('queues_shard_') }
      if !selected && !config.nil?
        row['selected_by_fixed_main_queue_precedence']=true; selected=true
      end
      next row if config.nil?
      config={'url'=>config} if config.is_a?(String)
      raise 'Redis_config_is_not_mapping_or_URL' unless config.is_a?(Hash)
      config=config.transform_keys(&:to_s)
      uri=config['url'].is_a?(String) ? URI.parse(config['url']) : nil
      path_db=uri && uri.path.to_s.match?(%r{\A/[0-9]+\z}) ? uri.path.delete_prefix('/').to_i : nil
      explicit_db=config.key?('db') ? config['db'] : (config.key?('database') ? config['database'] : path_db)
      explicit_db=explicit_db.to_i if explicit_db.is_a?(String) && explicit_db.match?(/\A[0-9]+\z/)
      row.merge!('host'=>config['host'] || uri&.host,'port'=>config['port'] || uri&.port,
        'database'=>explicit_db,'database_explicit'=>!explicit_db.nil?,
        'scheme'=>uri&.scheme,'url_present'=>!uri.nil?,
        'authentication_present'=>!!(config['username'] || config['password'] || uri&.user || uri&.password),
        'tls_present'=>!!config['ssl'] || uri&.scheme=='rediss',
        'cluster_present'=>!!config['cluster'] || !!config['nodes'],
        'sentinels_present'=>!!config['sentinels'],
        'config_command_present'=>!!config['config_command'],
        'secret_file_configured'=>!!config['secret_file'])
    rescue StandardError => error
      row['error_type']=error.class.name
      row['diagnostic_parse_complete']=false
    end
    row
  end
end

require 'json'
require 'digest'
require 'yaml'
require 'uri'
require 'net/smtp'
require 'mail'
require 'sidekiq/api'

root='/opt/gitlab/embedded/service/gitlab-rails'
versions={}
%w[mail net-smtp net-protocol sidekiq actionmailer].each do |name|
  versions[name]=Gem.loaded_specs[name]&.version&.to_s
end
bindings={}
{
  'smtp_data'=>[Net::SMTP,:data],
  'smtp_sendmail'=>[Net::SMTP,:sendmail],
  'smtp_recv_response'=>[Net::SMTP,:recv_response],
  'smtp_do_finish'=>[Net::SMTP,:do_finish],
  'protocol_write_message'=>[Net::InternetMessageIO,:write_message],
  'mail_smtp_deliver'=>[Mail::SMTP,:deliver!],
  'mail_connection_deliver'=>[Mail::SMTPConnection,:deliver!],
  'mail_message_deliver'=>[Mail::Message,:deliver],
  'sidekiq_processes'=>[Sidekiq::ProcessSet,:initialize],
  'sidekiq_work'=>[Sidekiq::WorkSet,:each]
}.each do |name,(klass,method)|
  bound=klass.instance_method(method)
  loc=bound.source_location
  bindings[name]={'owner'=>bound.owner.to_s,'source_location'=>loc,
                  'file_sha256'=>loc && Digest::SHA256.file(loc[0]).hexdigest,
                  'ancestors'=>klass.ancestors.map(&:to_s)}
end
sources={}
B0_EXPECTED_APPLICATION_SOURCES.each do |relative,expected|
  path=root+'/'+relative
  actual=File.file?(path) ? Digest::SHA256.file(path).hexdigest : nil
  sources[relative]={'sha256'=>actual,'expected_sha256'=>expected,'matches'=>actual==expected}
end
redis_configs=b0_redis_config_diagnostics
version=File.read(root+'/VERSION').strip
expected_versions={'mail'=>'2.9.0','net-smtp'=>'0.5.1','net-protocol'=>'0.2.2','sidekiq'=>'7.3.9'}
valid=expected_versions.all? { |k,v|versions[k]==v } && sources.values.all? { |v|v['matches'] }
binding_expect={
 'smtp_data'=>'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517',
 'smtp_sendmail'=>'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517',
 'smtp_recv_response'=>'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517',
 'smtp_do_finish'=>'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517',
 'protocol_write_message'=>'3d011dfa382fa5cc90e3619f2dc56c47e2a29e25081d90515bfc1da80771ba88',
 'mail_smtp_deliver'=>'14596f84aee964e30fb262caf65730cdb5f926956a3612c78f7cff28484f7459',
 'mail_connection_deliver'=>'26a2ea105b2f3c00f05d31d8848e94346f8d2a963d22326d3a74e5dfbc2d61a5',
 'mail_message_deliver'=>'62aec80d17112b198cd3cc9f7820e95e043c41fb279ce3edd3d6fb15da721dba',
 'sidekiq_processes'=>'0370bde2d73f166c53633804a54027bf1d448bd6cc2038a5cdc287bdb8bb4f8b',
 'sidekiq_work'=>'0370bde2d73f166c53633804a54027bf1d448bd6cc2038a5cdc287bdb8bb4f8b'
}
valid &&= binding_expect.all? { |k,v| bindings[k]['file_sha256']==v }
puts 'B0_RESULT:'+JSON.generate({'kind'=>'runtime_contract','gitlab_version'=>version,'ruby'=>RUBY_DESCRIPTION,
                               'versions'=>versions,'methods'=>bindings,'application_sources'=>sources,
                               'redis_configs'=>redis_configs,'approved_runtime'=>valid,
                               'redis_configuration_scope'=>'documented_files_diagnostic_only_actual_Rails_params_required',
                               'qualification'=>'standalone_bundle_loaded_sources_not_rails_execution',
                               'gemfile_lock_sha256'=>Digest::SHA256.file(root+'/Gemfile.lock').hexdigest},ascii_only:true)
