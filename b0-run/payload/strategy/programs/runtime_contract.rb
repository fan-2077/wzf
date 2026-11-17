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
