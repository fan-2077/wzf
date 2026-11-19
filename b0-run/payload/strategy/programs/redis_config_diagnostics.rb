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
