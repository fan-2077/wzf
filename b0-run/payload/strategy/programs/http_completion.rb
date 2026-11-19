request_id=cfg.fetch('request_id')
raise 'invalid_request_id' unless request_id.match?(/\A[A-Za-z0-9_-]{1,128}\z/)
paths=['/var/log/gitlab/gitlab-rails/api_json.log','/var/log/gitlab/gitlab-rails/api_json.log.1']
rows=[]
paths.each do |path|
  next unless File.file?(path) && !File.symlink?(path)
  raise 'api_log_over_bound' if File.size(path)>268435456
  File.foreach(path) do |line|
    next unless line.include?(request_id)
    begin
      row=JSON.parse(line)
    rescue JSON::ParserError
      raise 'matching_api_log_unparseable'
    end
    next unless row['correlation_id']==request_id
    rows << {'file'=>path,'line_sha256'=>B0.sha(line),
             'correlation_id'=>row['correlation_id'],'method'=>row['method'],'path'=>row['path'],
             'status'=>row['status'],'pid'=>row['pid'],'time'=>row['time'],
             'db_duration_s'=>row['db_duration_s'],'duration_s'=>row['duration_s']}
  end
end
B0.emit({'kind'=>'http_completion','request_id'=>request_id,'records'=>rows,'source_complete'=>true})
