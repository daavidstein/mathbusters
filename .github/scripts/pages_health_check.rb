require 'json'
require 'github-pages-health-check'

results = ['math-busters.com', 'www.math-busters.com'].product([:default, :public]).map do |host, resolver|
  begin
    check = GitHubPages::HealthCheck::Domain.new(host, nameservers: resolver)
    {
      host: host,
      resolver: resolver,
      checks: check.to_hash,
      records: check.dns&.map(&:to_s)
    }
  rescue StandardError => error
    {host: host, resolver: resolver, error: "#{error.class}: #{error.message}"}
  end
end
report = {
  ruby_version: RUBY_VERSION,
  gem_version: Gem.loaded_specs.fetch('github-pages-health-check').version.to_s,
  results: results
}
File.write('pages-health-check.json', JSON.pretty_generate(report))
puts JSON.pretty_generate(report)
