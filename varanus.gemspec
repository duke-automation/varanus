lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'varanus/version'

# rubocop:disable Metrics/BlockLength
Gem::Specification.new do |spec|
  spec.name          = 'varanus'
  spec.version       = Varanus::VERSION
  spec.authors       = ['Sean Dilda']
  spec.email         = ['sean@duke.edu']

  spec.summary       = "Interface for Sectigo's (formerly Comodo CA) API."
  spec.description   = <<~DESCRIPTION
    This gem provides an interface to Sectigo's (formerly Comodo CA) APIs for working
    with SSL/TLS certificates as well as its reporting API.

    Support for Sectigo's other APIs (S/MIME, code signing, device certificates, etc) may
    be added at a later date.
  DESCRIPTION
  spec.homepage      = 'https://github.com/duke-automation/varanus'
  spec.license       = 'MIT'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.16'
  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'minitest-rg'
  spec.add_development_dependency 'mocha'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'webmock'

  spec.add_runtime_dependency 'faraday'
  spec.add_runtime_dependency 'faraday_middleware'
end
# rubocop:enable Metrics/BlockLength
