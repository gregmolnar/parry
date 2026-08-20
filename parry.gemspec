# frozen_string_literal: true

require_relative "lib/parry/version"

Gem::Specification.new do |spec|
  spec.name = "parry"
  spec.version = Parry::VERSION
  spec.authors = ["Greg Molnar"]
  spec.email = ["molnargerg@gmail.com"]

  spec.summary = "A Rails engine that provides a GUI for Rack::Attack"
  spec.description = "Parry is a mountable Rails engine to manage Rack::Attack rules " \
    "(blocklists, safelists and throttles) at runtime, inspect blocked hosts and unblock them. " \
    "Rules are stored in Redis and applied without a redeploy."
  spec.homepage = "https://github.com/gregmolnar/parry"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/gregmolnar/parry"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .gitlab-ci.yml .standard.yml docker-compose.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "railties", ">= 7.1"
  spec.add_dependency "actionpack", ">= 7.1"
  spec.add_dependency "activemodel", ">= 7.1"
  spec.add_dependency "activesupport", ">= 7.1"
  spec.add_dependency "rack-attack", ">= 6.6"
  spec.add_dependency "redis", ">= 4.2"
end
