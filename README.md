# Varanus

This gem provides an interface to Sectigo's (formerly Comodo CA) APIs for working
with SSL/TLS certificates as well as its reporting API.

Support for Sectigo's other APIs (S/MIME, code signing, device certificates, etc) may
be added at a later date.  Merge requests to add some of this functionality would be
greatly appreciated.

[![Build Status](https://travis-ci.org/duke-automation/varanus.svg?branch=master)](https://travis-ci.org/duke-automation/varanus)
[![Gem Version](https://badge.fury.io/rb/varanus.svg)](http://badge.fury.io/rb/varanus)
[![Maintainability](https://api.codeclimate.com/v1/badges/593ef1aa2ba757b5374f/maintainability)](https://codeclimate.com/github/duke-automation/varanus/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/593ef1aa2ba757b5374f/test_coverage)](https://codeclimate.com/github/duke-automation/varanus/test_coverage)

## Usage

#### Sign SSL cert from CSR

```ruby
csr = File.read('/path/to/file.csr')
varanus = Varanus.new(customer_uri, username, password)
id = varanus.ssl.sign csr, org_id
begin
  cert = varanus.ssl.collect id
rescue Varanus::Error::StillProcessing
  sleep 1
  retry
end
puts cert
```

#### Revoke SSL cert

```ruby
Varanus.new(customer_uri, username, password).ssl.revoke(id)
```

#### Authentication

Authentication requires the same credentials you use to login to cert-manager.com as well as the ```customer_uri```.  If your URL to log into cert-manager.com is https://cert-manager.com/customer/MyCompany then your ```customer_uri``` will be ```'MyCompany'```

#### Finding Organization Id (org_id)

Signing a cert requires specifying an ```org_id```.  Each department in cert-manager.com has an associated ```org_id```.

To find the ```org_id```, log into cert-manager.com, go to **Settings** -> **Departments**, then click to edit the department you are interested in.  The value you want is in the **OrgID** field.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'varanus'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install varanus

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/duke-automation/varanus.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
