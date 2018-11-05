# Interface for Sectigo's (formerly Comodo CA) API.
class Varanus
  attr_reader :customer_uri, :username, :password

  def initialize customer_uri, username, password
    @customer_uri = customer_uri
    @username = username
    @password = password
  end

  def ssl
    @ssl ||= SSL.new(self)
  end
end

# stdlib/gem requires
require 'faraday'
require 'faraday_middleware'
require 'openssl'

# Require other files in this gem
require 'varanus/error'
require 'varanus/ssl'
require 'varanus/ssl/csr'
require 'varanus/version'
