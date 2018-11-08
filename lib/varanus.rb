# frozen_string_literal: true

# Interface for Sectigo's (formerly Comodo CA) API.
class Varanus
  attr_reader :customer_uri, :username, :password

  # @param customer_uri [String]
  #   (see {file:README.md#label-Finding+Organization+Id+-28org_id-29})
  # @param username [String]
  # @param password [String]
  def initialize customer_uri, username, password
    @customer_uri = customer_uri
    @username = username
    @password = password
  end

  # Retrieve Reports instance
  # @return [Varanus::Reports]
  def reports
    @reports ||= Reports.new(self)
  end

  # Retrive SSL instance
  # @return [Varanus::SSL]
  def ssl
    @ssl ||= SSL.new(self)
  end
end

# stdlib/gem requires
require 'faraday'
require 'faraday_middleware'
require 'openssl'
require 'savon'

# Require other files in this gem
require 'varanus/error'
require 'varanus/reports'
require 'varanus/ssl'
require 'varanus/ssl/csr'
require 'varanus/version'
