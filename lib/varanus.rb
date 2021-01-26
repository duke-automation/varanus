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

  # :nodoc:
  def connection
    @connection ||= Faraday.new(url: 'https://cert-manager.com/api',
                                request: { timeout: 300 }) do |conn|
      conn.request :json
      conn.response :json, content_type: /\bjson$/

      conn.headers['login'] = @username
      conn.headers['password'] = @password
      conn.headers['customerUri'] = @customer_uri

      conn.adapter Faraday.default_adapter
    end
  end

  # Retrive DCV instance
  # @return [Varanus::DCV]
  def dcv
    @dcv ||= DCV.new(self)
  end

  # Retrieve Domain instance
  # @return [Varanus::Domain]
  def domain
    @domain ||= Domain.new(self)
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
require 'varanus/rest_resource'
require 'varanus/dcv'
require 'varanus/domain'
require 'varanus/reports'
require 'varanus/ssl'
require 'varanus/ssl/csr'
require 'varanus/version'
