# frozen_string_literal: true

require 'test_helper'

class VaranusDomainTest < Minitest::Test
  def setup
    super
    @varanus = Varanus.new('test-customer', 'testuser', 'testpassword')
    @domain = @varanus.domain

    @expected_auth_headers = {
      'customerUri' => 'test-customer',
      'login' => 'testuser',
      'password' => 'testpassword'
    }
  end

  def test_create
    expected_body = { 'name' => '*.example.com',
                      'delegations' => [{ 'orgId' => 50, 'certTypes' => ['SSL'] }] }

    req = stub_request(:post, 'https://cert-manager.com/api/domain/v1')
          .with(headers: @expected_auth_headers, body: expected_body.to_json)
          .to_return(status: 201,
                     headers: { 'Location' => 'https://cert-manager.com/api/domain/v1/442' })

    assert_equal 'https://cert-manager.com/api/domain/v1/442',
                 @domain.create('example.com',
                                [{ 'orgId' => 50, 'certTypes' => ['SSL'] }])
    assert_requested req, times: 1
  end

  def test_create_no_subdomains
    expected_body = { 'name' => 'example.com',
                      'delegations' => [{ 'orgId' => 50, 'certTypes' => ['SSL'] }] }

    req = stub_request(:post, 'https://cert-manager.com/api/domain/v1')
          .with(headers: @expected_auth_headers, body: expected_body.to_json)
          .to_return(status: 201,
                     headers: { 'Location' => 'https://cert-manager.com/api/domain/v1/442' })

    assert_equal 'https://cert-manager.com/api/domain/v1/442',
                 @domain.create('example.com',
                                [{ 'orgId' => 50, 'certTypes' => ['SSL'] }],
                                allow_subdomains: false)
    assert_requested req, times: 1
  end

  def test_list
    response = [
      { 'id' => 5, 'name' => '*.example.com' },
      { 'id' => 556, 'name' => 'example.com' }
    ]

    stub_request(:get, 'https://cert-manager.com/api/domain/v1?position=0&size=200')
      .with(headers: @expected_auth_headers)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal response, @domain.list
  end

  def test_list_with_info
    list_response = [
      { 'id' => 5, 'name' => '*.example.com' },
      { 'id' => 557, 'name' => '*.example.com' }
    ]
    info_response1 = { 'dcvExpiration' => '2022-01-11', 'delegationStatus' => 'ACTIVE',
                       'id' => 5, 'name' => 'example.com', 'state' => 'ACTIVE',
                       'validationStatus' => 'VALIDATED' }
    info_response2 = { 'dcvExpiration' => '2022-01-11', 'delegationStatus' => 'ACTIVE',
                       'id' => 557, 'name' => '*.example.com', 'state' => 'ACTIVE',
                       'validationStatus' => 'VALIDATED' }

    expected_response = [info_response1, info_response2]

    stub_request(:get, 'https://cert-manager.com/api/domain/v1?position=0&size=200')
      .with(headers: @expected_auth_headers)
      .to_return(status: 200, body: list_response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    stub_request(:get, 'https://cert-manager.com/api/domain/v1/5')
      .with(headers: @expected_auth_headers)
      .to_return(status: 200, body: info_response1.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    stub_request(:get, 'https://cert-manager.com/api/domain/v1/557')
      .with(headers: @expected_auth_headers)
      .to_return(status: 200, body: info_response2.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal expected_response, @domain.list_with_info
  end

  def test_info
    response = { 'dcvExpiration' => '2022-01-11', 'delegationStatus' => 'ACTIVE',
                 'id' => 557, 'name' => '*.example.com', 'state' => 'ACTIVE',
                 'validationStatus' => 'VALIDATED' }

    stub_request(:get, 'https://cert-manager.com/api/domain/v1/557')
      .with(headers: @expected_auth_headers)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal response, @domain.info(557)
  end

  def test_report
    @expected_response ||= ['mock array']

    response_body = {
      'statusCode' => 0,
      'reports' => @expected_response
    }
    req = stub_request(:post, 'https://cert-manager.com/api/report/v1/domains')
          .with(headers: @expected_auth_headers, body: {}.to_json)
          .to_return(status: 200, body: response_body.to_json,
                     headers: { 'Content-Type' => 'application/json' })

    assert_equal @expected_response, @domain.report

    assert_requested req, times: 1
  end
end
