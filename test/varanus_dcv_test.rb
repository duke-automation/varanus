# frozen_string_literal: true

require 'test_helper'

class VaranusDCVTest < Minitest::Test
  def setup
    super
    @varanus = Varanus.new('test-customer', 'testuser', 'testpassword')
    @dcv = @varanus.dcv

    @expected_auth_headers = {
      'customerUri' => 'test-customer',
      'login' => 'testuser',
      'password' => 'testpassword'
    }
  end

  def test_search_two_pages
    response1 = [
      { 'domain' => 'example.com',
        'dcvStatus' => 'something',
        'expirationDate' => '2021-01-20' },
      { 'domain' => 'example.org',
        'dcvStatus' => 'something' },
      { 'domain' => 'example.net',
        'dcvStatus' => 'something' }
    ].to_json
    response2 = [
      { 'domain' => 'example.edu',
        'dcvStatus' => 'something' }
    ].to_json

    stub_request(:get, 'https://cert-manager.com/api/dcv/v2/validation?org=42&size=3&position=0')
      .to_return(body: response1, status: 200,
                 headers: { 'Content-Type' => 'application/json' })
    stub_request(:get, 'https://cert-manager.com/api/dcv/v2/validation?org=42&size=3&position=3')
      .to_return(body: response2, status: 200,
                 headers: { 'Content-Type' => 'application/json' })
    expected_results = [
      { 'domain' => 'example.com',
        'dcvStatus' => 'something',
        'expirationDate' => '2021-01-20',
        'expiration_date_obj' => Date.new(2021, 1, 20) },
      { 'domain' => 'example.org',
        'dcvStatus' => 'something' },
      { 'domain' => 'example.net',
        'dcvStatus' => 'something' },
      { 'domain' => 'example.edu',
        'dcvStatus' => 'something' }
    ]

    assert_equal expected_results, @dcv.search(org: 42, size: 3)
  end

  def test_start
    response = { 'host' => '_random.example.com', 'point' => '_barn.sectigo.com' }
    expected_body = { 'domain' => 'example.com' }

    stub_request(:post, 'https://cert-manager.com/api/dcv/v1/validation/start/domain/cname')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal response, @dcv.start('example.com', 'cname')
  end

  def test_status
    response = { 'status' => 'EXPIRED', 'orderStatus' => 'SUBMITTED',
                 'expirationDate' => '2020-12-20' }
    expected_response = { 'status' => 'EXPIRED', 'orderStatus' => 'SUBMITTED',
                          'expirationDate' => '2020-12-20',
                          'expiration_date_obj' => Date.new(2020, 12, 20) }
    expected_body = { 'domain' => 'example.com' }

    stub_request(:post, 'https://cert-manager.com/api/dcv/v2/validation/status')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal expected_response, @dcv.status('example.com')
  end

  def test_submit
    response = { 'status' => 'NOT_VALIDATED', 'orderStatus' => 'SUBMITTED',
                 'message' => 'DCV status: Not Validated; DCV order status: Submitted' }
    expected_body = { 'domain' => 'example.com' }

    stub_request(:post, 'https://cert-manager.com/api/dcv/v1/validation/submit/domain/cname')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal response, @dcv.submit('example.com', 'cname')
  end

  def test_submit_email
    response = { 'status' => 'NOT_VALIDATED', 'orderStatus' => 'SUBMITTED',
                 'message' => 'DCV status: Not Validated; DCV order status: Submitted' }
    expected_body = { 'domain' => 'example.com', 'email' => 'admin@example.com' }

    stub_request(:post, 'https://cert-manager.com/api/dcv/v1/validation/submit/domain/email')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal response, @dcv.submit('example.com', 'email', 'admin@example.com')
  end
end
