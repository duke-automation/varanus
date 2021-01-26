# frozen_string_literal: true

require 'test_helper'

class VaranusOrganizationTest < Minitest::Test
  def setup
    super
    @varanus = Varanus.new('test-customer', 'testuser', 'testpassword')
    @organization = @varanus.organization

    @expected_auth_headers = {
      'customerUri' => 'test-customer',
      'login' => 'testuser',
      'password' => 'testpassword'
    }
  end

  def test_list
    response = [
      { 'certTypes' => [], 'id' => 442, 'name' => 'Example Org',
        'departments' => [{ 'certTypes' => ['SSL'], 'id' => 445,
                            'name' => 'Example Department' }] }
    ]

    stub_request(:get, 'https://cert-manager.com/api/organization/v1')
      .with(headers: @expected_auth_headers)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal response, @organization.list
  end

  def test_info
    response = { 'certTypes' => ['SSL'], 'id' => 445, 'name' => 'Example Department',
                 'parentName' => 'Duke University' }

    stub_request(:get, 'https://cert-manager.com/api/organization/v1/445')
      .with(headers: @expected_auth_headers)
      .to_return(status: 200, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    assert_equal response, @organization.info(445)
  end
end
