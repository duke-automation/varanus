require 'test_helper'

class VaranusSSLTest < Minitest::Test
  def setup
    super
    @varanus = Varanus.new('test-customer', 'testuser', 'testpassword')
    @ssl = @varanus.ssl

    @expected_auth_headers = {
      'customerUri' => 'test-customer',
      'login' => 'testuser',
      'password' => 'testpassword'
    }
  end

  def test_certificate_types
    response_body = [
      { 'id' => 25, 'name' => 'test SSL (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 25, 'name' => 'test Multi Domain SSL (SHA-2)', 'terms' => [365, 730] }
    ]

    stub_request(:get, 'https://cert-manager.com/api/ssl/v1/types')
      .with(headers: @expected_auth_headers)
      .to_return(body: response_body.to_json, status: 200,
                 headers: { 'Content-Type' => 'application/json' })

    # The returned value should be the same thing the server sent us
    assert_equal response_body, @ssl.certificate_types
  end

  def test_certificate_types_with_error
    response_body = {
      'code' => -16,
      'description' => 'Unknown user'
    }

    stub_request(:get, 'https://cert-manager.com/api/ssl/v1/types')
      .to_return(body: response_body.to_json, status: 401,
                 headers: { 'Content-Type' => 'application/json' })

    exp = assert_raises(Varanus::Error) do
      @ssl.certificate_types
    end
    assert_equal(-16, exp.code)
    assert_equal 'Unknown user', exp.to_s
  end
end
