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

  def test_certificate_type_from_csr_cn_only
    expected_type = { 'id' => 224, 'name' => 'TestCompany SSL (SHA-2)', 'terms' => [365, 730] }

    csr_str = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBVTCBvwIBADAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
      AQEFAAOBjQAwgYkCgYEA0SoP9mkRDebGOM6RRthcRYocS3QhlyfyOkH/P7MYJ7TP
      jUN1T6CX3UXljHI3/y0FZQbihnbxidi1VtjMrCFg//pJeZJh77jfl+cr8FFIslyJ
      e8zpAsIE2yf1flOdabNNKm8DU1lCmIp6RSxwacuee8eofinJHlfAsn/xsIaJZBsC
      AwEAAaAAMA0GCSqGSIb3DQEBCwUAA4GBAEBZjx2e2nMTX3dJ2Oi4AFtF6BaZM4uD
      n9dL3B0REi+aFR2duzhm8LqntaHvHpHxI0kGCAy4xXySyGm+3+bCJxzSFDA3OAo1
      JiBTrv+eND/Ks7/KnXf/qT/0zcrwfAfDGwBp/kxRWp5MHBQSAFMKtsfSTbqDof0U
      h0UdQogGL49X
      -----END CERTIFICATE REQUEST-----
    CSR
    csr = Varanus::SSL::CSR.new csr_str

    mock_cert_types expected_type['name']
    assert_equal expected_type, @ssl.certificate_type_from_csr(csr)
  end

  def test_certificate_type_from_csr_cn_and_san
    expected_type = { 'id' => 226, 'name' => 'TestCompany Multi Domain SSL (SHA-2)', 'terms' => [365, 730] }

    csr_str = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBkzCB/QIBADAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
      AQEFAAOBjQAwgYkCgYEA0SoP9mkRDebGOM6RRthcRYocS3QhlyfyOkH/P7MYJ7TP
      jUN1T6CX3UXljHI3/y0FZQbihnbxidi1VtjMrCFg//pJeZJh77jfl+cr8FFIslyJ
      e8zpAsIE2yf1flOdabNNKm8DU1lCmIp6RSxwacuee8eofinJHlfAsn/xsIaJZBsC
      AwEAAaA+MDwGCSqGSIb3DQEJDjEvMC0wKwYDVR0RBCQwIoIPd3d3LmV4YW1wbGUu
      Y29tgg9mdHAuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADgYEAqlQP1YYkMQkq
      ehm+rfjdOMJwrEJAwJ0/O/RbFcwnb2x8YO9r/5Zuz1s3MIAekunDsdYLGTKuhKD0
      AO/dksVF3YCmZz8hshXvDhGoBP09NIQe/0/Xo5bRMtTE+6YU2fZ8EwBt0duFCh+O
      PUMpJq4wcK8tFbOgTsb0HjMXYmJIp6w=
      -----END CERTIFICATE REQUEST-----
    CSR
    csr = Varanus::SSL::CSR.new csr_str

    mock_cert_types expected_type['name']
    assert_equal expected_type, @ssl.certificate_type_from_csr(csr)
  end

  def test_certificate_type_from_csr_san_only
    expected_type = { 'id' => 226, 'name' => 'TestCompany Multi Domain SSL (SHA-2)', 'terms' => [365, 730] }

    csr_str = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBaDCB0gIBADAAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkFoOvytfA
      ywtwUBNto+2zVtbr4I1qLzfDpJNbrxDTLT1GQ6+yFGqtMzvwo28+8tkMAt3EeAVr
      4nv0Zw5NqlHbaGy/s8ECFGl3aIcw3vq7OazNL0SH1rCSUSbHNFd1o/3tj8x7sgDm
      UmJD2C3Cn8MfRPM2R+USDxfNO+NZh3T+fwIDAQABoCkwJwYJKoZIhvcNAQkOMRow
      GDAWBgNVHREEDzANggtleGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOBgQDTUzBx
      3NbOMQcaVsvACwrOleueqRncFnNoq3h6F9mbBr/28t4E8eCDVzB47sTohGSXysqg
      7NJQc1wCn6aPRw5LPJLP61HBLN8vw1c2e09Y1RSumr/CgOgPBiD8tI235oorMxZq
      KlEj1jBS5+uZLFU4O2Xl8fUkQz4tH4Zl0Hoplw==
      -----END CERTIFICATE REQUEST-----
    CSR
    csr = Varanus::SSL::CSR.new csr_str

    mock_cert_types expected_type['name']
    assert_equal expected_type, @ssl.certificate_type_from_csr(csr)
  end

  def test_certificate_type_from_csr_wildcard
    expected_type = { 'id' => 227, 'name' => 'TestCompany Wildcard SSL Certificate (SHA-2)', 'terms' => [365, 730] }

    csr_str = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBVzCBwQIBADAYMRYwFAYDVQQDDA0qLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3
      DQEBAQUAA4GNADCBiQKBgQDOT/UPp/gQqrd1dUBA6Wdj/T2hzfYLTarDNTgfoIkF
      Wab/wGBHWmG5i6g7UMD3V+5RjAXs0/wsP5XCpwGKqdz8ZpYu5/sOqfMZy9kwXQGz
      Cmh/0+n/Wf8uVCX/3t2QqFBa5/xu8H3irdeFYw8iSPQe/2IKYA1mO/ysRDCPqE73
      ZwIDAQABoAAwDQYJKoZIhvcNAQELBQADgYEAm//JbBC+xegvWBa0/gRwYdwcocds
      GvqBxh+UtEpgwUp70RtNVaK5mfMLrLZhJ/Y0YTS+4vuBmqI0oa+DZweMPpJutWJd
      fP7POXU+zt0JDT1imnyUBy4eDeRPA54w6xnka92SXF781RyeuOVAUWEiH2K28q6f
      kQ73v+4Go99Muww=
      -----END CERTIFICATE REQUEST-----
    CSR
    csr = Varanus::SSL::CSR.new csr_str

    mock_cert_types expected_type['name']
    assert_equal expected_type, @ssl.certificate_type_from_csr(csr)
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

  def test_sign_cert_all_options
    # Type will be int, term will be in days

    csr = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBkzCB/QIBADAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
      AQEFAAOBjQAwgYkCgYEA0SoP9mkRDebGOM6RRthcRYocS3QhlyfyOkH/P7MYJ7TP
      jUN1T6CX3UXljHI3/y0FZQbihnbxidi1VtjMrCFg//pJeZJh77jfl+cr8FFIslyJ
      e8zpAsIE2yf1flOdabNNKm8DU1lCmIp6RSxwacuee8eofinJHlfAsn/xsIaJZBsC
      AwEAAaA+MDwGCSqGSIb3DQEJDjEvMC0wKwYDVR0RBCQwIoIPd3d3LmV4YW1wbGUu
      Y29tgg9mdHAuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADgYEAqlQP1YYkMQkq
      ehm+rfjdOMJwrEJAwJ0/O/RbFcwnb2x8YO9r/5Zuz1s3MIAekunDsdYLGTKuhKD0
      AO/dksVF3YCmZz8hshXvDhGoBP09NIQe/0/Xo5bRMtTE+6YU2fZ8EwBt0duFCh+O
      PUMpJq4wcK8tFbOgTsb0HjMXYmJIp6w=
      -----END CERTIFICATE REQUEST-----
    CSR

    expected_body = {
      orgId: 557,
      csr: csr,
      subjAltNames: ['www.example.com', 'ftp.example.com'],
      certType: 27,
      term: 90,
      serverType: -1,
      comments: 'This is a comment',
      externalRequester: 'root@example.com'
    }
    return_body = { renewId: 'something', sslId: 382 }
    stub_request(:post, 'https://cert-manager.com/api/ssl/v1/enroll')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' },
                 body: return_body.to_json)

    assert_equal 382, @ssl.sign_cert(csr, 557, comments: 'This is a comment',
                                               cert_type: 27, days: 90,
                                               external_requester: 'root@example.com')
  end

  def test_sign_cert_csrobj_defaults_cn_only
    csr_str = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBVTCBvwIBADAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
      AQEFAAOBjQAwgYkCgYEA0SoP9mkRDebGOM6RRthcRYocS3QhlyfyOkH/P7MYJ7TP
      jUN1T6CX3UXljHI3/y0FZQbihnbxidi1VtjMrCFg//pJeZJh77jfl+cr8FFIslyJ
      e8zpAsIE2yf1flOdabNNKm8DU1lCmIp6RSxwacuee8eofinJHlfAsn/xsIaJZBsC
      AwEAAaAAMA0GCSqGSIb3DQEBCwUAA4GBAEBZjx2e2nMTX3dJ2Oi4AFtF6BaZM4uD
      n9dL3B0REi+aFR2duzhm8LqntaHvHpHxI0kGCAy4xXySyGm+3+bCJxzSFDA3OAo1
      JiBTrv+eND/Ks7/KnXf/qT/0zcrwfAfDGwBp/kxRWp5MHBQSAFMKtsfSTbqDof0U
      h0UdQogGL49X
      -----END CERTIFICATE REQUEST-----
    CSR
    csr = Varanus::SSL::CSR.new csr_str

    @ssl.expects(:certificate_types).returns(
      [{ 'id' => 25, 'name' => 'test SSL (SHA-2)', 'terms' => [90, 365, 730] },
       { 'id' => 27, 'name' => 'test Multi Domain SSL (SHA-2)', 'terms' => [365, 730] }]
    ).at_least_once

    expected_body = {
      orgId: 557,
      csr: csr,
      subjAltNames: [],
      certType: 25,
      term: 90,
      serverType: -1,
      comments: '',
      externalRequester: ''
    }
    return_body = { renewId: 'something', sslId: 382 }
    stub_request(:post, 'https://cert-manager.com/api/ssl/v1/enroll')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' },
                 body: return_body.to_json)

    assert_equal 382, @ssl.sign_cert(csr, 557)
  end

  def test_sign_cert_opensslobj_defaults_cn_and_san
    csr_str = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBkzCB/QIBADAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
      AQEFAAOBjQAwgYkCgYEA0SoP9mkRDebGOM6RRthcRYocS3QhlyfyOkH/P7MYJ7TP
      jUN1T6CX3UXljHI3/y0FZQbihnbxidi1VtjMrCFg//pJeZJh77jfl+cr8FFIslyJ
      e8zpAsIE2yf1flOdabNNKm8DU1lCmIp6RSxwacuee8eofinJHlfAsn/xsIaJZBsC
      AwEAAaA+MDwGCSqGSIb3DQEJDjEvMC0wKwYDVR0RBCQwIoIPd3d3LmV4YW1wbGUu
      Y29tgg9mdHAuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADgYEAqlQP1YYkMQkq
      ehm+rfjdOMJwrEJAwJ0/O/RbFcwnb2x8YO9r/5Zuz1s3MIAekunDsdYLGTKuhKD0
      AO/dksVF3YCmZz8hshXvDhGoBP09NIQe/0/Xo5bRMtTE+6YU2fZ8EwBt0duFCh+O
      PUMpJq4wcK8tFbOgTsb0HjMXYmJIp6w=
      -----END CERTIFICATE REQUEST-----
    CSR
    csr = OpenSSL::X509::Request.new csr_str

    @ssl.expects(:certificate_types).returns(
      [{ 'id' => 25, 'name' => 'test SSL (SHA-2)', 'terms' => [90, 365, 730] },
       { 'id' => 27, 'name' => 'test Multi Domain SSL (SHA-2)', 'terms' => [365, 730] }]
    ).at_least_once

    expected_body = {
      orgId: 557,
      csr: csr,
      subjAltNames: ['www.example.com', 'ftp.example.com'],
      certType: 27,
      term: 365,
      serverType: -1,
      comments: '',
      externalRequester: ''
    }
    return_body = { renewId: 'something', sslId: 382 }
    stub_request(:post, 'https://cert-manager.com/api/ssl/v1/enroll')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' },
                 body: return_body.to_json)

    assert_equal 382, @ssl.sign_cert(csr, 557)
  end

  def test_sign_cert_text_defaults_san_only
    csr = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBaDCB0gIBADAAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkFoOvytfA
      ywtwUBNto+2zVtbr4I1qLzfDpJNbrxDTLT1GQ6+yFGqtMzvwo28+8tkMAt3EeAVr
      4nv0Zw5NqlHbaGy/s8ECFGl3aIcw3vq7OazNL0SH1rCSUSbHNFd1o/3tj8x7sgDm
      UmJD2C3Cn8MfRPM2R+USDxfNO+NZh3T+fwIDAQABoCkwJwYJKoZIhvcNAQkOMRow
      GDAWBgNVHREEDzANggtleGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOBgQDTUzBx
      3NbOMQcaVsvACwrOleueqRncFnNoq3h6F9mbBr/28t4E8eCDVzB47sTohGSXysqg
      7NJQc1wCn6aPRw5LPJLP61HBLN8vw1c2e09Y1RSumr/CgOgPBiD8tI235oorMxZq
      KlEj1jBS5+uZLFU4O2Xl8fUkQz4tH4Zl0Hoplw==
      -----END CERTIFICATE REQUEST-----
    CSR

    @ssl.expects(:certificate_types).returns(
      [{ 'id' => 25, 'name' => 'test SSL (SHA-2)', 'terms' => [90, 365, 730] },
       { 'id' => 27, 'name' => 'test Multi Domain SSL (SHA-2)', 'terms' => [365, 730] }]
    ).at_least_once

    expected_body = {
      orgId: 557,
      csr: csr,
      subjAltNames: ['example.com'],
      certType: 27,
      term: 365,
      serverType: -1,
      comments: '',
      externalRequester: ''
    }
    return_body = { renewId: 'something', sslId: 382 }
    stub_request(:post, 'https://cert-manager.com/api/ssl/v1/enroll')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' },
                 body: return_body.to_json)

    assert_equal 382, @ssl.sign_cert(csr, 557)
  end

  def test_sign_cert_years_type_string
    # specify term as years
    # specify type as string

    @ssl.expects(:certificate_types).returns(
      [{ 'id' => 25, 'name' => 'test SSL (SHA-2)', 'terms' => [365, 730] },
       { 'id' => 27, 'name' => 'test Multi Domain SSL (SHA-2)', 'terms' => [365, 730] }]
    )

    csr = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBkzCB/QIBADAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
      AQEFAAOBjQAwgYkCgYEA0SoP9mkRDebGOM6RRthcRYocS3QhlyfyOkH/P7MYJ7TP
      jUN1T6CX3UXljHI3/y0FZQbihnbxidi1VtjMrCFg//pJeZJh77jfl+cr8FFIslyJ
      e8zpAsIE2yf1flOdabNNKm8DU1lCmIp6RSxwacuee8eofinJHlfAsn/xsIaJZBsC
      AwEAAaA+MDwGCSqGSIb3DQEJDjEvMC0wKwYDVR0RBCQwIoIPd3d3LmV4YW1wbGUu
      Y29tgg9mdHAuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADgYEAqlQP1YYkMQkq
      ehm+rfjdOMJwrEJAwJ0/O/RbFcwnb2x8YO9r/5Zuz1s3MIAekunDsdYLGTKuhKD0
      AO/dksVF3YCmZz8hshXvDhGoBP09NIQe/0/Xo5bRMtTE+6YU2fZ8EwBt0duFCh+O
      PUMpJq4wcK8tFbOgTsb0HjMXYmJIp6w=
      -----END CERTIFICATE REQUEST-----
    CSR

    expected_body = {
      orgId: 557,
      csr: csr,
      subjAltNames: ['www.example.com', 'ftp.example.com'],
      certType: 25,
      term: 730,
      serverType: -1,
      comments: 'This is a comment',
      externalRequester: 'root@example.com'
    }
    return_body = { renewId: 'something', sslId: 382 }
    stub_request(:post, 'https://cert-manager.com/api/ssl/v1/enroll')
      .with(headers: @expected_auth_headers, body: expected_body.to_json)
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' },
                 body: return_body.to_json)

    assert_equal 382, @ssl.sign_cert(csr, 557, comments: 'This is a comment',
                                               cert_type: 'test SSL (SHA-2)', years: 2,
                                               external_requester: 'root@example.com')
  end

  private

  def mock_cert_types last_name = nil
    # This list is based on the cert types for InCommon as of November 6, 2018
    cert_types = [
      { 'id' => 224, 'name' => 'TestCompany SSL (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 227, 'name' => 'TestCompany Wildcard SSL Certificate (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 226, 'name' => 'TestCompany Multi Domain SSL (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 228, 'name' => 'TestCompany Unified Communications Certificate (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 229, 'name' => 'Comodo EV Multi Domain SSL (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 98, 'name' => 'Comodo EV Multi Domain SSL', 'terms' => [365, 730] },
      { 'id' => 215, 'name' => 'IGTF Server Cert', 'terms' => [365, 395] },
      { 'id' => 283, 'name' => 'IGTF Multi Domain', 'terms' => [365, 395] },
      { 'id' => 179, 'name' => 'AMT SSL Certificate', 'terms' => [365, 730] },
      { 'id' => 180, 'name' => 'AMT Wildcard SSL Certificate', 'terms' => [365, 730] },
      { 'id' => 181, 'name' => 'AMT Multi-Domain SSL Certificate', 'terms' => [365, 730] },
      { 'id' => 243, 'name' => 'Comodo Elite SSL Certificate (FileMaker) (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 284, 'name' => 'TestCompany ECC', 'terms' => [365, 730] },
      { 'id' => 286, 'name' => 'TestCompany ECC Multi Domain', 'terms' => [365, 730] },
      { 'id' => 285, 'name' => 'TestCompany ECC Wildcard', 'terms' => [365, 730] },
      { 'id' => 60, 'name' => 'Comodo EV SSL Certificate', 'terms' => [365, 730] },
      { 'id' => 249, 'name' => 'Comodo EV SSL Certificate (SHA-2)', 'terms' => [365, 730] },
      { 'id' => 363, 'name' => 'EV Anchor Certificate', 'terms' => [395] }
    ]
    # Move the stated item to be the last in the list.  This is to help make sure our code
    # properly rejects all other options
    unless last_name.nil?
      item = cert_types.find { |ct| ct['name'] == last_name }
      raise "Unable to find item #{last_name}" if item.nil?

      cert_types.delete item
      cert_types << item
    end
    @ssl.stubs(:certificate_types).returns(cert_types)
  end
end
