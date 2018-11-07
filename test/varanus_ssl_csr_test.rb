# frozen_string_literal: true

require 'test_helper'

class VaranusSSLCSRTest < Minitest::Test
  def test_generate_basic
    key, csr = Varanus::SSL::CSR.generate(['example.com', 'www.example.com'])

    assert_equal 'example.com', csr.cn
    assert_equal ['example.com', 'www.example.com'], csr.subject_alt_names

    assert_equal Varanus::SSL::CSR::DEFAULT_KEY_SIZE, csr.key_size
    assert_equal csr.request.to_s, csr.to_s
    assert csr.request.verify(csr.request.public_key)

    assert_instance_of OpenSSL::PKey::DSA, key
  end

  def test_generate_with_existing_key
    orig_key = OpenSSL::PKey::RSA.new(1024)
    key, csr = Varanus::SSL::CSR.generate(['example.com', 'www.example.com'], orig_key)

    assert_equal 'example.com', csr.cn
    assert_equal ['example.com', 'www.example.com'], csr.subject_alt_names

    assert_equal 1024, csr.key_size
    assert_equal csr.request.to_s, csr.to_s
    assert csr.request.verify(csr.request.public_key)

    assert_equal orig_key, key
  end

  def test_generate_with_subject_data
    key, csr = Varanus::SSL::CSR.generate(['example.com', 'www.example.com'], nil,
                                          'O' => 'Test Company', 'C' => 'US')

    assert_equal 'example.com', csr.cn
    assert_equal ['example.com', 'www.example.com'], csr.subject_alt_names

    assert_equal Varanus::SSL::CSR::DEFAULT_KEY_SIZE, csr.key_size
    assert_equal csr.request.to_s, csr.to_s
    assert csr.request.verify(csr.request.public_key)

    assert_instance_of OpenSSL::PKey::DSA, key

    assert_equal '/O=Test Company/C=US/CN=example.com', csr.request.subject.to_s
  end

  def test_load_csr_cn_and_san
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

    assert_equal 'example.com', csr.cn
    assert_equal ['www.example.com', 'ftp.example.com'], csr.subject_alt_names
    assert_equal ['example.com', 'www.example.com', 'ftp.example.com'], csr.all_names
    assert_equal 1024, csr.key_size
    assert_equal csr_str, csr.to_s
  end

  def test_load_csr_cn_dsa_key
    csr_str = <<~CSR
      -----BEGIN CERTIFICATE REQUEST-----
      MIICZTCCAiMCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggG3MIIBKwYHKoZI
      zjgEATCCAR4CgYEA05l9ZxJ1zIgM4aMwhQzNBGFgNzM3XbvHeeQsCWSFdTGSADf6
      Bv28pQCllLTLjWqAx4C/gF7nz9V+zslLoI/zijFm8FtobWoSCwH9RXl7FZzHv7jG
      3uXjVXEsh5gFfhDyhDbkwhf+NZWJiMryIIl7Be0Y6t6g1EDpduP87/rkEx0CFQCk
      uz+J8tVEDwSDlSInu9vpC3kwxwKBgDWvaMZADHhm/da4y+ODWkpEG4q2kOqhSmBb
      sVXOjUHFF9WzA+mJavtn8o+Vl4FxtQbL88q1WL4phXlN3Wbk3uflEuCZ5w5kyD2i
      Y3nquUAEx80dDEWKFZ8PoDe78IHNQne4hzvZM7xAd8hWJkysMPI2l/k0JO3hp1V2
      6iyuZxaBA4GFAAKBgQCNMr2Y9qI1/qNl1MkE7rI/ocbCRw9uKE0lWDimxl7XgPPP
      UqaNKAz0+Uh3kd1rqevtoUdPJBw2SqWRjkNxBcFQt2+mYpAcO6Ki4Ph07VdEeDu7
      dQeGuMijK4sIYnepA4v2Cu4n3kYzgfp9Yn/3YjwS1JJwgVbV8grd0LDY7ubd36BL
      MEkGCSqGSIb3DQEJDjE8MDowOAYDVR0RBDEwL4ILZXhhbXBsZS5jb22CD3d3dy5l
      eGFtcGxlLmNvbYIPZnRwLmV4YW1wbGUuY29tMAsGCWCGSAFlAwQDAgMvADAsAhR4
      fluirIpoxStgOepOr/0h7pmyogIUV8Y8yEUf7Cn3mNrqwNCWbOXXoiQ=
      -----END CERTIFICATE REQUEST-----
    CSR

    csr = Varanus::SSL::CSR.new csr_str

    assert_equal 'example.com', csr.cn
    assert_equal ['example.com', 'www.example.com', 'ftp.example.com'],
                 csr.subject_alt_names
    assert_equal ['example.com', 'www.example.com', 'ftp.example.com'], csr.all_names
    assert_equal 1024, csr.key_size
    assert_equal csr_str, csr.to_s
  end

  def test_load_csr_from_openssl_obj
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

    csr = Varanus::SSL::CSR.new csr

    assert_equal 'example.com', csr.cn
    assert_equal ['www.example.com', 'ftp.example.com'], csr.subject_alt_names
    assert_equal ['example.com', 'www.example.com', 'ftp.example.com'], csr.all_names
    assert_equal 1024, csr.key_size
    assert_equal csr_str, csr.to_s
  end

  def test_load_csr_no_cn
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

    assert_nil csr.cn
    assert_equal ['example.com'], csr.subject_alt_names
    assert_equal ['example.com'], csr.all_names
    assert_equal 1024, csr.key_size
    assert_equal csr_str, csr.to_s
  end

  def test_load_csr_no_san
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

    assert_equal 'example.com', csr.cn
    assert_equal [], csr.subject_alt_names
    assert_equal ['example.com'], csr.all_names
    assert_equal 1024, csr.key_size
    assert_equal csr_str, csr.to_s
  end
end
