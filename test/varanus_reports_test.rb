# frozen_string_literal: true

require 'test_helper'

class VaranusReportsTest < Minitest::Test
  def setup
    super
    @varanus = Varanus.new('test-customer', 'testuser', 'testpassword')
    @reports = @varanus.reports

    @expected_auth_data = {
      customerLoginUri: 'test-customer',
      login: 'testuser',
      password: 'testpassword'
    }
  end

  def test_domains
    expected_output = [
      {
        dcv_method: nil,
        dcv_status: 'Not validated',
        id: '236340',
        name: '*.notexample.com',
        status: 'ACTIVE'
      },
      {
        dcv_method: nil,
        dcv_status: 'Validated',
        id: '098238',
        name: '*.example.com',
        status: 'ACTIVE'
      }
    ]
    savon_body = {
      get_domain_report_response: {
        return: {
          status_code: '0',
          report_row_domains: expected_output
        }
      }
    }

    savon = mock_savon_instance
    result = mock('savon result')
    result.stubs(:body).returns(savon_body)
    savon.expects(:call)
         .with(:get_domain_report, message: { authData: @expected_auth_data })
         .returns(result)

    assert_equal expected_output, @reports.domains
  end

  def test_ssl_basic
    expected_body = [
      {
        common_name: 'example.com',
        term: '360'
      },
      {
        common_name: 'example.com',
        term: '90'
      }
    ]
    savon_body = {
      get_ssl_report_response: {
        return: {
          status_code: '0',
          reports: expected_body
        }
      }
    }
    savon = mock_savon_instance
    result = mock('savon result')
    result.stubs(:body).returns(savon_body)
    savon.expects(:call)
         .with(:get_SSL_report, message: { organizationNames: nil, certificateStatus: 0,
                                           authData: @expected_auth_data })
         .returns(result)

    assert_equal expected_body, @reports.ssl
  end

  def test_ssl_cert_type
    expected_body = [
      {
        common_name: 'example.com',
        term: '360'
      },
      {
        common_name: 'example.com',
        term: '90'
      }
    ]
    savon_body = {
      get_ssl_report_response: {
        return: {
          status_code: '0',
          reports: expected_body
        }
      }
    }
    savon = mock_savon_instance
    result = mock('savon result')
    result.stubs(:body).returns(savon_body)
    savon.expects(:call)
         .with(:get_SSL_report, message: { organizationNames: nil, certificateStatus: 4,
                                           authData: @expected_auth_data })
         .returns(result)

    assert_equal expected_body, @reports.ssl(status: :expired)
  end

  def test_ssl_orgs
    expected_body = {
      common_name: 'example.com',
      term: '360'
    }
    savon_body = {
      get_ssl_report_response: {
        return: {
          status_code: '0',
          reports: expected_body
        }
      }
    }
    savon = mock_savon_instance
    result = mock('savon result')
    result.stubs(:body).returns(savon_body)
    savon.expects(:call)
         .with(:get_SSL_report, message: { organizationNames: 'Foo/Bar',
                                           certificateStatus: 0,
                                           authData: @expected_auth_data })
         .returns(result)

    assert_equal [expected_body], @reports.ssl(orgs: 'Foo/Bar')
  end

  private

  def mock_savon_instance
    savon = mock('savon instance')
    Savon.stubs(:client).with(
      namespace: 'http://report.ws.epki.comodo.com/',
      endpoint: 'https://cert-manager.com:443/ws/ReportService',
      log: false
    ).returns(savon)
    savon
  end
end
