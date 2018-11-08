# frozen_string_literal: true

# An connection to the Reports API.  This should not be initialized directly.  Instead,
# use Varanus#reports
class Varanus::Reports
  SSL_CERT_STATUSES = {
    any: 0,
    requested: 1,
    downloaded: 2,
    revoked: 3,
    expired: 4,
    pending_download: 5,
    not_enrolled: 6
  }.freeze

  # @note Do not call this directly.  Use {Varanus#reports} to initialize
  def initialize varanus
    @varanus = varanus
  end

  def domains
    r = soap_call :get_domain_report, {}
    format_results r[:report_row_domains]
  end

  # Return report on SSL request
  # @param [opts] [Hash]
  # @option opts [String, Array] :orgs Name(s) of organizations (departments) to limit
  #   the report to.  If this is unset, results from all departments are returned.
  # @option opts [Symbol] :status (:any) One of :any, :requested, :downloaded, :revoked,
  #   :expired, :pending_download, :not_enrolled.    :downloaded and :pending_download
  #   mean the cert has been enrolled/signed.
  # @return [Array<Hash>]
  def ssl opts = {}
    msg = { organizationNames: nil, certificateStatus: 0 }

    msg[:organizationNames] = Array(opts[:orgs]).join(',') if opts.include? :orgs
    if opts.include? :status
      msg[:certificateStatus] = SSL_CERT_STATUSES[opts[:status]]
      raise ArgumentError, 'Invalid status' if msg[:certificateStatus].nil?
    end

    r = soap_call :get_SSL_report, msg
    format_results r[:reports]
  end

  private

  def format_results results
    if results.is_a? Hash
      [results]
    else
      results.to_a
    end
  end

  def savon
    @savon ||= Savon.client(
      namespace: 'http://report.ws.epki.comodo.com/',
      endpoint: 'https://cert-manager.com:443/ws/ReportService',
      log: false
    )
  end

  def soap_call func, opts = {}
    msg = opts.dup
    msg[:authData] = { customerLoginUri: @varanus.customer_uri, login: @varanus.username,
                       password: @varanus.password }

    result = savon.call func, message: msg
    result.body[(func.to_s.downcase + '_response').to_sym][:return]
  end
end
