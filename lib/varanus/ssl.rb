# frozen_string_literal: true

# An connection to the SSL/TSL API.  This should not be initialized directly.  Instead,
# use Varanus#ssl
class Varanus::SSL < Varanus::RestResource
  # rubocop:disable Style/MutableConstant
  # These constants are frozen, rubocop is failing to detect the freeze.
  # See https://github.com/rubocop-hq/rubocop/issues/4406
  REPORT_CERT_STATUS = { any: 0, requested: 1, issued: 2, revoked: 3, expired: 4 }
  REPORT_CERT_STATUS.default_proc = proc { |_h, k|
    raise ArgumentError, "Unknown certificateStatus: #{k.inspect}"
  }
  REPORT_CERT_STATUS.freeze

  REPORT_CERT_DATE_ATTR = { revocation_date: 2, expiration_date: 3, request_date: 4,
                            issue_date: 5 }
  REPORT_CERT_DATE_ATTR.default_proc = proc { |_h, k|
    raise ArgumentError, "Unknown certificateDateAttribute: #{k.inspect}"
  }
  REPORT_CERT_DATE_ATTR.freeze
  # rubocop:enable Style/MutableConstant

  # Returns the option from #certificate_types that best matches the csr.
  # @param csr [Varanus::SSL::CSR]
  # @return [Hash] The option from {#certificate_types} that best matches the csr
  def certificate_type_from_csr csr, days = nil
    types = certificate_types_standard(days)
    return types.first if types.length <= 1

    regexp = cert_type_regexp(csr)
    typ = types.find { |ct| ct['name'] =~ regexp } if regexp
    return typ unless typ.nil?

    types.find do |ct|
      ct['name'] =~ /\bSSL\b/ && ct['name'] !~ /(?:Multi.?Domain|Wildcard)/i
    end
  end

  # Certificate types that can be used to sign a cert
  # @return [Array<Hash>]
  def certificate_types
    @certificate_types ||= get('ssl/v1/types')
  end

  # Return Array of certificate types based on standard sorting.
  # @param days [Integer] if present, only include types that support the given day count
  # @return [Array<Hash>]
  def certificate_types_standard days = nil
    types = certificate_types.reject do |ct|
      ct['name'] =~ /\b(?:EV|Extended Validation|ECC|AMT|Elite)\b/
    end
    types = types.select! { |t| t['terms'].include? days } unless days.nil?

    types
  end

  # Retrieves the cert.
  # @param id [Integer] As returned by {#sign}
  # @param type [String]
  #
  # +type+ can be one of:
  #  'x509'    - X509 format - cert and chain (default)
  #  'x509CO'  - X509 format - cert only
  #  'x509IO'  - X509 format - intermediates/root only
  #  'x590IOR' - X509 format - intermediates/root only reversed
  #  'base64'  - PKCS#7 base64 encoded
  #  'bin'     - PKCS#7 bin encoded
  #
  # @raise [Varanus::Error::StillProcessing] Cert is still being signed
  # @return [String] Certificate
  def collect id, type = 'x509'
    get("ssl/v1/collect/#{id}/#{type}")
  end

  # Returns info on the SSL certificate of the given name
  def info id
    get("ssl/v1/#{id}")
  end

  # List certs ids and serial numbers
  def list opts = {}
    get_with_size_and_position('ssl/v1', opts)
  end

  # Return a report (list) of SSL certs based on the options.
  # The report includes a full set of details about the certs, not just the id/cn/serial
  # +opts+ can include:
  # (all are optional)
  # - :organizationIds - Array - ids of organization/departments to include certs for
  # - :certificateStatus - :any, :requested, :issued, :revoked, or :expired
  # - :certificateDateAttribute - Specifies what fields :from and/or :to refer to.
  #                               Can be: :revocation_date, :expiration_date,
  #                                       :request_date, or :issue_date
  # - :from - Date - based on :certificateDateAttribute
  # - :to - Date - based on :certificateDateAttribute
  def report opts = { certificateStatus: :any }
    # Default is to request any certificate status since the API call will fail if no
    # options are passed
    opts = { certificateStatus: :any } if opts.empty?
    opts = _parse_report_opts(opts)

    post('report/v1/ssl-certificates', opts)['reports']
  end

  # Revoke an ssl cert
  # @param id [Integer] As returned by {#sign}
  # @param reason [String] Reason for revoking. Sectigo's API will return an error if it
  #   is blank.
  def revoke id, reason
    post("ssl/v1/revoke/#{id}", reason: reason)
    nil
  end

  # Sign an SSL cert.  Returns the id of the SSL cert
  # @param csr [Varanus::SSL::CSR, OpenSSL::X509::Request, String] CSR to sign
  # @param org_id [Integer] your organization id on cert-manager.com
  # @param opts [Hash]
  # @option opts [String] :comments ('') Limited to 1,024 characters
  # @option opts [String] :external_requester ('') email address associated with cert on
  #   cert-manager.com - limited to 512 characters
  # @option opts [String, Integer] :cert_type name(String) or id(Integer) of the cert
  #   type to use.  If none is specified, Varanus will attempt to find one
  # @option opts [Integer] :years number of years cert should be valid for (this number
  #   is multiplied by 365  and used as days)
  # @option opts [Integer] :days  number of days cert should be valid for (if none is
  #   specified, lowest allowed for the cert type will be used)
  # @return [Integer] Id of SSL cert.
  def sign csr, org_id, opts = {}
    opts[:days] ||= opts[:years] * 365 unless opts[:years].nil?
    csr = Varanus::SSL::CSR.new(csr) unless csr.is_a?(Varanus::SSL::CSR)
    cert_type_id = opts_to_cert_type_id opts, csr
    args = {
      orgId: org_id,
      csr: csr.to_s,
      subjAltNames: csr.subject_alt_names.join(','),
      certType: cert_type_id,
      term: opts_to_term(opts, cert_type_id),
      serverType: -1,
      comments: opts[:comments].to_s[0, 1024],
      externalRequester: opts[:external_requester].to_s[0, 512]
    }
    post('ssl/v1/enroll', args)['sslId']
  end

  private

  def cert_type_regexp csr
    return /Wildcard.+SSL/i if csr.all_names.any? { |n| n.start_with?('*.') }

    return /Multi.?Domain.+SSL/i if csr.subject_alt_names.any?

    nil
  end

  def opts_to_cert_type_id opts, csr
    case opts[:cert_type]
    when Integer
      opts[:cert_type]
    when String
      certificate_types.find { |ct| ct['name'] == opts[:cert_type] }['id']
    else
      certificate_type_from_csr(csr, opts[:days])['id']
    end
  end

  def opts_to_term opts, cert_type_id
    term = opts[:days]
    term ||= certificate_types.find { |ct| ct['id'] == cert_type_id }['terms'].min
    term
  end

  def _parse_report_opts user_opts
    api_opts = {}
    user_opts.each do |key, val|
      case key
      when :organizationIds, :certificateRequestSource, :serialNumberFormat
        api_opts[key] = val
      when :from, :to
        api_opts[key] = val.strftime('%Y-%m-%d')
      when :certificateStatus
        api_opts[key] = REPORT_CERT_STATUS[val]
      when :certificateDateAttribute
        api_opts[key] = REPORT_CERT_DATE_ATTR[val]
      else
        raise ArgumentError, "Unknown key: #{key.inspect}"
      end
    end

    api_opts
  end
end
