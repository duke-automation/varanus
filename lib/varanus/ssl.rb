# frozen_string_literal: true

# An connection to the SSL/TSL API.  This should not be initialized directly.  Instead,
# use Varanus#ssl
class Varanus::SSL
  # @note Do not call this directly.  Use {Varanus#ssl} to initialize
  def initialize varanus
    @varanus = varanus
  end

  # Returns the option from #certificate_types that best matches the csr.
  # @param csr [Varanus::SSL::CSR]
  # @return [Hash] The option from {#certificate_types} that best matches the csr
  def certificate_type_from_csr csr
    # first exclude certificate types we don't want
    types = certificate_types.reject do |ct|
      ct['name'] =~ /\b(?:EV|ECC|AMT|Elite)\b/
    end
    if csr.all_names.any? { |n| n.start_with?('*.') }
      types.find { |ct| ct['name'] =~ /Wildcard.+SSL/i }
    elsif csr.subject_alt_names.any?
      types.find { |ct| ct['name'] =~ /Multi.?Domain.+SSL/i }
    else
      types.find do |ct|
        ct['name'] =~ /\bSSL\b/ && ct['name'] !~ /(?:Multi.?Domain|Wildcard)/i
      end
    end
  end

  # Certificate types that can be used to sign a cert
  # @return [Array<Hash>]
  def certificate_types
    @certificate_types ||= get('types')
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
    get("collect/#{id}/#{type}")
  end

  # Revoke an ssl cert
  # @param id [Integer] As returned by {#sign}
  # @param reason [String] Reason for revoking. Sectigo's API will return an error if it
  #   is blank.
  def revoke id, reason
    post("revoke/#{id}", reason: reason)
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
    post('enroll', args)['sslId']
  end

  private

  def check_result result
    body = result.body
    return unless body.is_a?(Hash)
    return if body['code'].nil?

    klass = Varanus::Error
    if body['code'] == 0 && body['description'] =~ /process/
      klass = Varanus::Error::StillProcessing
    end

    raise klass.new(body['code'], body['description'])
  end

  def connection
    @connection ||= Faraday.new(url: 'https://cert-manager.com/api/ssl/v1',
                                request: { timeout: 300 }) do |conn|
      conn.request :json
      conn.response :json, content_type: /\bjson$/

      conn.headers['login'] = @varanus.username
      conn.headers['password'] = @varanus.password
      conn.headers['customerUri'] = @varanus.customer_uri

      conn.adapter Faraday.default_adapter
    end
  end

  def get path
    result = connection.get(path)
    check_result result
    result.body
  end

  def opts_to_cert_type_id opts, csr
    case opts[:cert_type]
    when Integer
      opts[:cert_type]
    when String
      certificate_types.find { |ct| ct['name'] == opts[:cert_type] }['id']
    else
      certificate_type_from_csr(csr)['id']
    end
  end

  def post path, *args
    result = connection.post(path, *args)
    check_result result
    result.body
  end

  def opts_to_term opts, cert_type_id
    term = opts[:days]
    term ||= opts[:years] * 365 unless opts[:years].nil?
    term ||= certificate_types.find { |ct| ct['id'] == cert_type_id }['terms'].min
    term
  end
end
