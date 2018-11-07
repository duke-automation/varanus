# An connection to the SSL/TSL API.  This should not be initialized directly.  Instead,
# use Varanus#ssl
class Varanus::SSL
  def initialize varanus # :nodoc:
    @varanus = varanus
  end

  # Returns the option from #certificate_types that best matches the csr.
  # +csr+ must be a Varanus::SSL::CSR object
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

  # Return Array of certificate types that can be used
  def certificate_types
    @certificate_types ||= get('types')
  end

  # Returns the cert contents.
  # +id+ is the id returned by #sign_cert
  # +type+ can be one of:
  #  'x509'    - X509 format - cert and chain (default)
  #  'x509CO'  - X509 format - cert only
  #  'x509IO'  - X509 format - intermediates/root only
  #  'x590IOR' - X509 format - intermediates/root only reversed
  #  'base64'  - PKCS#7 base64 encoded
  #  'bin'     - PKCS#7 bin encoded
  #
  # If the cert is still being signed, Varanus::Error::StillProcessing will be raised
  def collect_cert id, type = 'x509'
    get("collect/#{id}/#{type}")
  end

  # Sign an SSL cert.  Returns the id of the SSL cert
  # +csr+ is the CSR as a String, OpenSSL::X509::Request or Varanus::SSL::CSR
  # +org_id+ or your organization id on cert-manager.com
  # +opts+ can include any of the following keys:
  #  :comments - no more than 1,024 characers
  #  :external_requester - email address associated with cert on cert-manager.com - no
  #                        more than 512 characters
  #  :cert_type - can be name(String) or id(Integer) of the cert type to use.  If none is
  #               specified, Varanus will attempt to find one
  #  :years - number of years cert should be valid for (this number is multiplied by 365
  #           and used as days)
  #  :days - number of days cert should be valid for (if none is specified, lowest allowed
  #          for the cert type will be used)
  def sign_cert csr, org_id, opts = {}
    csr = Varanus::SSL::CSR.new(csr) unless csr.is_a?(Varanus::SSL::CSR)
    cert_type_id = opts_to_cert_type_id opts, csr
    args = {
      orgId: org_id,
      csr: csr.to_s,
      subjAltNames: csr.subject_alt_names,
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
    @connection ||= Faraday.new(url: 'https://cert-manager.com/api/ssl/v1') do |conn|
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
