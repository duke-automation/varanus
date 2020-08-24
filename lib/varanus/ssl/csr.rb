# frozen_string_literal: true

# Wrapper class around a OpenSSL::X509::Request
# Provides helper functions to make reading information from the CSR easier
class Varanus::SSL::CSR
  # Key size used when calling {.generate}
  DEFAULT_KEY_SIZE = 4096

  # Generate a CSR
  # @param names [Array<String>] List of DNS names.  The first one will be the CN
  # @param key [OpenSSL::PKey::RSA, OpenSSL::PKey::DSA, nil] Secret key for the cert.
  #   A DSA key will be generated if +nil+ is passed in.
  # @param subject [Hash] Options for the subject of the cert.  By default only CN will
  #   be set
  # @return [Array(OpenSSL::PKey::PKey, Varanus::SSL::CSR)] The private key for the cert
  #   and CSR
  def self.generate names, key = nil, subject = {}
    raise ArgumentError, 'names cannot be empty' if names.empty?

    subject = subject.dup
    subject['CN'] = names.first

    key ||= OpenSSL::PKey::DSA.new(DEFAULT_KEY_SIZE)

    request = OpenSSL::X509::Request.new
    request.version = 0
    request.subject = OpenSSL::X509::Name.parse subject.map { |k, v| "/#{k}=#{v}" }.join
    request.add_attribute names_to_san_attribute(names)
    request.public_key = key.public_key

    request.sign(key, OpenSSL::Digest::SHA256.new)

    [key, Varanus::SSL::CSR.new(request)]
  end

  # :nodoc:
  # Create a Subject Alternate Names attribute from an Array of dns names
  def self.names_to_san_attribute names
    ef = OpenSSL::X509::ExtensionFactory.new
    name_str = names.map { |n| "DNS:#{n}" }.join(', ')
    ext = ef.create_extension('subjectAltName', name_str, false)
    seq = OpenSSL::ASN1::Sequence([ext])
    ext_req = OpenSSL::ASN1::Set([seq])
    OpenSSL::X509::Attribute.new('extReq', ext_req)
  end

  # Common Name (CN) for cert.
  # @return [String]
  attr_reader :cn

  # OpenSSL::X509::Request representation of CSR
  # @return [OpenSSL::X509::Request]
  attr_reader :request

  # @param csr [String, OpenSSL::X509::Request]
  def initialize csr
    if csr.is_a? OpenSSL::X509::Request
      @request = csr
      @text = csr.to_s
    else
      @text = csr.to_s
      @request = OpenSSL::X509::Request.new @text
    end

    raise 'Improperly signed CSR' unless @request.verify @request.public_key

    cn_ref = @request.subject.to_a.find { |a| a[0] == 'CN' }
    @cn = cn_ref && cn_ref[1].downcase

    _parse_sans

    # If we have no CN or SAN, raise an error
    raise 'CSR must have a CN and/or subjectAltName' if @cn.nil? && @sans.empty?
  end

  # Unique list of all DNS names for cert (CN and subject alt names)
  # @return [Array<String>]
  def all_names
    ([@cn] + @sans).compact.uniq
  end

  # Key size for the cert
  # @return [Integer]
  def key_size
    case @request.public_key
    when OpenSSL::PKey::RSA
      @request.public_key.n.num_bytes * 8
    when OpenSSL::PKey::DSA
      @request.public_key.p.num_bytes * 8
    else
      raise "Unknown public key type: #{@request.public_key.class}"
    end
  end

  # PEM format for cert
  def to_s
    @text
  end

  # DNS subject alt names
  # @return [Array<String>]
  def subject_alt_names
    @sans
  end

  private

  def _parse_sans
    extensions = @request.attributes.select { |at| at.oid == 'extReq' }
    sans_extensions = extensions.flat_map do |extension|
      extension.value.value[0].value
               .select { |ext| ext.first.value == 'subjectAltName' }
               .map { |ext| ext.value.last }
    end
    @sans = sans_extensions.compact.flat_map do |san|
      _parse_sans_extension san
    end
  end

  def _parse_sans_extension ext
    OpenSSL::ASN1.decode(ext.value).map do |s_entry|
      unless s_entry.tag == 2 && s_entry.tag_class == :CONTEXT_SPECIFIC
        raise "unknown tag #{s_entry.tag}"
      end

      s_entry.value.downcase
    end
  end
end
