# Wrapper class around a OpenSSL::X509::Request
# Provides helper functions to make reading information from the CSR easier
class Varanus::SSL::CSR
  # Common Name (CN) for cert.
  # @return [String]
  attr_reader :cn

  # @param csr [String, OpenSSL::X509::Request]
  def initialize csr
    if csr.is_a? OpenSSL::X509::Request
      @req = csr
      @text = csr.to_s
    else
      @text = csr.to_s
      @req = OpenSSL::X509::Request.new @text
    end

    raise 'Improperly signed CSR' unless @req.verify @req.public_key

    cn_ref = @req.subject.to_a.find { |a| a[0] == 'CN' }
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
    case @req.public_key
    when OpenSSL::PKey::RSA
      @req.public_key.n.num_bytes * 8
    when OpenSSL::PKey::DSA
      @req.public_key.p.num_bytes * 8
    else
      raise "Unknown public key type: #{@req.public_key.class}"
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
    extensions = @req.attributes.select { |at| at.oid == 'extReq' }
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
