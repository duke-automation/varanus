# frozen_string_literal: true

# An connection to the DCV API.  This should not be initialized directly.  Instead,
# use Varanus#dcv
class Varanus::DCV < Varanus::RestResource
  # Returns an Array of DCV information about searched for domains.
  # This method will automatically page through all results
  # @param opts [Hash] - all opts are optional
  # @option opts [String] :domain Domain to search for
  # @option opts [Integer] :org ID of organization
  # @option opts [Integer] :department ID of department
  # @option opts [String] :dcvStatus
  # @option opts [String] :orderStatus
  # @option opts [Integer] :expiresIn Expires in (days)
  #
  # Results will included an extra 'expiration_date_obj' if 'expirationDate' is in the
  # response
  def search opts = {}
    get_with_size_and_position('dcv/v2/validation', opts).map(&method(:_format_status))
  end

  # Start domain validation process.  This must be called before #submit is called
  # @option domain [String] domain to validate
  # @option type [String] Type of validation. Must be one of 'http', 'https', 'cname',
  #                       or 'email'
  def start domain, type
    post("dcv/v1/validation/start/domain/#{type}", domain: domain)
  end

  # Retrieve DCV status for a single domain
  # Result will included an extra 'expiration_date_obj' if 'expirationDate' is in the
  # response
  def status domain
    _format_status(post('dcv/v2/validation/status', domain: domain))
  end

  # Submit domain validation for verficiation.  This must be called after #start
  # @option domain [String] domain to validate
  # @option type [String] Type of validation. Must be one of 'http', 'https', 'cname',
  #                       or 'email'
  # @option email_address [String] This is required of +type+ is 'email'. Otherwise, it is
  #                                ignored.
  def submit domain, type, email_address = nil
    if type.to_s == 'email'
      raise ArgumentError, 'email_address must be specified' if email_address.nil?

      post('dcv/v1/validation/submit/domain/email', domain: domain,
                                                    email: email_address)
    else
      post("dcv/v1/validation/submit/domain/#{type}", domain: domain)
    end
  end

  private

  def _format_status status
    return status unless status['expirationDate']

    status.merge('expiration_date_obj' =>
                   Date.strptime(status['expirationDate'], '%Y-%m-%d'))
  end
end
