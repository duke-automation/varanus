# frozen_string_literal: true

# A connection to the Domain API
class Varanus::Domain < Varanus::RestResource
  # Create a new domain.  The domain may need to be manually approved after this is
  # called.
  # +name+ is the domain
  # +delegations+ is an Array of Hashes.  Each Hash should have an 'orgId' and
  #                                       'certTypes' key
  # opts may include the following keys:
  #  - :description - optional - String
  #  - :active - optional - Boolean (defaults to +true+)
  #  - :allow_subdomains - optional - set to +false+ if you don't want to allow sub
  #                                   domains for this entry
  #
  # @returns [String] - URL for newly created domain
  def create domain, delegations, opts = {}
    opts = opts.dup
    allow_subdomains = opts.delete(:allow_subdomains)
    domain = "*.#{domain}" if allow_subdomains != false && !domain.start_with?('*.')

    result = @varanus.connection.post('domain/v1',
                                      opts.merge(name: domain, delegations: delegations))
    check_result result
    result.headers['Location']
  end

  # Return info on domain.  +id+ must be the id returned by #list
  def info id
    get("domain/v1/#{id}")
  end

  def list opts = {}
    get_with_size_and_position('domain/v1', opts)
  end

  def list_with_info opts = {}
    domains = list(opts)
    domains.map! { |domain| info(domain['id']) }
    domains
  end
end
